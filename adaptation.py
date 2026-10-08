"""
Adaptation automatique d'un .ovpn de fournisseur au fonctionnement du daemon.

Le but n'est pas de connaître chaque fournisseur : c'est d'appliquer les
règles, peu nombreuses, qui font qu'un .ovpn ordinaire fonctionne à travers
Tor avec ce daemon.  Chacune répond à un blocage constaté sur OpenVPN 2.7 :

  TCP obligatoire      Tor ne transporte que du TCP.  Un fichier UDP (ou sans
                       « proto », OpenVPN utilisant l'UDP par défaut) est
                       converti — avec un avertissement, car le fournisseur
                       doit accepter le TCP sur les mêmes ports.
  Fichiers annexes     « ca ca.crt », « tls-auth ta.key 1 »… : OpenVPN lit
                       une copie du .ovpn depuis /run, les chemins relatifs n'y
                       mènent plus nulle part (« Cannot pre-load keyfile »).
                       Leur contenu est intégré dans le fichier.
  Scripts              up/down/script-security : refusés par le daemon, qui
                       applique le DNS du VPN lui-même.
  Options Windows      block-outside-dns, register-dns… : « Unrecognized
                       option » sous Linux, connexion impossible.
  Options disparues    ncp-disable, keysize, key-method, tls-remote.
  UDP seulement        fragment, mtu-test : refusés en TCP.
  route-nopull         empêcherait le VPN de pousser ses serveurs DNS.

Une ligne retirée n'est jamais effacée : elle reste dans le fichier en
commentaire, avec la raison.  Plusieurs fichiers d'un même fournisseur (un
par serveur, cas courant dans un .zip) sont fusionnés en un seul, si et
seulement si tout sauf les lignes « remote » est identique.

Le choix des serveurs (pays, ports) reste à l'utilisateur, en amont : ce
module ne retire aucun serveur.  Le résultat passe en dernier lieu par
validation.analyser_ovpn, exactement comme au démarrage du tunnel.
"""

import base64
import posixpath
import zipfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from i18n import N_, _, ngettext
from validation import (OVPN_AUTORISEES, OVPN_BLOCS, OVPN_SCRIPTS, _RAISONS,
                        _jetons, analyser_ovpn)

OVPN_MAX   = 1_000_000        # octets par fichier, comme le daemon
ZIP_MAX    = 20_000_000       # octets lus au total dans une archive
ZIP_FICHIERS_MAX = 2000

# Options qui désignent un fichier : leur contenu est intégré au .ovpn.
FICHIERS = frozenset("""
    ca cert key extra-certs tls-auth tls-crypt tls-crypt-v2 pkcs12 secret dh
    crl-verify
""".split())
# Refusées par OpenVPN 2.7 sous Linux (« Unrecognized option »).
WINDOWS = frozenset("""
    block-outside-dns register-dns dhcp-release dhcp-renew dhcp-pre-release
    ip-win32 windows-driver tap-sleep win-sys
""".split())
# Supprimées d'OpenVPN : fatales en 2.7.
DISPARUES = frozenset("ncp-disable keysize key-method tls-remote".split())
# Refusées en TCP (« can only be used with --proto udp »).
UDP_SEULEMENT = frozenset("fragment mtu-test".split())
# Le daemon impose son propre proxy (Tor) en ligne de commande.
PROXIES = frozenset("socks-proxy socks-proxy-retry http-proxy http-proxy-option".split())
SERVEUR = frozenset("server server-bridge server-ipv6 tls-server mode".split())
# Liste de négociation par défaut d'OpenVPN 2.6+.  Un « cipher » absent de
# cette liste est ignoré pour la négociation, avec un avertissement
# (« DEPRECATED OPTION: --cipher set to … but missing in --data-ciphers »).
DATA_CIPHERS_DEFAUT = ("AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305")
# Chiffrements qu'on peut ajouter sans risque à data-ciphers.  BF-CBC, par
# exemple, rend le fichier REFUSÉ (« Unsupported cipher in --data-ciphers »,
# vérifié sur OpenVPN 2.7 / OpenSSL 3) : il n'est jamais ajouté.
DATA_CIPHERS_AJOUTABLES = frozenset(
    "AES-128-CBC AES-192-CBC AES-256-CBC AES-192-GCM".split())

_MARQUE = "# [katakomba] retiré"
_REMOTES = "\0REMOTES\0"      # emplacement des lignes remote (fusion)


@dataclass
class Resultat:
    texte: str = ""
    serveurs: int = 0
    modifications: list = field(default_factory=list)
    avertissements: list = field(default_factory=list)
    erreurs: list = field(default_factory=list)


@dataclass
class _Fichier:
    nom: str
    lignes: list = field(default_factory=list)
    remotes: list = field(default_factory=list)
    modifications: list = field(default_factory=list)
    avertissements: list = field(default_factory=list)
    erreurs: list = field(default_factory=list)
    udp: bool = False
    remote_tcp: bool = False      # « remote hôte port tcp » vu
    cipher: str = ""
    connexions: bool = False
    ajouts: list = field(default_factory=list)


def _nom_directive(p):
    nom = p[0][2:] if p[0].startswith("--") else p[0]
    # « setenv opt X » : OpenVPN traite X comme une directive.
    if nom == "setenv" and len(p) >= 3 and p[1] == "opt":
        return nom, (p[2][2:] if p[2].startswith("--") else p[2])
    return nom, nom


def _presentes(texte: str) -> set:
    """Noms des directives présentes (hors blocs de données)."""
    noms, bloc = set(), None
    for brute in texte.splitlines():
        ligne = brute.strip()
        if bloc:
            bloc = None if ligne == f"</{bloc}>" else bloc
            continue
        if ligne.startswith("<") and ligne.endswith(">"):
            tag = ligne[1:-1]
            if tag in OVPN_BLOCS:
                bloc = tag
                noms.add(tag)          # <ca>… vaut « ca [inline] »
            continue
        if not ligne or ligne[0] in "#;":
            continue
        p = _jetons(ligne)
        if p:
            noms.add(_nom_directive(p)[1])
    return noms


def _adapter_un(nom: str, texte: str, lire_annexe) -> _Fichier:
    f = _Fichier(nom)
    presentes = _presentes(texte)
    proto_vu = False
    bloc, dans_connexion = None, False

    def retirer(ligne, raison):
        raison = _(raison)
        f.lignes.append(f"{_MARQUE} ({raison}) : {ligne}")
        f.modifications.append(_("« {ligne} » retiré — {raison}").format(
            ligne=ligne[:70], raison=raison))

    for brute in texte.splitlines():
        ligne = brute.strip()
        if bloc is not None:
            f.lignes.append(brute)
            if ligne == f"</{bloc}>":
                bloc = None
            continue
        if not ligne or ligne[0] in "#;":
            f.lignes.append(brute)
            continue
        if ligne.startswith("<") and ligne.endswith(">"):
            tag = ligne[1:-1]
            if tag == "connection":
                dans_connexion = f.connexions = True
            elif tag == "/connection":
                dans_connexion = False
            elif tag in OVPN_BLOCS:
                bloc = tag
            f.lignes.append(brute)        # bloc inconnu : validation tranchera
            continue
        p = _jetons(ligne)
        if not p:
            f.lignes.append(brute)
            continue
        dir_, eff = _nom_directive(p)

        if eff in SERVEUR:
            f.erreurs.append(_("{fichier} : configuration de SERVEUR OpenVPN "
                               "(« {directive} ») — il faut le fichier client du "
                               "fournisseur.").format(fichier=nom, directive=eff))
        elif eff == "script-security" or eff in OVPN_SCRIPTS:
            retirer(ligne, N_("exécution de script ; le daemon applique le DNS "
                              "du VPN lui-même"))
        elif eff in PROXIES:
            retirer(ligne, N_("le daemon impose le passage par Tor"))
        elif eff in _RAISONS:
            retirer(ligne, _RAISONS[eff])
        elif dir_ == "setenv":
            f.lignes.append(brute)        # « setenv opt X » : ignoré si inconnu
        elif eff in WINDOWS:
            retirer(ligne, N_("option propre à Windows, refusée par OpenVPN "
                              "sous Linux"))
        elif eff in DISPARUES:
            retirer(ligne, N_("option supprimée des versions récentes d'OpenVPN"))
        elif eff in UDP_SEULEMENT:
            retirer(ligne, N_("réservée à l'UDP ; Tor impose le TCP"))
        elif eff == "route-nopull":
            retirer(ligne, N_("empêcherait le VPN de pousser ses serveurs DNS, "
                              "dont le daemon a besoin"))
        elif eff == "proto":
            proto_vu = True
            valeur = p[1].lower() if len(p) > 1 else ""
            if valeur.startswith("udp"):
                f.udp = True
            if valeur == "tcp-server":
                f.erreurs.append(_("{fichier} : « proto tcp-server » — "
                                   "configuration de serveur.").format(fichier=nom))
            if valeur != "tcp":
                f.lignes.append("proto tcp")
                f.modifications.append(_("« {ligne} » remplacé par « proto tcp » "
                                         "(Tor ne transporte que du TCP)").format(ligne=ligne))
            else:
                f.lignes.append(brute)
        elif eff == "remote":
            if len(p) < 2:
                f.lignes.append(brute)
                continue
            if len(p) >= 4:
                if p[3].lower().startswith("udp"):
                    f.udp = True
                elif p[3].lower().startswith("tcp"):
                    f.remote_tcp = True
                f.modifications.append(_("protocole retiré de « {ligne} » "
                                         "(fixé par « proto tcp »)").format(ligne=ligne))
            normale = " ".join(["remote", *p[1:3]])
            if dans_connexion:
                f.lignes.append(normale)
            else:
                if not f.remotes:
                    f.lignes.append(_REMOTES)
                f.remotes.append(normale)
        elif eff == "cipher":
            if len(p) > 1:
                f.cipher = p[1]
            f.lignes.append(brute)
        elif eff == "dev":
            if len(p) > 1 and p[1].lower().startswith("tap"):
                f.erreurs.append(_("{fichier} : interface TAP (« {ligne} ») — le "
                                   "daemon ne gère que TUN.").format(fichier=nom, ligne=ligne))
            f.lignes.append(brute)
        elif eff == "auth-user-pass" and len(p) > 1:
            f.lignes.append("auth-user-pass")
            f.modifications.append(_("« {ligne} » : fichier d'identifiants "
                                     "ignoré, le daemon fournit les siens").format(ligne=ligne))
        elif eff in FICHIERS and len(p) > 1 and p[1] != "[inline]":
            _integrer(f, eff, p, ligne, lire_annexe, presentes)
        elif eff not in OVPN_AUTORISEES:
            retirer(ligne, N_("directive non prise en charge par le daemon"))
        else:
            f.lignes.append(brute)

    if not f.remotes and not f.connexions:
        f.erreurs.append(_("{fichier} : aucun serveur (ligne « remote ») — ce "
                           "n'est pas un fichier de connexion client.").format(fichier=nom))
    # OpenVPN utilise l'UDP quand rien n'est précisé.
    if not proto_vu and not f.connexions:
        f.udp = f.udp or not f.remote_tcp
        f.ajouts.append(("proto tcp", _("« proto tcp » ajouté (OpenVPN "
                                        "utiliserait l'UDP par défaut)")))
    if "client" not in presentes and not {"pull", "tls-client"} <= presentes:
        f.ajouts.append(("client", _("« {ligne} » ajouté").format(ligne="client")))
    if "dev" not in presentes:
        f.ajouts.append(("dev tun", _("« {ligne} » ajouté").format(ligne="dev tun")))
    _data_ciphers(f, presentes)
    # Jamais de « redirect-gateway » ajouté : les serveurs l'envoient
    # eux-mêmes, et le doublon fait avertir OpenVPN (« specified
    # redirect-gateway … the same option multiple times … may lead to
    # unexpected results » — constaté en production).  `katakomba doctor`
    # signale un tunnel sans routes def1.
    return f


def _data_ciphers(f, presentes):
    """« cipher X » hors de la liste par défaut, sans data-ciphers : X est
    ajouté en FIN de liste.  Il reste négociable avec un serveur qui
    l'exige, sans changer le choix quand le serveur sait faire mieux (AES-GCM
    est essayé d'abord) — la correction qu'OpenVPN recommande lui-même."""
    x = f.cipher.upper()
    if not x or x == "NONE" or presentes & {"data-ciphers", "ncp-ciphers"}:
        return
    if x in DATA_CIPHERS_DEFAUT:
        return
    if x not in DATA_CIPHERS_AJOUTABLES:
        # Sans le nom du fichier : le même avertissement venu de N fichiers
        # n'est affiché qu'une fois.
        f.avertissements.append(_(
            "Chiffrement « {cipher} » obsolète et non pris en charge par OpenVPN "
            "récent — la connexion reposera sur AES-GCM, que le serveur doit "
            "accepter.").format(cipher=f.cipher))
        return
    liste = ":".join((*DATA_CIPHERS_DEFAUT, x))
    f.ajouts.append((f"data-ciphers {liste}",
                     _("« data-ciphers » ajouté avec {cipher} en dernier recours "
                       "(OpenVPN ignore « cipher » seul depuis la 2.6)").format(cipher=x)))


def _integrer(f, eff, p, ligne, lire_annexe, presentes):
    chemin = p[1]
    contenu = lire_annexe(f.nom, chemin) if lire_annexe else None
    if contenu is None:
        f.erreurs.append(_("{fichier} : fichier « {annexe} » ({directive}) introuvable "
                           "— placez-le à côté du .ovpn, ou importez le .zip "
                           "complet du fournisseur.").format(fichier=f.nom, annexe=chemin,
                                                             directive=eff))
        return
    if eff == "crl-verify" and len(p) > 2 and p[2] == "dir":
        f.erreurs.append(_("{fichier} : « crl-verify … dir » (répertoire) n'est "
                           "pas intégrable.").format(fichier=f.nom))
        return
    if eff == "pkcs12":
        # Forme intégrée d'un PKCS#12 : base64 (binaire à l'origine).
        donnees = base64.encodebytes(contenu).decode()
    else:
        try:
            donnees = contenu.decode("utf-8")
        except UnicodeDecodeError:
            f.erreurs.append(_("{fichier} : « {annexe} » n'est pas un fichier "
                               "texte.").format(fichier=f.nom, annexe=chemin))
            return
    f.lignes += [f"<{eff}>", donnees.strip("\n"), f"</{eff}>"]
    # « tls-auth ta.key 1 » : la direction passe dans key-direction.
    if eff in ("tls-auth", "secret") and len(p) > 2 \
            and "key-direction" not in presentes:
        f.lignes.append(f"key-direction {p[2]}")
        presentes.add("key-direction")
    f.modifications.append(_("« {annexe} » intégré au fichier ({directive})").format(
        annexe=chemin, directive=eff))


def _profil(f: _Fichier) -> list:
    """Tout sauf les commentaires, lignes vides et remotes : doit être
    identique pour que des fichiers puissent être fusionnés."""
    return [l.strip() for l in f.lignes
            if l.strip() and not l.lstrip().startswith(("#", ";"))]


def _dedoublonner(messages):
    """Même message venu de N fichiers : une ligne, avec le compte."""
    comptes = {}
    for m in messages:
        comptes[m] = comptes.get(m, 0) + 1
    return [m + (" " + _("(×{n} fichiers)").format(n=n) if n > 1 else "")
            for m, n in comptes.items()]


def adapter(fichiers, lire_annexe=None, aujourdhui=None) -> Resultat:
    """Adapte un ou plusieurs .ovpn d'un même fournisseur.

    `fichiers` : liste de (nom, texte).  `lire_annexe(nom, chemin)` renvoie
    le contenu (bytes) d'un fichier référencé par `nom`, ou None."""
    res = Resultat()
    if not fichiers:
        res.erreurs.append(_("Aucun fichier .ovpn fourni."))
        return res
    adaptes = [_adapter_un(nom, texte, lire_annexe) for nom, texte in fichiers]
    for a in adaptes:
        res.erreurs += a.erreurs
    if res.erreurs:
        return res
    res.avertissements += _dedoublonner([m for a in adaptes for m in a.avertissements])

    # Archive mêlant variantes TCP et UDP : on garde les TCP, seules
    # utilisables à travers Tor, plutôt que de convertir les UDP.
    tcp = [a for a in adaptes if not a.udp]
    if tcp and len(tcp) < len(adaptes):
        ignores = len(adaptes) - len(tcp)
        res.avertissements.append(ngettext(
            "{n} fichier UDP ignoré : les variantes TCP du fournisseur sont utilisées.",
            "{n} fichiers UDP ignorés : les variantes TCP du fournisseur sont utilisées.",
            ignores).format(n=ignores))
        adaptes = tcp
    elif not tcp:
        res.avertissements.append(_(
            "Configuration UDP convertie en TCP sur les mêmes ports (Tor ne "
            "transporte que du TCP). Si la connexion échoue, le fournisseur "
            "n'accepte pas le TCP sur ces ports : téléchargez sa variante "
            "TCP, souvent sur le port 443."))

    base = adaptes[0]
    if len(adaptes) > 1:
        if any(a.connexions for a in adaptes):
            res.erreurs.append(_("Fichiers à blocs <connection> : importez-les "
                                 "un par un."))
            return res
        reference = _profil(base)
        for a in adaptes[1:]:
            if _profil(a) != reference:
                diff = next((l for l in _profil(a) if l not in reference),
                            _("(ordre ou nombre de lignes)"))
                res.erreurs.append(_(
                    "{fichier} ne peut pas être fusionné avec {reference} : "
                    "leur configuration diffère au-delà des serveurs "
                    "(par exemple « {difference} »). Importez chaque "
                    "fichier comme un fournisseur distinct.").format(
                        fichier=a.nom, reference=base.nom, difference=diff[:60]))
                return res

    remotes = list(dict.fromkeys(r for a in adaptes for r in a.remotes))
    corps = []
    for ligne in base.lignes:
        if ligne == _REMOTES:
            corps += remotes
        else:
            corps.append(ligne)

    modifs = _dedoublonner([m for a in adaptes for m in a.modifications]
                           + [m for _ligne, m in base.ajouts])
    if len(adaptes) > 1:
        modifs.insert(0, _("{n} fichiers fusionnés").format(n=len(adaptes)) + " : "
                      + ngettext("{n} serveur distinct", "{n} serveurs distincts",
                                 len(remotes)).format(n=len(remotes)))
    noms = [a.nom for a in adaptes]
    entete = ["# " + _("Configuration adaptée par Katakomba ({date})").format(
                  date=(aujourdhui or date.today()).isoformat()),
              "# " + _("Sources : {fichiers}").format(fichiers=", ".join(noms[:5]))
              + (" … " + _("({n} fichiers)").format(n=len(noms)) if len(noms) > 5 else "")]
    if modifs:
        entete.append("# " + _("Modifications :"))
        entete += [f"#   - {m}" for m in modifs[:40]]
    entete.append("")
    res.texte = "\n".join(entete + [l for l, _m in base.ajouts] + corps) + "\n"
    res.serveurs = len(remotes) + sum(1 for l in corps if l == "<connection>")
    res.modifications = modifs

    # Filet final : exactement le contrôle du daemon au démarrage du tunnel.
    refus, _avert = analyser_ovpn(res.texte)
    if refus:
        res.erreurs += refus
        res.texte = ""
    return res


# ── Lecture des sources (fichiers, archives) ─────────────────────────────────

def lire_sources(chemins):
    """Lit des .ovpn/.conf et des .zip.  Renvoie (fichiers, lire_annexe,
    erreurs), prêts pour adapter().

    Un fichier annexe (« ca ca.crt ») est cherché à côté du .ovpn qui le
    cite — dans le même dossier, ou le même répertoire de l'archive —, puis,
    dans une archive, par son seul nom s'il y est unique."""
    fichiers, erreurs, annexes = [], [], {}
    for chemin in map(Path, chemins):
        if chemin.suffix.lower() == ".zip":
            _lire_zip(chemin, fichiers, annexes, erreurs)
            continue
        try:
            with open(chemin, "rb") as fh:
                data = fh.read(OVPN_MAX + 1)
        except OSError as e:
            erreurs.append(_("{fichier} : lecture impossible ({erreur}).").format(
                fichier=chemin.name, erreur=e.strerror or e))
            continue
        if len(data) > OVPN_MAX:
            erreurs.append(_("{fichier} : trop volumineux pour un .ovpn.").format(
                fichier=chemin.name))
            continue
        fichiers.append((chemin.name, data.decode("utf-8", errors="replace")))
        annexes[chemin.name] = _annexe_dossier(chemin.parent)
    if not fichiers and not erreurs:
        erreurs.append(_("Aucun fichier .ovpn ou .conf trouvé."))

    def lire_annexe(nom, ref):
        chercher = annexes.get(nom)
        return chercher(ref) if chercher else None

    return fichiers, lire_annexe, erreurs


def _annexe_dossier(dossier: Path):
    def chercher(ref):
        # Chemin relatif sous le dossier du .ovpn, ou à défaut son seul nom :
        # jamais un fichier arbitraire du système.
        for candidat in (dossier / ref, dossier / Path(ref).name):
            try:
                reel = candidat.resolve()
                if reel.is_relative_to(dossier.resolve()) and reel.is_file() \
                        and reel.stat().st_size <= OVPN_MAX:
                    return reel.read_bytes()
            except (OSError, ValueError):
                continue
        return None
    return chercher


def _lire_zip(chemin, fichiers, annexes, erreurs):
    try:
        zf = zipfile.ZipFile(chemin)
    except (OSError, zipfile.BadZipFile) as e:
        erreurs.append(_("{fichier} : archive illisible ({erreur}).").format(
            fichier=chemin.name, erreur=e))
        return
    with zf:
        membres = [i for i in zf.infolist()
                   if not i.is_dir() and not i.filename.startswith("__MACOSX/")]
        if len(membres) > ZIP_FICHIERS_MAX:
            erreurs.append(_("{fichier} : trop de fichiers dans l'archive.").format(
                fichier=chemin.name))
            return
        contenu, total = {}, 0
        for i in membres:
            if i.file_size > OVPN_MAX:
                continue
            total += i.file_size
            if total > ZIP_MAX:
                erreurs.append(_("{fichier} : archive trop volumineuse.").format(
                    fichier=chemin.name))
                return
            contenu[i.filename] = zf.read(i)
    par_nom = {}
    for n in contenu:
        par_nom.setdefault(posixpath.basename(n), []).append(n)

    def pour(entree):
        def chercher(ref):
            voisin = posixpath.normpath(
                posixpath.join(posixpath.dirname(entree), ref))
            if voisin in contenu:
                return contenu[voisin]
            homonymes = par_nom.get(posixpath.basename(ref), [])
            return contenu[homonymes[0]] if len(homonymes) == 1 else None
        return chercher

    trouves = 0
    for n, data in sorted(contenu.items()):
        if n.lower().endswith((".ovpn", ".conf")):
            trouves += 1
            fichiers.append((n, data.decode("utf-8", errors="replace")))
            annexes[n] = pour(n)
    if not trouves:
        erreurs.append(_("{fichier} : aucun .ovpn ni .conf dans l'archive.").format(
            fichier=chemin.name))
