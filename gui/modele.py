"""
Logique de l'interface, sans aucune dépendance graphique.

Configuration, fournisseurs, torrc, sauvegardes, service systemd, lecture de
l'état du daemon : tout ce que l'interface GTK affiche ou modifie passe par
ici.  Les fonctions sont testées sans écran (tests/test_modele.py).

Les chemins sont lus sur ce module à chaque appel (modele.CONFIG_FILE…) :
les tests les redirigent vers un répertoire temporaire.

Tout texte destiné à l'utilisateur passe par _() au moment de l'appel,
jamais à l'import : la langue peut changer pendant que l'interface tourne.
"""

import base64
import copy
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from adaptation import adapter, lire_sources
from constants import (
    CONFIG_DIR, CONFIG_FILE, DEFAULT_CONFIG, OBSOLETE_CONFIG_KEYS, PROVIDERS_DIR,
    SCRIPT_DIR, SERVICE_NAME, STATUS_SOCKET, TORRC_FILE,
)
from i18n import LANGUES, N_, _, ngettext, nombre
from validation import analyser_ovpn, analyser_torrc

OVPN_MAX = 1_000_000      # octets, comme le daemon


# ── Petits outils ────────────────────────────────────────────────────────────

def obf(s: str) -> str:
    """Identifiants dans config.json : base64, pas du chiffrement."""
    return base64.b64encode(s.encode()).decode()


def deobf(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s


def composant_sur(c: str) -> bool:
    """Composant de chemin simple : anti path-traversal (import de sauvegarde)."""
    return bool(c) and c not in (".", "..") \
        and "/" not in c and "\\" not in c and not c.startswith(".")


def _insecable(texte: str) -> str:
    """Nombre et unité jamais séparés par un retour à la ligne."""
    return texte.replace(" ", "\u00a0")


def kbs_en_mbps(kbs: float) -> str:
    """Les speed tests parlent en mégabits, les téléchargements en kilo-octets."""
    return _insecable(_("{valeur} Mb/s").format(valeur=nombre(kbs * 8 / 1000)))


def kbs_lisible(kbs: float) -> str:
    return _insecable(_("{valeur} Ko/s").format(valeur=f"{kbs:.0f}"))


def duree_lisible(secondes: int) -> str:
    secondes = int(secondes)
    if secondes < 60:
        texte = _("{n} s").format(n=secondes)
    elif secondes < 3600:
        texte = _("{n} min").format(n=secondes // 60)
    elif secondes < 86400:
        heures, minutes = divmod(secondes // 60, 60)
        texte = _("{h} h {m:02d}").format(h=heures, m=minutes)
    else:
        jours, heures = divmod(secondes // 3600, 24)
        texte = _("{j} j {h} h").format(j=jours, h=heures)
    return _insecable(texte)


# ── Configuration ────────────────────────────────────────────────────────────

def charger_config() -> dict:
    # deepcopy et non dict() : les défauts contiennent des listes, et
    # l'interface les modifie EN PLACE.  Une copie superficielle ferait
    # grossir DEFAULT_CONFIG lui-même.
    defauts = copy.deepcopy(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                lu = json.load(f)
            if not isinstance(lu, dict):
                raise ValueError("config.json ne contient pas un objet JSON")
            # Clés d'anciennes versions : retirées à la prochaine sauvegarde.
            for k in OBSOLETE_CONFIG_KEYS:
                lu.pop(k, None)
            return {**defauts, **lu}
        except Exception as e:
            # Ne pas écraser silencieusement une config corrompue : elle est
            # mise de côté pour pouvoir la récupérer.
            mauvaise = CONFIG_FILE.with_name(CONFIG_FILE.name + ".bad")
            try:
                CONFIG_FILE.replace(mauvaise)
                print(f"config.json illisible ({e}) — sauvegardé dans {mauvaise}",
                      file=sys.stderr)
            except Exception:
                pass
    return defauts


def enregistrer_config(config: dict):
    """Écriture atomique (tmp + fsync + rename) : jamais de config.json
    tronqué après une coupure.  PermissionError remonte à l'appelant."""
    tmp = CONFIG_FILE.with_name(CONFIG_FILE.name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    tmp.chmod(0o660)          # root + groupe katakomba
    os.replace(tmp, CONFIG_FILE)


def message_droits() -> str:
    return _("Votre compte ne peut pas modifier la configuration de Katakomba. "
             "Fermez puis rouvrez votre session ; si le problème persiste : "
             "sudo katakomba autoriser $USER")


def mode_avance_initial(config: dict) -> bool:
    """Mode choisi, ou — jamais choisi — déduit de la configuration.

    Une installation qui utilise déjà des exclusions, le DNS local, le
    partage LAN ou des réglages de circuit modifiés démarre en mode avancé :
    masquer à quelqu'un les réglages dont il se sert serait pire que de les
    montrer à un débutant."""
    choix = config.get("advanced_mode")
    if choix is not None:
        return bool(choix)
    return bool(
        config.get("excluded_ips") or config.get("excluded_domains")
        or config.get("local_dns") or config.get("lan_auto")
        or config.get("lan_iface")
        or config.get("circuit_min_kbs", DEFAULT_CONFIG["circuit_min_kbs"])
           != DEFAULT_CONFIG["circuit_min_kbs"]
        or config.get("circuit_check", True) is False)


# ── Saisies ──────────────────────────────────────────────────────────────────

def erreur_dns(dns: str) -> str:
    dns = dns.strip()
    if not dns:
        return ""
    try:
        ipaddress.ip_address(dns)
    except ValueError:
        return _("« {valeur} » n'est pas une adresse IP.").format(valeur=dns)
    return ""


def erreurs_lan(passerelle: str, sous_reseau: str) -> list:
    erreurs, net = [], None
    try:
        net = ipaddress.ip_network(sous_reseau.strip(), strict=False)
    except ValueError:
        erreurs.append(_("Sous-réseau « {valeur} » invalide.").format(valeur=sous_reseau))
    try:
        if net is not None and ipaddress.ip_address(passerelle.strip()) not in net:
            erreurs.append(_("{adresse} n'appartient pas à {reseau}.").format(
                adresse=passerelle, reseau=net))
    except ValueError:
        erreurs.append(_("« {valeur} » n'est pas une adresse IP.").format(valeur=passerelle))
    return erreurs


def erreurs_config(config: dict) -> list:
    """Réglages invalides, en clair.  Liste vide : tout est enregistrable.
    Une valeur invalide n'est jamais ignorée en silence ni transmise telle
    quelle à systemd-resolved ou à ip addr."""
    erreurs = []
    e = erreur_dns(config.get("local_dns", ""))
    if e:
        erreurs.append(_("Serveur DNS local : {erreur}").format(erreur=e))
    try:
        cmin = int(config.get("circuit_min_kbs", 250))
        cret = int(config.get("circuit_max_retries", 3))
        if cmin < 0 or not 1 <= cret <= 10:
            raise ValueError
    except (TypeError, ValueError):
        erreurs.append(_("Qualité du circuit : débit minimum entier ≥ 0, "
                         "essais entre 1 et 10."))
    if config.get("lan_auto"):
        erreurs += [_("Partage LAN : {erreur}").format(erreur=m) for m in
                    erreurs_lan(config.get("lan_gateway", ""),
                                config.get("lan_subnet", ""))]
    return erreurs


def normaliser_ip(saisie: str):
    """(réseau normalisé, erreur).  L'exclusion repose sur « --route », une
    option IPv4 uniquement : une entrée IPv6 serait acceptée puis ignorée par
    OpenVPN, en laissant croire que le réseau est exclu du tunnel."""
    saisie = saisie.strip()
    if not saisie:
        return "", ""
    try:
        net = ipaddress.ip_network(saisie, strict=False)
    except ValueError:
        return "", _("« {valeur} » n'est pas une adresse ou un réseau "
                     "valide.").format(valeur=saisie)
    if net.version != 4:
        return "", _("« {valeur} » est une adresse IPv6 : l'exclusion du tunnel "
                     "ne gère que l'IPv4.").format(valeur=saisie)
    return str(net), ""


def normaliser_domaine(saisie: str) -> str:
    saisie = saisie.strip()
    return ("." + saisie.lstrip(".")).lower() if saisie else ""


# ── Fournisseurs ─────────────────────────────────────────────────────────────

def verifier_nom(nom: str, fournisseurs) -> str:
    """Message d'erreur, ou "" si le nom est utilisable (il sert de nom de
    dossier sous providers/)."""
    nom = nom.strip()
    if not nom:
        return _("Donnez un nom au fournisseur (par exemple celui de votre VPN).")
    if nom in (".", "..") or "/" in nom or "\\" in nom:
        return _("Le nom ne peut contenir ni « / » ni « \\ ».")
    if any(p.get("name", "").lower() == nom.lower() for p in fournisseurs):
        return _("Un fournisseur « {nom} » existe déjà.").format(nom=nom)
    return ""


def nom_depuis_fichier(chemin: str) -> str:
    """Nom proposé à partir du fichier : « ivpn-config.zip » → « ivpn-config »."""
    return Path(chemin).stem.replace("_", " ").strip()[:40]


def preparer_import(chemins):
    """Lit et adapte les fichiers du fournisseur ; renvoie (résultat,
    erreurs).  Le fichier est rendu fonctionnel tel quel (TCP, fichiers
    annexes intégrés, scripts et options Windows retirés, voir adaptation.py)."""
    fichiers, lire_annexe, erreurs = lire_sources(chemins)
    if erreurs:
        return None, erreurs
    res = adapter(fichiers, lire_annexe)
    return res, res.erreurs


def resume_adaptation(res) -> str:
    lignes = [ngettext("{n} serveur retenu.", "{n} serveurs retenus.",
                       res.serveurs).format(n=res.serveurs)]
    if res.modifications:
        lignes += ["", _("Modifications apportées :")]
        lignes += [f"• {m}" for m in res.modifications[:12]]
        reste = len(res.modifications) - 12
        if reste > 0:
            lignes.append(ngettext("… et {n} autre, détaillée en tête du fichier.",
                                   "… et {n} autres, détaillées en tête du fichier.",
                                   reste).format(n=reste))
    if res.avertissements:
        lignes += ["", *(f"⚠ {a}" for a in res.avertissements)]
    lignes += ["", _("Les lignes retirées restent dans le fichier, en commentaire.")]
    return "\n".join(lignes)


def nom_destination(fournisseur: str, chemins) -> str:
    """Un seul .ovpn : son nom est conservé.  Plusieurs fichiers ou une
    archive : un fichier fusionné au nom du fournisseur."""
    if len(chemins) == 1 and not str(chemins[0]).lower().endswith(".zip"):
        return Path(chemins[0]).name
    return "".join(c if c.isalnum() or c in "-_." else "-"
                   for c in fournisseur) + ".ovpn"


def ecrire_ovpn(fournisseur: str, res, chemins) -> str:
    """Écrit la configuration adaptée ; renvoie son chemin relatif."""
    dossier = PROVIDERS_DIR / fournisseur
    dossier.mkdir(parents=True, exist_ok=True)
    dest = dossier / nom_destination(fournisseur, chemins)
    dest.write_text(res.texte)
    return str(dest.relative_to(SCRIPT_DIR))


def ajouter_fournisseur_adapte(config: dict, nom, res, chemins, identifiant,
                               mot_de_passe):
    """Assistant : fichier écrit, fournisseur et compte ajoutés, config
    enregistrée.  Le fournisseur va en fin de liste : la priorité des autres
    ne change pas."""
    rel = ecrire_ovpn(nom, res, chemins)
    config.setdefault("providers", []).append({
        "name": nom, "ovpn_file": rel,
        "accounts": [{"u": obf(identifiant), "p": obf(mot_de_passe)}],
    })
    enregistrer_config(config)


def deplacer(liste: list, i: int, delta: int) -> int:
    """Échange l'élément i avec son voisin ; renvoie la nouvelle position."""
    j = i + delta
    if not (0 <= i < len(liste) and 0 <= j < len(liste)):
        return i
    liste[i], liste[j] = liste[j], liste[i]
    return j


# ── torrc ────────────────────────────────────────────────────────────────────

# Valeurs par défaut (circuits longs et stables, adaptées à un tunnel OpenVPN
# persistant), identiques au torrc créé par install.sh.
TOR_DEFAUTS = {
    "avoid_disk": True, "safe_logging": True, "no_ipv6": True,
    "test_socks": True, "conn_padding": False, "long_lived": True,
    "learn_timeout": True, "max_dirty": 3600, "build_timeout": 60,
    "new_circuit": 60, "keepalive": 60, "num_guards": 3,
    "guard_lifetime": "2 months", "exclude_exits": "", "strict_nodes": False,
}
# Valeur d'un réglage quand sa clé est ABSENTE du fichier : le fichier fait
# foi, pas les défauts de l'interface.
TOR_ABSENT = {
    "avoid_disk": False, "safe_logging": False, "no_ipv6": False,
    "test_socks": False, "conn_padding": False, "long_lived": False,
    "learn_timeout": False, "max_dirty": 0, "build_timeout": 0,
    "new_circuit": 0, "keepalive": 0, "num_guards": 0,
    "guard_lifetime": "", "exclude_exits": "", "strict_nodes": False,
}
TOR_DUREES_GARDE = ("", "1 months", "2 months", "3 months", "6 months")

# Rappel informatif : le daemon impose ces quatre valeurs en ligne de
# commande, qui l'emporte sur le fichier.
TORRC_OBLIGATOIRE = (
    "# === Paramètres obligatoires — ne pas supprimer ===\n"
    "SocksPort 9050\n"
    "ControlPort 9051\n"
    "CookieAuthentication 1\n"
    "DataDirectory /var/lib/katakomba/tor_data\n"
)
_OBLIGATOIRES = frozenset(
    ("socksport", "controlport", "cookieauthentication", "datadirectory"))
# En-têtes produits par l'interface : jamais repris comme lignes personnelles
# (ils se dupliqueraient à chaque régénération).
_ENTETES = ("# === Paramètres obligatoires", "# === Paramètres personnalisés",
            "# === Lignes du mode expert")

_DRAPEAUX = {   # clé torrc → (réglage, valeur « activé », valeur « désactivé »)
    "avoiddiskwrites": ("avoid_disk", "1", "0"),
    "safelogging": ("safe_logging", "1", "0"),
    "clientuseipv6": ("no_ipv6", "0", "1"),
    "testsocks": ("test_socks", "1", "0"),
    "connectionpadding": ("conn_padding", "1", None),
    "longlivedports": ("long_lived", "1194,443", None),
    "learncircuitbuildtimeout": ("learn_timeout", "0", "1"),
}
_ENTIERS = {"maxcircuitdirtiness": "max_dirty",
            "circuitbuildtimeout": "build_timeout",
            "newcircuitperiod": "new_circuit",
            "keepaliveperiod": "keepalive",
            "numentryguards": "num_guards"}


def lire_torrc(texte: str):
    """Sépare un torrc en (réglages représentables, lignes personnelles).

    Une ligne n'est confiée à un réglage que s'il sait la représenter
    EXACTEMENT ; sinon elle reste une ligne personnelle, recopiée telle
    quelle.  « ConnectionPadding 0 » n'est pas « désactivé » (qui signifie
    « défaut de Tor, auto ») : la ligne est conservée au lieu d'être perdue."""
    lignes, extras = [], []
    for brute in texte.splitlines():
        ligne = brute.strip()
        if not ligne:
            continue
        if ligne.startswith("#"):
            if not ligne.startswith(_ENTETES):
                extras.append(brute)
            continue
        morceaux = ligne.split(None, 1)
        cle = morceaux[0].lower()
        val = morceaux[1].strip() if len(morceaux) > 1 else ""
        if cle in _OBLIGATOIRES:
            continue                  # régénérés depuis TORRC_OBLIGATOIRE
        lignes.append((cle, val, brute))

    cles = {c for c, _val, _brute in lignes}
    valeurs = {}
    for cle, val, brute in lignes:
        if cle in _DRAPEAUX:
            nom, oui, non = _DRAPEAUX[cle]
            if val == oui:
                valeurs[nom] = True
                continue
            if non is not None and val == non:
                valeurs[nom] = False
                continue
        elif cle in _ENTIERS and val.isdigit():
            valeurs[_ENTIERS[cle]] = int(val)
            continue
        elif cle == "guardlifetime" and val in TOR_DUREES_GARDE:
            valeurs["guard_lifetime"] = val
            continue
        elif cle == "excludeexitnodes":
            valeurs["exclude_exits"] = val
            continue
        elif (cle == "strictnodes" and val in ("0", "1")
              and "excludeexitnodes" in cles):
            # Le réglage n'émet StrictNodes qu'avec une exclusion de sortie :
            # seul, il vise sans doute ExcludeNodes — la ligne est gardée.
            valeurs["strict_nodes"] = val == "1"
            continue
        extras.append(brute)
    return valeurs, extras


def completer_valeurs_tor(valeurs: dict) -> dict:
    """Réglages lus d'un fichier, complétés par « absent » (et non par les
    défauts de l'interface)."""
    return {cle: valeurs.get(cle, absent) for cle, absent in TOR_ABSENT.items()}


def construire_torrc(valeurs: dict, extras=()) -> str:
    v = {**TOR_ABSENT, **valeurs}
    lignes = [TORRC_OBLIGATOIRE.rstrip(), "", "# === Paramètres personnalisés ==="]
    for cle, texte in (("avoid_disk", "AvoidDiskWrites 1"),
                       ("safe_logging", "SafeLogging 1"),
                       ("no_ipv6", "ClientUseIPv6 0"),
                       ("test_socks", "TestSocks 1"),
                       ("conn_padding", "ConnectionPadding 1"),
                       ("long_lived", "LongLivedPorts 1194,443"),
                       ("learn_timeout", "LearnCircuitBuildTimeout 0")):
        if v[cle]:
            lignes.append(texte)
    for cle, nom in (("max_dirty", "MaxCircuitDirtiness"),
                     ("build_timeout", "CircuitBuildTimeout"),
                     ("new_circuit", "NewCircuitPeriod"),
                     ("keepalive", "KeepalivePeriod"),
                     ("num_guards", "NumEntryGuards")):
        try:
            n = int(v[cle])
        except (TypeError, ValueError):
            continue
        if n > 0:
            lignes.append(f"{nom} {n}")
    duree = str(v["guard_lifetime"]).strip()
    if duree:
        lignes.append(f"GuardLifetime {duree}")
    sorties = str(v["exclude_exits"]).strip()
    if sorties:
        lignes.append(f"ExcludeExitNodes {sorties}")
        lignes.append(f"StrictNodes {'1' if v['strict_nodes'] else '0'}")
    if extras:
        lignes += ["", "# === Lignes du mode expert ===", *extras]
    return "\n".join(lignes) + "\n"


def completer_obligatoires(contenu: str) -> str:
    """Ajoute les paramètres obligatoires réellement manquants, clé par clé.
    Préfixer tout le bloc dupliquerait SocksPort/ControlPort (conflit de
    bind : Tor refuserait de démarrer).  Lignes commentées ignorées ;
    comparaison insensible à la casse, comme Tor."""
    presentes = {ln.strip().split()[0].lower() for ln in contenu.splitlines()
                 if ln.strip() and not ln.strip().startswith("#")}
    manquantes = [ln for ln in TORRC_OBLIGATOIRE.splitlines()
                  if ln.strip() and not ln.startswith("#")
                  and ln.split()[0].lower() not in presentes]
    if manquantes:
        contenu = ("# === Paramètres obligatoires (réinjectés) ===\n"
                   + "\n".join(manquantes) + "\n\n" + contenu)
    return contenu


def lire_torrc_fichier() -> str:
    try:
        return TORRC_FILE.read_text()
    except OSError:
        return ""


def enregistrer_torrc(contenu: str) -> list:
    """Enregistre le torrc ; renvoie les refus (liste vide : enregistré).
    Mêmes règles que le daemon : un torrc qu'il refuserait est bloqué ici,
    avec l'explication, plutôt qu'ignoré en silence au démarrage."""
    contenu = contenu.strip() + "\n"
    refus = analyser_torrc(contenu)
    if refus:
        return refus
    TORRC_FILE.write_text(completer_obligatoires(contenu))
    try:
        TORRC_FILE.chmod(0o660)
    except PermissionError:
        pass
    return []


def supprimer_torrc():
    TORRC_FILE.unlink(missing_ok=True)


# ── Sauvegardes ──────────────────────────────────────────────────────────────

def exporter(config: dict, chemin):
    with zipfile.ZipFile(chemin, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(config, indent=2))
        for p in config.get("providers", []):
            ovpn = p.get("ovpn_file", "")
            if not ovpn:
                continue
            chemin_ovpn = Path(ovpn)
            if not chemin_ovpn.is_absolute():
                chemin_ovpn = SCRIPT_DIR / chemin_ovpn
            if chemin_ovpn.exists():
                zf.write(str(chemin_ovpn), f"providers/{p['name']}/{chemin_ovpn.name}")
        if TORRC_FILE.exists():
            zf.write(str(TORRC_FILE), "torrc")


def lire_sauvegarde(chemin):
    """Ouvre une sauvegarde ; renvoie (nouvelle config, écartés) sans rien
    enregistrer de la config elle-même.  ValueError si ce n'en est pas une."""
    with zipfile.ZipFile(chemin, "r") as zf:
        if "config.json" not in zf.namelist():
            raise ValueError(_("Ce fichier n'est pas une sauvegarde Katakomba."))
        nouvelle = json.loads(zf.read("config.json").decode())
        if not isinstance(nouvelle, dict):
            raise ValueError(_("config.json ne contient pas un objet JSON"))
        for k in OBSOLETE_CONFIG_KEYS:
            nouvelle.pop(k, None)
        ecartes = importer_fichiers(zf, nouvelle)
    return {**copy.deepcopy(DEFAULT_CONFIG), **nouvelle}, ecartes


def importer_fichiers(zf, nouvelle: dict) -> list:
    """Restaure les .ovpn/.conf et le torrc d'une sauvegarde ; renvoie ce qui
    a été écarté, en clair.  Tout passe par les contrôles du daemon : une
    sauvegarde reçue d'un tiers est la voie la plus simple pour introduire un
    « plugin » dans un .ovpn."""
    ecartes = []
    for nom in zf.namelist():
        if not (nom.startswith("providers/") and nom.endswith((".ovpn", ".conf"))):
            continue
        parts = nom.split("/")
        if len(parts) != 3 or not all(map(composant_sur, parts[1:])):
            ecartes.append(_("{fichier} : chemin refusé").format(fichier=nom))
            continue
        data = zf.read(nom)
        refus, _avert = analyser_ovpn(data.decode("utf-8", errors="replace"))
        if len(data) > OVPN_MAX or refus:
            ecartes.append(_("{fichier} : {raison}").format(
                fichier=f"{parts[1]}/{parts[2]}",
                raison=refus[0] if refus else _("trop volumineux")))
            continue
        dossier = PROVIDERS_DIR / parts[1]
        dossier.mkdir(parents=True, exist_ok=True)
        (dossier / parts[2]).write_bytes(data)
    # Chemins .ovpn : relatifs, sous providers/, rien d'autre.  Un chemin
    # absolu ferait lire au daemon, en root, un fichier arbitraire.
    for p in nouvelle.get("providers", []):
        ovpn = p.get("ovpn_file", "")
        parts = Path(ovpn).parts
        if ovpn and not (len(parts) == 3 and parts[0] == "providers"
                         and all(map(composant_sur, parts[1:]))):
            p["ovpn_file"] = ""
            ecartes.append(_("{fournisseur} : chemin .ovpn refusé (hors de "
                             "providers/)").format(fournisseur=p.get("name", "?")))
    if "torrc" in zf.namelist():
        texte = zf.read("torrc").decode("utf-8", errors="replace")
        refus = analyser_torrc(texte)
        if refus:
            ecartes.append(_("{fichier} : {raison}").format(fichier="torrc", raison=refus[0]))
        else:
            TORRC_FILE.write_text(texte)
            try:
                TORRC_FILE.chmod(0o660)
            except PermissionError:
                pass
    return ecartes


# ── Service systemd ──────────────────────────────────────────────────────────

_LECTURES = ("is-active", "is-enabled", "show", "status")
# Réponses de systemd quand polkit refuse, ou quand l'invite est annulée.
_REFUS_POLKIT = ("Access denied", "Interactive authentication required")
ANNULE = 126             # code de pkexec pour une invite annulée ou refusée


def systemctl(*args) -> subprocess.CompletedProcess:
    """systemctl lancé tel quel, jamais via pkexec : systemd consulte polkit
    lui-même.  start/stop/restart de katakomba.service passent sans mot de
    passe pour le groupe katakomba (règle 50-katakomba.rules) ; sans cette
    règle, l'agent polkit du bureau demande le mot de passe."""
    r = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    if r.returncode != 0 and any(m in (r.stderr or "") for m in _REFUS_POLKIT):
        r.returncode = ANNULE
    return r


def privilegie(programme: str, *args) -> subprocess.CompletedProcess:
    """Programme de Katakomba lancé en root, via pkexec hors root.  Chemin et
    premier argument désignent une action d'org.katakomba.policy : l'invite
    dit ce que Katakomba demande."""
    cmd = [str(SCRIPT_DIR / programme), *args]
    if os.geteuid() != 0:
        cmd = ["pkexec"] + cmd
    return subprocess.run(cmd, capture_output=True, text=True)


def etat_service() -> str:
    return systemctl("is-active", SERVICE_NAME).stdout.strip() or "unknown"


def demarrage_auto_actif() -> bool:
    return systemctl("is-enabled", SERVICE_NAME).stdout.strip() == "enabled"


def regler_demarrage_auto(actif: bool) -> subprocess.CompletedProcess:
    """enable/disable (mot de passe demandé) seulement si l'état doit changer."""
    if demarrage_auto_actif() == actif:
        return subprocess.CompletedProcess([], 0, "", "")
    return privilegie("katakomba-cli.sh", "enable" if actif else "disable")


def piloter_service(action: str) -> subprocess.CompletedProcess:
    # Pas de « reset-failed » préalable : inutile (StartLimitIntervalSec=0
    # dans l'unité) et la règle polkit ne l'autorise pas sans mot de passe.
    return systemctl(action, SERVICE_NAME)


def lire_statut() -> dict:
    """État exposé par le daemon sur son socket Unix (lecture seule).
    Dict vide si le daemon ne tourne pas."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sk:
            sk.settimeout(1.5)
            sk.connect(str(STATUS_SOCKET))
            buf = b""
            while not buf.endswith(b"\n"):
                morceau = sk.recv(4096)
                if not morceau:
                    break
                buf += morceau
        return json.loads(buf.decode())
    except Exception:
        return {}


def lancer_reparation():
    """repair_network.sh exige root : mot de passe demandé hors root."""
    if not (SCRIPT_DIR / "repair_network.sh").exists():
        raise FileNotFoundError(f"{SCRIPT_DIR / 'repair_network.sh'} introuvable")
    return privilegie("repair_network.sh")


# ── Préférences de l'interface (propres à chaque compte) ─────────────────────
#
# Hors de /etc/katakomba : elles ne regardent pas le daemon, et chaque
# utilisateur du groupe a les siennes.

def _config_utilisateur() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


PREFERENCES_FILE = _config_utilisateur() / "katakomba" / "interface.json"
# Même nom que l'application : GNOME rattache ainsi l'entrée à Katakomba.
LANCEMENT_SESSION_FILE = _config_utilisateur() / "autostart" / "org.katakomba.Katakomba.desktop"
PREFERENCES_DEFAUT = {
    "arriere_plan": True,           # fermer la fenêtre laisse l'interface veiller
    "notifications": True,
    "avis_arriere_plan_vu": False,  # explication donnée à la première fermeture
    "langue": "",                   # "" : langue du système
}


def charger_preferences() -> dict:
    prefs = dict(PREFERENCES_DEFAUT)
    try:
        lues = json.loads(PREFERENCES_FILE.read_text())
    except (OSError, ValueError):
        return prefs
    if isinstance(lues, dict):
        prefs.update({k: v for k, v in lues.items()
                      if k in PREFERENCES_DEFAUT and type(v) is type(PREFERENCES_DEFAUT[k])})
    if prefs["langue"] not in LANGUES:
        prefs["langue"] = ""
    return prefs


def enregistrer_preferences(prefs: dict):
    PREFERENCES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PREFERENCES_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({k: type(v)(prefs.get(k, v))
                               for k, v in PREFERENCES_DEFAUT.items()}, indent=2))
    os.replace(tmp, PREFERENCES_FILE)


def lancement_session_actif() -> bool:
    try:
        texte = LANCEMENT_SESSION_FILE.read_text()
    except OSError:
        return False
    return "X-Katakomba=1" in texte and "Hidden=true" not in texte


def regler_lancement_session(actif: bool):
    """Entrée ~/.config/autostart : l'interface démarre cachée à l'ouverture
    de session, pour veiller sur la connexion et prévenir en cas de coupure."""
    if not actif:
        # Une entrée écrite par l'utilisateur lui-même n'est pas la nôtre.
        if lancement_session_actif():
            LANCEMENT_SESSION_FILE.unlink()
        return
    LANCEMENT_SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    LANCEMENT_SESSION_FILE.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Katakomba\n"
        "Comment=" + _("Veille sur la connexion et prévient en cas de coupure") + "\n"
        "Exec=katakomba gui --arriere-plan\n"
        "Icon=katakomba\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
        "X-GNOME-Autostart-enabled=true\n"
        "X-Katakomba=1\n")


# ── Ce que l'écran d'accueil affiche ─────────────────────────────────────────

# Raisons de reconnexion publiées par le daemon (en français, dans ses
# journaux) : traduites à l'affichage.
RAISONS = (N_("démarrage du service"), N_("redémarrage complet de Tor et d'OpenVPN"),
           N_("perte de connectivité, relance d'OpenVPN"),
           N_("circuit Tor trop lent, nouveau tirage"), N_("connexion VPN interrompue"),
           N_("identifiants refusés, compte suivant"))


def raison_lisible(raison: str) -> str:
    """Raison du daemon, traduite, avec une majuscule."""
    texte = _(raison) if raison else ""
    return texte[:1].upper() + texte[1:]


def resume_etat(service: str, st: dict, nb_fournisseurs: int = 1) -> dict:
    """Traduit l'état du service et du daemon pour l'écran d'accueil.

    niveau : « ok », « attente », « erreur » ou « arret » ; action : ce que
    fait le bouton principal (« demarrer », « arreter », « configurer »)."""
    if nb_fournisseurs == 0:
        return {"niveau": "arret", "titre": _("Aucun fournisseur"),
                "detail": _("Ajoutez votre fournisseur VPN pour commencer : "
                            "l'assistant vous guide."),
                "action": "configurer"}
    if service == "failed":
        return {"niveau": "erreur", "titre": _("Arrêté sur une erreur"),
                "detail": _("Le détail est dans le journal. Vous pouvez relancer "
                            "la connexion."),
                "action": "demarrer"}
    if service in ("activating", "reloading") or (service == "active" and not st):
        return {"niveau": "attente", "titre": _("Démarrage…"),
                "detail": _("Le service démarre."), "action": "arreter"}
    if service != "active":
        return {"niveau": "arret", "titre": _("Déconnecté"),
                "detail": _("Votre trafic ne passe pas par Katakomba."),
                "action": "demarrer"}
    if st.get("tunnel_up"):
        return {"niveau": "ok", "titre": _("Connecté"),
                "detail": _("Tout le trafic de cet ordinateur passe par le VPN, "
                            "à travers Tor."),
                "action": "arreter"}
    raison = st.get("reconnect_reason", "")
    if raison and raison != "démarrage du service":
        return {"niveau": "attente", "titre": _("Reconnexion…"),
                "detail": _("{raison} — depuis {duree}.").format(
                    raison=raison_lisible(raison),
                    duree=duree_lisible(st.get("tunnel_down_for", 0))),
                "action": "arreter"}
    if not st.get("tor_ready"):
        return {"niveau": "attente", "titre": _("Connexion au réseau Tor…"),
                "detail": _("1 à 3 minutes la première fois."), "action": "arreter"}
    return {"niveau": "attente", "titre": _("Connexion au VPN…"),
            "detail": _("À travers Tor, en général en moins de 30 secondes."),
            "action": "arreter"}


def trajet(service: str, st: dict, nb_fournisseurs: int = 1) -> list:
    """Les quatre étapes du trafic, pour le schéma de l'écran d'accueil :
    [{cle, icone, niveau, titre, detail, progression}].  Rien n'est mesuré
    ici : tout vient de l'état que le daemon publie déjà.  progression (0-1)
    n'existe que pour Tor en cours de démarrage : l'anneau de son étape."""
    actif = service == "active" and bool(st)
    tor_ok = actif and st.get("tor_ready")
    vpn_ok = actif and st.get("tunnel_up")
    reconnexion = actif and not vpn_ok

    if actif:
        ordi = ("ok", _("Trafic redirigé"))
    else:
        ordi = ("arret", _("Trafic direct"))

    if tor_ok:
        gardes = st.get("tor_guard_routes")
        tor = ("ok", ngettext("{n} relais d'entrée", "{n} relais d'entrée",
                              len(gardes)).format(n=len(gardes))
               if gardes else _("Circuit établi"))
    elif actif:
        amorce = st.get("tor_bootstrap") or 0
        tor = ("attente", _insecable(_("Démarrage : {n} %").format(n=amorce))
               if 0 < amorce < 100 else _("Connexion…"))
    elif service == "failed":
        tor = ("erreur", _("Arrêté"))
    else:
        tor = ("arret", _("Inactif"))

    fournisseur = st.get("provider") if actif else ""
    if vpn_ok:
        vpn = ("ok", _("Compte {n}").format(n=st.get("account_index", 0) + 1))
    elif reconnexion and tor_ok:
        vpn = ("attente", _("Reconnexion…") if st.get("reconnect_reason")
               and st.get("reconnect_reason") != "démarrage du service" else _("Connexion…"))
    elif reconnexion:
        vpn = ("attente", _("En attente de Tor"))
    elif nb_fournisseurs == 0:
        vpn = ("arret", _("Aucun fournisseur"))
    elif service == "failed":
        vpn = ("erreur", _("Arrêté"))
    else:
        vpn = ("arret", _("Inactif"))

    if vpn_ok:
        net = ("ok", _("Via le VPN"))
    elif actif:
        net = ("attente", _("En attente du tunnel"))
    else:
        net = ("arret", _("Sans Katakomba"))

    return [
        {"cle": "ordinateur", "icone": "computer-symbolic", "titre": _("Cet ordinateur"),
         "niveau": ordi[0], "detail": ordi[1]},
        {"cle": "tor", "icone": "katakomba-tor-symbolic", "titre": _("Réseau Tor"),
         "niveau": tor[0], "detail": tor[1],
         "progression": min(st.get("tor_bootstrap") or 0, 100) / 100
         if tor[0] == "attente" else None},
        {"cle": "vpn", "icone": "network-vpn-symbolic", "titre": fournisseur or _("VPN"),
         "niveau": vpn[0], "detail": vpn[1]},
        {"cle": "internet", "icone": "katakomba-internet-symbolic", "titre": _("Internet"),
         "niveau": net[0], "detail": net[1]},
    ]


def tuiles(service: str, st: dict) -> list:
    """Chiffres de l'écran d'accueil : [{cle, titre, valeur, detail}]."""
    actif = service == "active" and bool(st)
    connecte = actif and st.get("tunnel_up")
    kbs = (st.get("last_circuit_kbs") or 0) if actif else 0
    legeres = st.get("light_restarts", 0) if actif else 0
    completes = st.get("full_restarts", 0) if actif else 0
    age = st.get("last_circuit_age")
    if not actif:
        reprises = _("Depuis le démarrage")
    elif completes:
        reprises = ngettext("dont {n} redémarrage complet", "dont {n} redémarrages complets",
                            completes).format(n=completes)
    else:
        reprises = ngettext("relance légère", "relances légères", legeres)
    if connecte and kbs:
        debit = (_("{debit} · il y a {duree}").format(debit=kbs_lisible(kbs),
                                                      duree=duree_lisible(age))
                 if isinstance(age, (int, float)) else kbs_lisible(kbs))
    else:
        debit = _("Mesuré à la connexion")
    if not actif:
        ipv6 = ("—", _("Selon les réglages"))
    elif st.get("ipv6_blocked") or st.get("kill_switch"):
        ipv6 = (_("Bloqué"), _("Pas de fuite IPv6"))
    else:
        ipv6 = (_("Autorisé"), _("Peut contourner le tunnel"))
    return [
        {"cle": "duree", "titre": _("Connecté depuis"),
         "valeur": duree_lisible(st.get("tunnel_uptime", 0)) if connecte else "—",
         "detail": _("Tunnel actif") if connecte else _("Pas de tunnel")},
        {"cle": "circuit", "titre": _("Circuit Tor"),
         "valeur": kbs_en_mbps(kbs) if connecte and kbs else "—", "detail": debit},
        {"cle": "reprises", "titre": _("Reprises"),
         "valeur": str(legeres + completes) if actif else "—", "detail": reprises},
        {"cle": "ipv6", "titre": _("IPv6"), "valeur": ipv6[0], "detail": ipv6[1]},
    ]


def etat_connexion(service: str, st: dict, fournisseur: str = "",
                   compte: int = 0):
    """Assistant : (niveau, message, fini) pendant la première connexion.
    niveau : « attente », « ok » ou « erreur » ; fini : plus rien à attendre
    (connecté et débit mesuré, ou échec)."""
    if service == "failed":
        return ("erreur", _("Le service s'est arrêté sur une erreur. Le détail "
                            "est visible dans la page Journal."), True)
    if service != "active" or not st:
        return ("attente", _("Démarrage du service…"), False)
    if st.get("tunnel_up"):
        kbs = st.get("last_circuit_kbs") or 0
        message = _("Connecté : votre trafic passe par Tor, puis par le VPN.")
        if kbs:
            return ("ok", message + " " + _("Débit mesuré : {debit}.").format(
                debit=kbs_en_mbps(kbs)), True)
        return ("ok", message + " " + _("Mesure du débit en cours…"), False)
    refus = st.get("accounts_cooldown") or {}
    if st.get("provider") == fournisseur and str(compte + 1) in refus:
        return ("erreur", _("Le fournisseur a refusé l'identifiant ou le mot de "
                            "passe. Vérifiez-les : ce sont les identifiants OpenVPN, "
                            "souvent différents de ceux de votre compte sur le site "
                            "du fournisseur."), True)
    if not st.get("tor_ready"):
        return ("attente", _("Connexion au réseau Tor… (1 à 3 minutes la première "
                             "fois)"), False)
    return ("attente", _("Connexion au VPN à travers Tor…"), False)


# ── Journal ──────────────────────────────────────────────────────────────────

def lire_journal(lignes: int = 300) -> list:
    """Dernières lignes du journal du service (lecture sans privilège pour
    les membres des groupes adm ou systemd-journal)."""
    try:
        r = subprocess.run(
            ["journalctl", "-u", SERVICE_NAME, "-n", str(lignes), "--no-pager",
             "-o", "short-iso"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l for l in r.stdout.splitlines() if not l.startswith("-- ")]


# « … katakomba[123]: [2026-09-24 22:12:00] [WARN ] message »
_LIGNE = re.compile(r"\[(\d{4}-\d\d-\d\d) (\d\d:\d\d):\d\d\] \[(\w+)\s*\] (.*)$")

# Événements parlants pour l'utilisateur : (motif du journal, niveau, texte).
# Le texte reprend les groupes nommés du motif ; {debit} vient de (?P<kbs>).
_EVENEMENTS = (
    (re.compile(r"^Katakomba daemon v.* démarré"), "info", N_("Service démarré")),
    (re.compile(r"^Daemon arrêté proprement"), "arret", N_("Service arrêté")),
    (re.compile(r"^Tunnel VPN actif"), "ok", N_("Connecté")),
    (re.compile(r"^\[circuit\] Débit OK : (?P<kbs>\d+) KB/s"), "ok",
     N_("Circuit mesuré : {debit}")),
    (re.compile(r"^\[circuit\] Débit faible : (?P<kbs>\d+) KB/s"), "attente",
     N_("Circuit trop lent ({debit}) : nouveau tirage")),
    (re.compile(r"^\[circuit\] Débit toujours faible \((?P<kbs>\d+) KB/s\)"), "attente",
     N_("Circuit lent conservé ({debit})")),
    (re.compile(r"^Watchdog : Tor est sain"), "attente",
     N_("Connexion perdue : relance d'OpenVPN")),
    (re.compile(r"^Watchdog : redémarrage complet"), "attente",
     N_("Connexion perdue : redémarrage complet")),
    (re.compile(r"^Compte (?P<n>\d+) refusé"), "erreur",
     N_("Compte {n} refusé par le fournisseur")),
    (re.compile(r"^Fournisseur suivant"), "attente", N_("Bascule vers le fournisseur suivant")),
)


# Filtre côté journalctl : le journal est dominé par des messages répétitifs
# de Tor, si bien que les N dernières lignes brutes ne contiennent souvent
# aucun événement utile.
_FILTRE_EVENEMENTS = (r"démarré \(PID|arrêté proprement|Tunnel VPN actif|"
                      r"\[circuit\] Débit|Watchdog : (Tor est sain|redémarrage complet)|"
                      r"refusé|Fournisseur suivant")


def lire_evenements(maximum: int = 8) -> list:
    try:
        r = subprocess.run(
            ["journalctl", "-u", SERVICE_NAME, "--no-pager", "-o", "short-iso",
             "-n", str(maximum * 3), "-g", _FILTRE_EVENEMENTS],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return evenements(r.stdout.splitlines(), maximum)


def evenements(lignes, maximum: int = 8) -> list:
    """Traduit le journal en événements lisibles, du plus récent au plus
    ancien : [(date, heure, niveau, texte)]."""
    sortie = []
    # Horodatage ISO en tête de ligne : l'ordre lexicographique est
    # chronologique (journalctl -g ne le garantit pas).
    for ligne in sorted(lignes):
        m = _LIGNE.search(ligne)
        if not m:
            continue
        date, heure, message = m.group(1), m.group(2), m.group(4)
        for motif, niveau, texte in _EVENEMENTS:
            t = motif.search(message)
            if t:
                champs = t.groupdict()
                if "kbs" in champs:
                    champs["debit"] = kbs_en_mbps(int(champs.pop("kbs")))
                sortie.append((date, heure, niveau, _(texte).format(**champs)))
                break
    return sortie[::-1][:maximum]


# ── Diagnostic ───────────────────────────────────────────────────────────────

_CLI = ("/usr/bin/katakomba", "/usr/local/bin/katakomba")
# Sortie texte d'un CLI antérieur à --json : titres sur 26 colonnes.
_RESULTAT = re.compile(r"^\s*\[(OK  |WARN|KO  |\.\.\.\.|--  )\] (.{26}) ?(.*)$")
NIVEAUX_DIAG = {"OK  ": "ok", "WARN": "attention", "KO  ": "erreur",
                "....": "attente", "--  ": "reporte"}


def lancer_diagnostic(langue: str = ""):
    """Exécute « katakomba doctor --json » (lecture seule, sans root) dans
    la langue de l'interface ; renvoie (résultats [(niveau, titre, détail)],
    conclusion, code de sortie)."""
    cli = next((c for c in _CLI if os.path.exists(c)),
               str(SCRIPT_DIR / "katakomba-cli.sh"))
    env = {**os.environ, "KATAKOMBA_LANGUE": langue} if langue else None
    try:
        r = subprocess.run(["bash", cli, "doctor", "--json"], capture_output=True,
                           text=True, timeout=120, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], _("Diagnostic impossible : {erreur}").format(erreur=e), 1
    return lire_diagnostic(r.stdout, r.returncode)


def lire_diagnostic(sortie: str, code: int):
    try:
        d = json.loads(sortie.strip().splitlines()[-1])
        return ([(x["niveau"], x["titre"], x["detail"]) for x in d["resultats"]],
                " ".join(d["conclusion"]), d.get("code", code))
    except (ValueError, KeyError, IndexError, TypeError):
        pass
    resultats, conclusion = [], []
    for ligne in sortie.splitlines():
        m = _RESULTAT.match(ligne)
        if m:
            resultats.append((NIVEAUX_DIAG[m.group(1)], m.group(2).strip(),
                              m.group(3).strip()))
        elif resultats and ligne.strip() and not ligne.strip().startswith("╚"):
            conclusion.append(ligne.strip())
    return resultats, " ".join(conclusion), code


# ── Partage LAN ──────────────────────────────────────────────────────────────

def interface_sortie() -> str:
    """Interface portant la route par défaut : jamais proposée comme carte
    LAN, sinon l'accès réseau serait coupé."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for ligne in r.stdout.splitlines():
            parts = ligne.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def interfaces_lan() -> list:
    sortie = interface_sortie()
    try:
        return [i for i in sorted(os.listdir("/sys/class/net"))
                if i not in ("lo", sortie) and
                not i.startswith(("tun", "virbr", "docker", "wg", "veth", "br-"))]
    except OSError:
        return []


def maintenant() -> float:
    return time.time()
