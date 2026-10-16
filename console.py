#!/usr/bin/env python3
"""
Katakomba sans interface graphique : configuration en ligne de commande,
pour un serveur ou une machine sans écran.  Appelé par le CLI :

    katakomba provider add ivpn.ovpn         (fournisseur, compte, exclusion…)
    katakomba help                           (toutes les commandes)

Mêmes contrôles que l'interface graphique : tout passe par gui/modele.py,
qui n'a aucune dépendance graphique, et par validation.py.  Les réglages
sont lus par le daemon à son démarrage : chaque modification le rappelle.

Utilisable par root ou par un membre du groupe katakomba, sans sudo.  En
root, aucune écriture ne suit un lien symbolique (modele.ecrire_sans_lien) :
les dossiers de configuration sont inscriptibles par le groupe.

Commandes en anglais, comme le reste du CLI (start, status, doctor…), avec
leurs équivalents français ; messages dans la langue de l'utilisateur.
"""

import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import i18n                                                    # noqa: E402
from i18n import _, ngettext                                   # noqa: E402
from gui import modele                                         # noqa: E402
from validation import exclusion_locale                        # noqa: E402

# Réglages exposés : nom en console → (clé de config.json, type).  Les mêmes
# que l'interface, sauf le partage LAN, rare sur un serveur.
REGLAGES = {
    "kill-switch":     ("kill_switch", "bool"),
    "block-ipv6":      ("block_ipv6", "bool"),
    "auto-reconnect":  ("auto_reconnect", "bool"),
    "random-account":  ("random_account", "bool"),
    "local-dns":       ("local_dns", "dns"),
    "circuit-check":   ("circuit_check", "bool"),
    "circuit-min-kbs": ("circuit_min_kbs", "int"),
    "circuit-retries": ("circuit_max_retries", "int"),
}
OUI = ("on", "yes", "true", "1", "oui")
NON = ("off", "no", "false", "0", "non")

# Équivalents français des commandes et des actions.
ALIAS = {"fournisseur": "provider", "compte": "account", "exclusion": "exclude",
         "reglage": "set", "sauvegarde": "backup", "aide": "help",
         "ajouter": "add", "retirer": "remove", "liste": "list",
         "priorite": "priority", "exporter": "export", "restaurer": "restore"}


class Erreur(Exception):
    """Erreur d'utilisation ou de saisie : message affiché, code 1."""


# ── Outils ───────────────────────────────────────────────────────────────────

def _verifier_droits():
    """Écriture possible dans la configuration ?  Message clair sinon, avant
    de demander quoi que ce soit (un mot de passe saisi pour rien)."""
    for chemin in (modele.CONFIG_DIR, modele.PROVIDERS_DIR):
        if not os.access(chemin, os.W_OK):
            raise Erreur(_("Votre compte ne peut pas modifier la configuration de "
                           "Katakomba : utilisez sudo, ou donnez-lui l'accès avec "
                           "« sudo katakomba autoriser <utilisateur> »."))


def _rappel_demarrage():
    """Le daemon lit sa configuration au démarrage."""
    print(_("Pris en compte au prochain démarrage du service : "
            "sudo katakomba restart") if modele.etat_service() == "active"
          else _("Démarrez le service : sudo katakomba start"))


def _enregistrer(config: dict):
    modele.enregistrer_config(config)
    _rappel_demarrage()


def _fournisseur(config: dict, nom: str) -> dict:
    for p in config.get("providers", []):
        if p.get("name", "").lower() == nom.strip().lower():
            return p
    raise Erreur(_("Aucun fournisseur « {nom} ». Liste : katakomba provider "
                   "list").format(nom=nom))


def _identifiants(depuis_stdin: bool) -> tuple:
    """Identifiant et mot de passe : demandés sans écho, ou lus sur l'entrée
    standard (deux lignes) pour un script.  Jamais en argument : ils
    seraient visibles de tous dans la liste des processus."""
    if depuis_stdin:
        lignes = sys.stdin.read().splitlines()
        if len(lignes) < 2 or not lignes[0].strip():
            raise Erreur(_("--stdin : attendu l'identifiant puis le mot de passe, "
                           "une ligne chacun."))
        return lignes[0].strip(), lignes[1]
    if not sys.stdin.isatty():
        raise Erreur(_("Pas de terminal pour saisir le mot de passe : passez "
                       "l'identifiant et le mot de passe sur l'entrée standard "
                       "avec --stdin."))
    identifiant = input(_("Identifiant") + " : ").strip()
    if not identifiant:
        raise Erreur(_("Identifiant vide."))
    return identifiant, getpass.getpass(_("Mot de passe") + " : ")


def _options(args: list, attendues: dict) -> tuple:
    """Sépare les options (--nom valeur, ou --drapeau) des arguments."""
    opts, reste = {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            if a not in attendues:
                raise Erreur(_("Option inconnue : {option}").format(option=a))
            if attendues[a]:
                if i + 1 >= len(args):
                    raise Erreur(_("{option} attend une valeur.").format(option=a))
                opts[a] = args[i + 1]
                i += 1
            else:
                opts[a] = True
        else:
            reste.append(a)
        i += 1
    return opts, reste


def _attendre(args: list, n: int, usage: str):
    if len(args) != n:
        raise Erreur(_("Usage : {usage}").format(usage=usage))


# ── Fournisseurs et comptes ──────────────────────────────────────────────────

def fournisseur(action: str, args: list):
    config = modele.charger_config()
    fournisseurs = config.setdefault("providers", [])

    if action == "list":
        _attendre(args, 0, "katakomba provider list")
        if not fournisseurs:
            print(_("Aucun fournisseur. Ajoutez-en un : katakomba provider add "
                    "<fichier.ovpn>"))
            return
        print(_("Fournisseurs, par ordre de priorité :"))
        for i, p in enumerate(fournisseurs, 1):
            n = len(p.get("accounts", []))
            print(f"  {i}. {p.get('name', '?'):<20} "
                  + ngettext("{n} compte", "{n} comptes", n).format(n=n)
                  + f"   {p.get('ovpn_file', '')}")
        return

    _verifier_droits()
    if action == "add":
        opts, fichiers = _options(args, {"--name": True, "--stdin": False})
        if not fichiers:
            raise Erreur(_("Usage : {usage}").format(
                usage=_("katakomba provider add <fichier.ovpn|archive.zip>… "
                        "[--name NOM] [--stdin]")))
        nom = (opts.get("--name") or modele.nom_depuis_fichier(fichiers[0])).strip()
        erreur = modele.verifier_nom(nom, fournisseurs)
        if erreur:
            raise Erreur(erreur)
        res, erreurs = modele.preparer_import(fichiers)
        if erreurs:
            raise Erreur("\n".join(erreurs))
        print(modele.resume_adaptation(res))
        print()
        identifiant, mot_de_passe = _identifiants(opts.get("--stdin", False))
        modele.ajouter_fournisseur_adapte(config, nom, res, fichiers, identifiant,
                                          mot_de_passe)
        print(_("Fournisseur « {nom} » ajouté (priorité {rang}).").format(
            nom=nom, rang=len(fournisseurs)))
        _rappel_demarrage()
        return

    if action == "remove":
        _attendre(args, 1, _("katakomba provider remove <nom>"))
        p = _fournisseur(config, args[0])
        fournisseurs.remove(p)
        print(_("Fournisseur « {nom} » retiré.").format(nom=p.get("name", "")),
              _("Son fichier de configuration reste sur le disque."))
        _enregistrer(config)
        return

    if action == "priority":
        _attendre(args, 2, _("katakomba provider priority <nom> <rang>"))
        p = _fournisseur(config, args[0])
        try:
            rang = int(args[1])
        except ValueError:
            rang = 0
        if not 1 <= rang <= len(fournisseurs):
            raise Erreur(_("Rang entre 1 et {n}.").format(n=len(fournisseurs)))
        fournisseurs.remove(p)
        fournisseurs.insert(rang - 1, p)
        print(_("« {nom} » passe en priorité {rang}.").format(nom=p["name"], rang=rang))
        _enregistrer(config)
        return
    raise Erreur(_("Action inconnue : {action}").format(action=action))


def compte(action: str, args: list):
    config = modele.charger_config()
    if action == "list":
        _attendre(args, 1, _("katakomba account list <fournisseur>"))
        p = _fournisseur(config, args[0])
        for i, c in enumerate(p.get("accounts", []), 1):
            print(f"  {i}. {modele.deobf(c.get('u', ''))}")
        return

    _verifier_droits()
    if action == "add":
        opts, reste = _options(args, {"--stdin": False})
        _attendre(reste, 1, _("katakomba account add <fournisseur> [--stdin]"))
        p = _fournisseur(config, reste[0])
        identifiant, mot_de_passe = _identifiants(opts.get("--stdin", False))
        p.setdefault("accounts", []).append(
            {"u": modele.obf(identifiant), "p": modele.obf(mot_de_passe)})
        print(_("Compte « {nom} » ajouté à {fournisseur}.").format(
            nom=identifiant, fournisseur=p["name"]))
        _enregistrer(config)
        return

    if action == "remove":
        _attendre(args, 2, _("katakomba account remove <fournisseur> <numéro>"))
        p = _fournisseur(config, args[0])
        comptes = p.setdefault("accounts", [])
        try:
            i = int(args[1]) - 1
        except ValueError:
            i = -1
        if not 0 <= i < len(comptes):
            raise Erreur(_("Numéro de compte entre 1 et {n} (katakomba account list "
                           "{fournisseur}).").format(n=len(comptes), fournisseur=p["name"]))
        c = comptes.pop(i)
        print(_("Le compte « {nom} » sera retiré de ce fournisseur.").format(
            nom=modele.deobf(c.get("u", ""))))
        _enregistrer(config)
        return
    raise Erreur(_("Action inconnue : {action}").format(action=action))


# ── Exclusions ───────────────────────────────────────────────────────────────

def _normaliser_exclusion(valeur: str) -> tuple:
    """(clé de config, valeur normalisée) : réseau IPv4 ou nom de domaine."""
    est_domaine = any(c.isalpha() for c in valeur) and ":" not in valeur
    if est_domaine:
        norm, erreur = modele.verifier_domaine(valeur)
        cle = "excluded_domains"
    else:
        norm, erreur = modele.normaliser_ip(valeur)
        cle = "excluded_ips"
    if erreur or not norm:
        raise Erreur(erreur or _("Valeur vide."))
    return cle, norm


def exclusion(action: str, args: list):
    config = modele.charger_config()
    if action == "list":
        _attendre(args, 0, "katakomba exclude list")
        for cle, titre in (("excluded_ips", _("Réseaux exclus du tunnel")),
                           ("excluded_domains", _("Domaines résolus localement"))):
            valeurs = config.get(cle, [])
            print(f"{titre} :", ", ".join(valeurs) if valeurs else "—")
        dns = config.get("local_dns", "")
        print(_("Serveur DNS local") + " :", dns or "—")
        return

    _verifier_droits()
    _attendre(args, 1, _("katakomba exclude {action} <adresse|réseau|domaine>").format(
        action=action))
    cle, norm = _normaliser_exclusion(args[0])
    valeurs = config.setdefault(cle, [])
    if action == "add":
        if norm in valeurs:
            print(_("« {valeur} » est déjà exclu.").format(valeur=norm))
            return
        valeurs.append(norm)
        print(_("« {valeur} » exclu du tunnel.").format(valeur=norm))
        if cle == "excluded_ips" and not exclusion_locale(norm):
            print(_("Attention : ce trafic sort hors du tunnel, avec votre adresse "
                    "réelle."))
        if cle == "excluded_domains" and not config.get("local_dns"):
            print(_("Les domaines exclus sont résolus par le serveur DNS local : "
                    "réglez-le avec « katakomba set local-dns <adresse> »."))
    elif action == "remove":
        if norm not in valeurs:
            raise Erreur(_("« {valeur} » n'est pas dans la liste.").format(valeur=norm))
        valeurs.remove(norm)
        print(_("« {valeur} » retiré.").format(valeur=norm))
    else:
        raise Erreur(_("Action inconnue : {action}").format(action=action))
    _enregistrer(config)


# ── Réglages ─────────────────────────────────────────────────────────────────

def _afficher(valeur, genre: str) -> str:
    if genre == "bool":
        return "on" if valeur else "off"
    return str(valeur) if valeur not in ("", None) else "—"


def reglage(args: list):
    config = modele.charger_config()
    if not args:
        for nom, (cle, genre) in REGLAGES.items():
            print(f"  {nom:<17} {_afficher(config.get(cle), genre)}")
        return
    _attendre(args, 2, _("katakomba set <réglage> <valeur>"))
    nom, brut = args[0], args[1].strip()
    if nom not in REGLAGES:
        raise Erreur(_("Réglage inconnu : {nom}. Réglages : {liste}").format(
            nom=nom, liste=", ".join(REGLAGES)))
    _verifier_droits()
    cle, genre = REGLAGES[nom]
    if genre == "bool":
        if brut.lower() not in OUI + NON:
            raise Erreur(_("Valeur attendue : on ou off."))
        valeur = brut.lower() in OUI
    elif genre == "dns":
        valeur = "" if brut.lower() in ("none", "aucun", "-", "") else brut
        erreur = modele.erreur_dns(valeur)
        if erreur:
            raise Erreur(erreur)
    else:
        try:
            valeur = int(brut)
        except ValueError:
            raise Erreur(_("Nombre entier attendu.")) from None
    essai = {**config, cle: valeur}
    erreurs = modele.erreurs_config(essai)
    if erreurs:
        raise Erreur("\n".join(erreurs))
    config[cle] = valeur
    print(f"{nom} = {_afficher(valeur, genre)}")
    if cle == "kill_switch" and not valeur:
        print(_("Attention : pendant une reconnexion, le trafic peut sortir à "
                "découvert."))
    _enregistrer(config)


# ── Sauvegarde ───────────────────────────────────────────────────────────────

def sauvegarde(action: str, args: list):
    _attendre(args, 1, _("katakomba backup {action} <fichier.zip>").format(action=action))
    chemin = Path(args[0])
    if action == "export":
        if chemin.exists():
            raise Erreur(_("{fichier} existe déjà.").format(fichier=chemin))
        # Identifiants compris (base64, pas du chiffrement) : lisible par
        # son seul propriétaire.
        ancien = os.umask(0o077)
        try:
            modele.exporter(modele.charger_config(), chemin)
        finally:
            os.umask(ancien)
        print(_("Sauvegarde écrite : {fichier}").format(fichier=chemin))
        print(_("Elle contient vos identifiants : gardez-la en lieu sûr."))
        return
    if action == "restore":
        _verifier_droits()
        try:
            config, ecartes = modele.lire_sauvegarde(chemin)
        except (OSError, ValueError) as e:
            raise Erreur(str(e)) from None
        except Exception as e:
            raise Erreur(_("Ce fichier n'est pas une sauvegarde Katakomba.")
                         + f" ({e})") from None
        for e in ecartes:
            print("⚠", e)
        n = len(config.get("providers", []))
        print(ngettext("Sauvegarde restaurée : {n} fournisseur.",
                       "Sauvegarde restaurée : {n} fournisseurs.", n).format(n=n))
        _enregistrer(config)
        return
    raise Erreur(_("Action inconnue : {action}").format(action=action))


# ── Aide ─────────────────────────────────────────────────────────────────────

def aide():
    """Syntaxe et description traduites : les paramètres (<fichier>…) sont
    dans la langue de l'utilisateur, les commandes restent les mêmes."""
    sections = [
        (_("Service (sudo) :"), [
            (_("start [--essai [MIN]]"),
             _("Démarrer ; à l'essai : arrêt automatique sans « katakomba confirm » "
               "(5 min par défaut)")),
            ("confirm", _("Garder le service démarré à l'essai")),
            ("stop | restart", _("Arrêter, redémarrer")),
            ("enable | disable", _("Démarrage automatique au boot")),
        ]),
        (_("Configuration (sudo, ou membre du groupe katakomba) :"), [
            (_("provider list | add <fichier.ovpn|.zip>… [--name NOM] [--stdin]"), ""),
            (_("provider remove <nom> | priority <nom> <rang>"), ""),
            (_("account list <fournisseur> | add <fournisseur> [--stdin]"), ""),
            (_("account remove <fournisseur> <numéro>"), ""),
            (_("exclude list | add <adresse|réseau|domaine> | remove <…>"), ""),
            (_("set [<réglage> <valeur>]"), _("sans argument : réglages actuels")),
            (_("backup export | restore <fichier.zip>"), ""),
            ("gui", _("Interface graphique (paquet katakomba)")),
        ]),
        (_("Surveillance :"), [
            ("status", _("État complet")),
            ("doctor", _("Diagnostic : routage, DNS, fuites")),
            ("logs [n] | follow | ip", ""),
        ]),
        (_("Installation (sudo) :"), [
            (_("autoriser <utilisateur>"), _("Donner accès à la configuration à un compte")),
            ("uninstall [--purge]", ""),
        ]),
    ]
    lignes = [_("Usage : katakomba <commande>")]
    for titre, rangees in sections:
        largeur = max(len(s) for s, d in rangees if d)
        lignes += ["", titre]
        lignes += [f"  {s:<{largeur}}  {d}" if d else f"  {s}" for s, d in rangees]
    lignes += ["", _("Équivalents français : fournisseur, compte, exclusion, reglage, "
                     "sauvegarde ; ajouter, retirer, liste, priorite, exporter, "
                     "restaurer ; confirmer.")]
    print("\n".join(lignes))


# ── Point d'entrée ───────────────────────────────────────────────────────────

def main(argv: list) -> int:
    i18n.activer(os.environ.get("KATAKOMBA_LANGUE", ""))
    # Fichiers créés lisibles et modifiables par le groupe katakomba
    # (l'interface graphique, sans root), jamais par les autres.
    os.umask(0o007)
    mots = [ALIAS.get(a, a) for a in argv[:2]] + argv[2:]
    commande = mots[0] if mots else "help"
    action = mots[1] if len(mots) > 1 else "list"
    reste = mots[2:]
    try:
        if commande == "provider":
            fournisseur(action, reste)
        elif commande == "account":
            compte(action, reste)
        elif commande == "exclude":
            exclusion(action, reste)
        elif commande == "set":
            reglage(mots[1:])
        elif commande == "backup":
            if len(mots) < 2:
                raise Erreur(_("Usage : {usage}").format(
                    usage=_("katakomba backup export|restore <fichier.zip>")))
            sauvegarde(action, reste)
        elif commande == "help":
            aide()
        else:
            aide()
            return 2
    except Erreur as e:
        print(str(e), file=sys.stderr)
        return 1
    except PermissionError:
        print(modele.message_droits(), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
