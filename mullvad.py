"""
Mullvad : appareils WireGuard d'un compte, par l'API de Mullvad à travers Tor.

Chez Mullvad, un compte n'a pas de mot de passe : son numéro suffit.  Chaque
appareil enregistré (une clé publique) occupe une des 5 places du compte et
reçoit son adresse dans le tunnel.  Ce module ouvre, liste, vérifie et
supprime des appareils, sans jamais sortir de Tor (certificat de l'API
vérifié) : l'adresse réelle de la machine n'est pas liée au compte.

L'API donne la date de CRÉATION de chaque appareil, pas celle de sa dernière
utilisation.  Le daemon (WireGuard géré, v4.3.0) en fait une preuve de vie :
chaque PC remplace son appareil toutes les semaines ; un appareil bien plus
vieux appartient à un PC disparu.

Deux usages :

  python3 mullvad.py api
      Pour le daemon : une requête JSON sur l'entrée standard, la réponse
      JSON sur la sortie.  Lancé SANS AUCUN DROIT : c'est lui qui lit ce que
      le réseau renvoie.  Il ne voit jamais de clé privée.

  python3 mullvad.py liberer
      À la désinstallation : supprime l'appareil géré de cette machine, pour
      rendre sa place au compte.

Les codes d'erreur sont ceux d'ivpn.py : le daemon traite les deux services
de la même façon.  Codes de l'API Mullvad : mullvad-api/src/lib.rs.
"""

import argparse
import base64
import email.utils
import hashlib
import http.client
import json
import os
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# Lancé par le daemon avec « python3 -I », qui retire le dossier du script
# des chemins d'import : on l'y remet (/opt/katakomba, à root).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ivpn import (                                       # noqa: E402
    COMPTE_PLEIN, NON_AUTORISE, REPONSE_MAX, RESEAU,
    SESSION_INCONNUE, _ConnexionTor)
from pont_wg import ErreurPont                           # noqa: E402

API = "api.mullvad.net"
PORT_WG = 51820                  # Endpoint du .conf ; le pont joint TCP 443 (udp-over-tcp)
DNS = "10.64.0.1"                # DNS de Mullvad dans le tunnel (reconnu par validation)
CONFIG_KATAKOMBA = Path("/etc/katakomba/config.json")
SESSION_GEREE = Path("/var/lib/katakomba/mullvad-session.json")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# Codes de l'API → vocabulaire commun (ivpn.py).
CODES = {"INVALID_ACCOUNT": NON_AUTORISE, "MAX_DEVICES_REACHED": COMPTE_PLEIN,
         "DEVICE_NOT_FOUND": SESSION_INCONNUE}


class ErreurMullvad(Exception):
    def __init__(self, message, code=RESEAU):
        super().__init__(message)
        self.code = code


def requete(socks, methode, chemin, corps=None, jeton=None):
    """(statut HTTP, réponse JSON ou None, heure du serveur)."""
    c = _ConnexionTor(API, socks)
    entetes = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "Katakomba"}
    if jeton:
        entetes["Authorization"] = f"Bearer {jeton}"
    try:
        c.request(methode, chemin, headers=entetes,
                  body=None if corps is None else json.dumps(corps).encode())
        r = c.getresponse()
        texte = r.read(REPONSE_MAX)
        date = r.getheader("Date")
    finally:
        c.close()
    try:
        serveur = email.utils.parsedate_to_datetime(date).timestamp() if date else time.time()
    except (TypeError, ValueError):
        serveur = time.time()
    if not texte.strip():
        return r.status, None, serveur
    try:
        return r.status, json.loads(texte), serveur
    except ValueError:
        raise ErreurMullvad(f"réponse illisible de l'API (HTTP {r.status})") from None


def _refus(statut, r) -> ErreurMullvad:
    code_api = r.get("code", "") if isinstance(r, dict) else ""
    code = CODES.get(code_api, RESEAU if statut >= 500 else statut)
    if code == COMPTE_PLEIN:
        texte = "compte plein : ses 5 places d'appareil sont prises"
    elif code == NON_AUTORISE:
        texte = "compte refusé (numéro inexistant)"
    elif code == SESSION_INCONNUE:
        texte = "appareil inconnu (supprimé, depuis le site ou par un autre PC)"
    elif statut == 429:
        texte = "trop de requêtes : nouvel essai plus tard"
    else:
        detail = str(r.get("error", "?") if isinstance(r, dict) else "?")[:200]
        texte = f"refus de l'API : {detail} (HTTP {statut}, {code_api or '-'})"
    return ErreurMullvad(texte, code)


def jeton(socks, compte) -> str:
    statut, r, _h = requete(socks, "POST", "/auth/v1/token", {"account_number": compte})
    if statut != 200 or not isinstance(r, dict) or not r.get("access_token"):
        raise _refus(statut, r)
    return str(r["access_token"])


def _appareil(a) -> dict:
    """Ce que le daemon garde d'un appareil : identifiant, adresse, date."""
    if not isinstance(a, dict) or not UUID.fullmatch(str(a.get("id", ""))):
        raise ErreurMullvad("appareil illisible dans la réponse de l'API")
    try:
        cree = datetime.fromisoformat(str(a.get("created"))).timestamp()
    except ValueError:
        cree = 0
    return {"jeton": a["id"], "adresse": str(a.get("ipv4_address", "")),
            "publique": str(a.get("pubkey", "")), "cree": int(cree)}


def _id(appareil: str) -> str:
    """Identifiant d'appareil sûr à placer dans un chemin d'URL."""
    if not UUID.fullmatch(str(appareil)):
        raise ErreurMullvad("identifiant d'appareil mal formé", SESSION_INCONNUE)
    return appareil


def nouvel_appareil(socks, compte, publique) -> dict:
    j = jeton(socks, compte)
    statut, r, _h = requete(socks, "POST", "/accounts/v1/devices",
                            {"pubkey": publique, "hijack_dns": False}, j)
    if statut != 201:
        raise _refus(statut, r)
    a = _appareil(r)
    if not a["adresse"]:
        raise ErreurMullvad("appareil créé sans adresse")
    return a


def appareils(socks, compte) -> dict:
    """{"appareils": [{jeton, cree}], "maintenant": heure du serveur} : l'âge
    d'un appareil se compte à l'heure de Mullvad, pas à celle du PC."""
    j = jeton(socks, compte)
    statut, r, serveur = requete(socks, "GET", "/accounts/v1/devices", jeton=j)
    if statut != 200 or not isinstance(r, list):
        raise _refus(statut, r)
    return {"appareils": [{"jeton": a["jeton"], "cree": a["cree"]}
                          for a in map(_appareil, r)],
            "maintenant": int(serveur)}


def statut_appareil(socks, compte, appareil) -> dict:
    """{"actif": compte en cours de validité, "jusqua", "publique"} ;
    ErreurMullvad de code SESSION_INCONNUE si l'appareil n'existe plus."""
    j = jeton(socks, compte)
    statut, r, serveur = requete(socks, "GET", f"/accounts/v1/devices/{_id(appareil)}", jeton=j)
    if statut != 200:
        raise _refus(statut, r)
    a = _appareil(r)
    statut, compte_r, _h = requete(socks, "GET", "/accounts/v1/accounts/me", jeton=j)
    if statut != 200 or not isinstance(compte_r, dict):
        raise _refus(statut, compte_r)
    try:
        jusqua = int(datetime.fromisoformat(str(compte_r.get("expiry"))).timestamp())
    except ValueError:
        jusqua = 0
    return {"actif": jusqua > serveur, "jusqua": jusqua, "publique": a["publique"]}


def changer_cle(socks, compte, appareil, publique) -> str:
    """Nouvelle clé pour le MÊME appareil ; renvoie son adresse."""
    j = jeton(socks, compte)
    statut, r, _h = requete(socks, "PUT", f"/accounts/v1/devices/{_id(appareil)}/pubkey",
                            {"pubkey": publique}, j)
    if statut != 200:
        raise _refus(statut, r)
    return _appareil(r)["adresse"]


def supprimer(socks, compte, appareil):
    """Supprime l'appareil ; un appareil déjà supprimé n'est pas une erreur."""
    j = jeton(socks, compte)
    statut, r, _h = requete(socks, "DELETE", f"/accounts/v1/devices/{_id(appareil)}", jeton=j)
    if statut not in (204, 404):
        raise _refus(statut, r)


def serveurs(socks) -> dict:
    statut, r, _h = requete(socks, "GET", "/app/v1/relays")
    if statut != 200 or not isinstance(r, dict) or not isinstance(
            (r.get("wireguard") or {}).get("relays"), list):
        raise ErreurMullvad(f"liste des relais indisponible (HTTP {statut})")
    # Seul ce qui sert : la liste complète fait plus de 600 Ko.
    return {"locations": r.get("locations") or {},
            "relays": [{c: x.get(c) for c in ("hostname", "location", "active",
                                                "ipv4_addr_in", "public_key", "weight")}
                       for x in r["wireguard"]["relays"] if isinstance(x, dict)]}


# ── Relais ───────────────────────────────────────────────────────────────────

def candidats(liste: dict, pays=None) -> list:
    """Relais WireGuard actifs, dans les pays voulus (codes à deux lettres)."""
    voulus = {p.lower() for p in pays or []}
    trouves = []
    for r in liste.get("relays", []):
        if not (isinstance(r, dict) and r.get("active") and r.get("ipv4_addr_in")
                and r.get("public_key") and isinstance(r.get("location"), str)):
            continue
        if voulus and r["location"].split("-")[0] not in voulus:
            continue
        trouves.append(r)
    return trouves


def choisir_hotes(liste: dict, pays=None, n=3) -> list:
    """Jusqu'à `n` relais, chacun dans une ville différente si possible,
    tirés au hasard selon le poids que Mullvad leur donne.  Sans relais dans
    les pays voulus : tous les pays."""
    trouves = candidats(liste, pays) or candidats(liste)
    choisis, villes, ecartes = [], set(), []
    while trouves and len(choisis) < n:
        poids = [max(1, r["weight"]) if isinstance(r.get("weight"), int) else 1
                 for r in trouves]
        r = random.choices(trouves, poids)[0]
        trouves.remove(r)
        if r["location"] in villes:
            ecartes.append(r)
            continue
        choisis.append((r,))
        villes.add(r["location"])
    # Moins de villes que de relais voulus : on complète.
    choisis += [(r,) for r in ecartes[:n - len(choisis)]]
    return choisis


def nom_hote(relais) -> str:
    return str(relais.get("hostname", "?"))


def config_wg(cle_privee, adresse, liste, relais) -> str:
    """Le texte du .conf ; il passe ensuite par validation.analyser_wg, qui
    reconnaît Mullvad à son DNS et en déduit l'emballage udp-over-tcp."""
    lieu = (liste.get("locations") or {}).get(relais["location"]) or {}
    return "\n".join([
        f"# Mullvad — {lieu.get('city', '?')} ({nom_hote(relais)}), "
        "appareil géré par Katakomba",
        "[Interface]",
        f"PrivateKey = {cle_privee}",
        f"Address = {adresse.split('/')[0]}/32",
        f"DNS = {DNS}",
        "",
        "[Peer]",
        f"PublicKey = {relais['public_key']}",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {relais['ipv4_addr_in']}:{PORT_WG}",
        "",
    ])


# ── Ligne de commande ────────────────────────────────────────────────────────

ACTIONS = {
    "serveurs":  lambda s, q: {"liste": serveurs(s)},
    "nouvelle":  lambda s, q: nouvel_appareil(s, q["compte"], q["publique"]),
    "appareils": lambda s, q: appareils(s, q["compte"]),
    "statut":    lambda s, q: statut_appareil(s, q["compte"], q["jeton"]),
    "cle":       lambda s, q: {"adresse": changer_cle(s, q["compte"], q["jeton"],
                                                      q["publique"])},
    "fermer":    lambda s, q: supprimer(s, q["compte"], q["jeton"]) or {},
}


def repondre(socks, requete_json: str) -> dict:
    """Une requête du daemon → sa réponse : {"ok": True, …} ou {"ok": False,
    "code", "message"}.  Le message ne contient jamais le numéro de compte."""
    try:
        q = json.loads(requete_json)
        action = ACTIONS[q["action"]]
    except (ValueError, KeyError, TypeError):
        return {"ok": False, "code": RESEAU, "message": "requête illisible"}
    try:
        return {"ok": True, **action(socks, q)}
    except ErreurMullvad as e:
        return {"ok": False, "code": e.code, "message": str(e)}
    except (ErreurPont, OSError, http.client.HTTPException) as e:
        return {"ok": False, "code": RESEAU, "message": f"API injoignable : {e}"[:300]}
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        return {"ok": False, "code": RESEAU, "message": f"réponse inattendue : {e}"[:300]}


def compte_par_empreinte(empreinte: str) -> str:
    """Le numéro de compte dont l'empreinte est `empreinte`, lu dans la
    configuration de Katakomba (l'état n'en garde que l'empreinte)."""
    config = json.loads(CONFIG_KATAKOMBA.read_text())
    for p in config.get("providers", []):
        for a in p.get("accounts", []) if isinstance(p, dict) else []:
            try:
                compte = base64.b64decode(a.get("u", "")).decode().strip()
            except (ValueError, AttributeError):
                continue
            if hashlib.sha256(compte.encode()).hexdigest()[:16] == empreinte:
                return compte
    return ""


def liberer(socks) -> int:
    """Supprime l'appareil géré de cette machine (désinstallation)."""
    try:
        etat = json.loads(SESSION_GEREE.read_text())
    except FileNotFoundError:
        return 0
    except (OSError, ValueError) as e:
        print(f"Mullvad : état de l'appareil géré illisible ({e}).", file=sys.stderr)
        return 1
    machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()[:16]
    if etat.get("machine") != machine:
        SESSION_GEREE.unlink(missing_ok=True)       # image clonée : pas à nous
        return 0
    try:
        compte = compte_par_empreinte(etat["compte"])
        if not compte:
            raise ErreurMullvad("compte absent de la configuration")
        supprimer(socks, compte, etat["jeton"])
    except (ErreurMullvad, ErreurPont, OSError, KeyError, ValueError) as e:
        print(f"Mullvad : appareil non supprimé ({e}) ; les autres PC du parc le "
              "supprimeront quand il sera trop ancien (comptes réservés), sinon "
              "depuis le site de Mullvad.", file=sys.stderr)
        return 1
    SESSION_GEREE.unlink(missing_ok=True)
    print("Mullvad : appareil de cette machine supprimé, place rendue au compte.")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    commande = argv.pop(0) if argv and argv[0] in ("api", "liberer") else ""
    p = argparse.ArgumentParser(prog="mullvad.py", description="Appareils WireGuard "
                                "Mullvad, par l'API à travers Tor (api | liberer).")
    p.add_argument("--socks", default="127.0.0.1:9050")
    a = p.parse_args(argv)
    if commande == "api":
        print(json.dumps(repondre(a.socks, sys.stdin.read(65536))))
        return 0
    if commande == "liberer":
        return liberer(a.socks)
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
