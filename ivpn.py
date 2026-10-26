"""
IVPN : sessions WireGuard d'un compte, par l'API d'IVPN à travers Tor.

IVPN ne fournit pas de fichier WireGuard à télécharger : son application
génère une paire de clés, enregistre la clé publique en ouvrant une session
(« appareil ») sur le compte, et reçoit en retour l'adresse du tunnel.  Ce
module fait de même, sans jamais sortir de Tor : l'adresse réelle de la
machine n'est pas liée au compte.

Chaque session occupe une place d'appareil sur le compte (2 ou 7 selon la
formule).  Une session n'est forcée (les autres appareils du compte
déconnectés) que sur demande explicite : jamais par la ligne de commande,
et par le daemon seulement pour des comptes réservés à Katakomba, quand
tous sont pleins.

Trois usages :

  python3 ivpn.py creer --compte-katakomba 1 --pays NL --sortie ivpn-nl.conf
      Un .conf WireGuard ordinaire, plus des commentaires « # Katakomba-… »
      qui disent au pont comment joindre le serveur par TCP (emballage,
      adresse V2Ray, cible, identifiant VMess public, jeton de la session).
      Le numéro de compte peut aussi venir de la variable IVPN_COMPTE.

  python3 ivpn.py api
      Pour le daemon (WireGuard géré, v4.2.0) : une requête JSON sur
      l'entrée standard, la réponse JSON sur la sortie.  Lancé SANS AUCUN
      DROIT : c'est lui qui lit ce que le réseau renvoie.  Il ne voit jamais
      de clé privée, seulement des clés publiques.

  python3 ivpn.py liberer
      À la désinstallation : ferme la session gérée de cette machine, pour
      rendre sa place au compte.

Codes de l'API : ceux de l'application IVPN (daemon/api/types/errors.go).
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import random
import ssl
import sys
from datetime import date
from pathlib import Path

# Lancé par le daemon avec « python3 -I », qui retire le dossier du script
# des chemins d'import : on l'y remet (/opt/katakomba, à root).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pont_wg import ErreurPont, connexion_tcp     # noqa: E402

API = "api.ivpn.net"
PORT_WG_DIRECT = 2049            # port UDP ordinaire, pour mémoire (Endpoint)
PORT_V2RAY_TCP = 80              # VMess/TCP côté client (application IVPN)
CONFIG_KATAKOMBA = Path("/etc/katakomba/config.json")
SESSION_GEREE = Path("/var/lib/katakomba/ivpn-session.json")
REPONSE_MAX = 5_000_000          # octets ; la liste des serveurs en fait ~75 000

RESEAU = 0                       # pas de réponse exploitable (Tor, réseau)
SUCCES = 200
NON_AUTORISE = 401
SESSION_INCONNUE = 601
COMPTE_PLEIN = 602
COMPTE_INACTIF = 702
CAPTCHA = (70001, 70002)
DOUBLE_AUTH = (70011, 70012)


class ErreurIvpn(Exception):
    def __init__(self, message, code=RESEAU):
        super().__init__(message)
        self.code = code


class _ConnexionTor(http.client.HTTPSConnection):
    """HTTPS vers l'API, par le SOCKS de Tor, certificat VÉRIFIÉ : c'est ici
    que circule le numéro de compte."""

    def __init__(self, hote, socks):
        super().__init__(hote, 443, timeout=60,
                         context=ssl.create_default_context())
        self._socks = socks

    def connect(self):
        brut = connexion_tcp(self._socks, self.host, self.port)
        self.sock = self._context.wrap_socket(brut, server_hostname=self.host)


def requete(socks, methode, chemin, corps=None):
    c = _ConnexionTor(API, socks)
    try:
        donnees = None if corps is None else json.dumps(corps).encode()
        c.request(methode, chemin, body=donnees, headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": "Katakomba"})
        r = c.getresponse()
        texte = r.read(REPONSE_MAX)
    finally:
        c.close()
    try:
        reponse = json.loads(texte)
    except ValueError:
        raise ErreurIvpn(f"réponse illisible de l'API (HTTP {r.status})") from None
    if not isinstance(reponse, dict):
        raise ErreurIvpn(f"réponse inattendue de l'API (HTTP {r.status})")
    return r.status, reponse


def _code(statut, r) -> int:
    code = r.get("status", statut)
    return code if isinstance(code, int) else RESEAU


def _refus(code, r) -> ErreurIvpn:
    """L'erreur, en clair, d'une réponse sans succès."""
    if code == COMPTE_PLEIN:
        texte = ("compte plein : toutes ses places d'appareil sont prises")
    elif code == NON_AUTORISE:
        texte = "compte refusé (numéro inexistant)"
    elif code == COMPTE_INACTIF:
        texte = "compte inactif (abonnement expiré ?)"
    elif code == SESSION_INCONNUE:
        texte = "session inconnue (fermée, ou remise à zéro du compte)"
    elif code in CAPTCHA or r.get("captcha_id"):
        code = CAPTCHA[0]
        texte = "l'API demande un captcha : nouvel essai plus tard"
    elif code in DOUBLE_AUTH:
        texte = ("double authentification activée sur ce compte : aucune "
                 "session ne peut s'ouvrir sans vous")
    else:
        texte = f"refus de l'API : {str(r.get('message', '?'))[:200]} (code {code})"
    return ErreurIvpn(texte, code)


def serveurs(socks) -> dict:
    statut, liste = requete(socks, "GET", "/v5/servers.json")
    if statut != 200 or not isinstance(liste.get("wireguard"), list):
        raise ErreurIvpn(f"liste des serveurs indisponible (HTTP {statut})")
    return liste


def generer_cles():
    """(clé privée, clé publique), en base64 comme dans un .conf."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)
    cle = X25519PrivateKey.generate()
    privee = cle.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    publique = cle.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(privee).decode(), base64.b64encode(publique).decode()


def ouvrir_session(socks, compte, cle_publique, force=False) -> dict:
    """Nouvelle session (appareil) sur le compte, avec la clé WireGuard.
    {"jeton", "adresse"} ; ErreurIvpn sinon, avec le code de l'API.

    force : ferme d'abord toutes les autres sessions du compte."""
    statut, r = requete(socks, "POST", "/v4/session/new", {
        "username": compte, "force": bool(force), "wg_public_key": cle_publique})
    code = _code(statut, r)
    if code == SUCCES and r.get("token"):
        wg = r.get("wireguard") or {}
        if wg.get("status", 200) != 200 or not wg.get("ip_address"):
            raise ErreurIvpn("session ouverte, mais clé WireGuard refusée : "
                             f"{str(wg.get('message', '?'))[:200]}", code)
        return {"jeton": str(r["token"]), "adresse": str(wg["ip_address"])}
    raise _refus(code, r)


def statut_session(socks, jeton) -> dict:
    """{"actif": abonnement en cours, "jusqua": horodatage de fin}.
    ErreurIvpn de code SESSION_INCONNUE si la session n'existe plus."""
    statut, r = requete(socks, "POST", "/v4/session/status", {"session_token": jeton})
    code = _code(statut, r)
    if code != SUCCES:
        raise _refus(code, r)
    s = r.get("service_status") or {}
    jusqua = s.get("active_until")
    return {"actif": bool(s.get("is_active")),
            "jusqua": jusqua if isinstance(jusqua, int) else 0}


def changer_cle(socks, jeton, publique, active) -> str:
    """Nouvelle clé WireGuard pour la MÊME session (aucune place de plus).
    Renvoie l'adresse du tunnel, qui peut changer."""
    statut, r = requete(socks, "POST", "/v4/session/wg/set", {
        "session_token": jeton, "public_key": publique,
        "connected_public_key": active})
    code = _code(statut, r)
    if code != SUCCES or not r.get("ip_address"):
        raise _refus(code, r)
    return str(r["ip_address"])


def fermer_session(socks, jeton):
    """Ferme la session : sa place est rendue au compte.  Une session déjà
    fermée n'est pas une erreur."""
    statut, r = requete(socks, "POST", "/v4/session/delete", {"session_token": jeton})
    code = _code(statut, r)
    if code not in (SUCCES, SESSION_INCONNUE):
        raise _refus(code, r)


# ── Serveurs ─────────────────────────────────────────────────────────────────

def candidats(liste: dict, pays=None, ville=None) -> list:
    """(charge, passerelle, hôte) des serveurs WireGuard équipés de V2Ray,
    du moins chargé au plus chargé.  `pays` : un code ou une liste de codes."""
    if isinstance(pays, str):
        pays = [pays]
    voulus = {p.upper() for p in pays or []}
    trouves = []
    for passerelle in liste.get("wireguard", []):
        if not isinstance(passerelle, dict):
            continue
        if voulus and str(passerelle.get("country_code", "")).upper() not in voulus:
            continue
        if ville and ville.lower() not in str(passerelle.get("city", "")).lower():
            continue
        hotes = passerelle.get("hosts")
        for hote in hotes if isinstance(hotes, list) else []:
            if (isinstance(hote, dict) and hote.get("v2ray") and hote.get("public_key")
                    and hote.get("host")):
                charge = hote.get("load", 100)
                trouves.append((charge if isinstance(charge, (int, float)) else 100,
                                passerelle, hote))
    trouves.sort(key=lambda c: c[0])
    return trouves


def choisir_hote(liste: dict, pays=None, ville=None):
    """Un serveur WireGuard équipé de V2Ray, parmi les moins chargés."""
    trouves = candidats(liste, pays, ville)
    if not trouves:
        raise ErreurIvpn("aucun serveur WireGuard + V2Ray ne correspond")
    _, passerelle, hote = random.choice(trouves[:3])
    return passerelle, hote


def choisir_hotes(liste: dict, pays=None, n=3) -> list:
    """Jusqu'à `n` serveurs, chacun dans une ville différente si possible
    (une panne locale ne les emporte pas tous), tirés parmi les moins
    chargés.  Sans serveur dans les pays voulus : tous les pays."""
    trouves = candidats(liste, pays) or candidats(liste)
    tete = trouves[:max(3 * n, 6)]
    random.shuffle(tete)
    choisis, villes = [], set()
    for _, passerelle, hote in tete:
        ville = passerelle.get("city")
        if ville not in villes:
            choisis.append((passerelle, hote))
            villes.add(ville)
        if len(choisis) == n:
            return choisis
    for _, passerelle, hote in tete:        # moins de n villes : on complète
        if len(choisis) == n:
            break
        if (passerelle, hote) not in choisis:
            choisis.append((passerelle, hote))
    return choisis


def nom_hote(passerelle, hote) -> str:
    return str(hote.get("hostname", "?"))


def port_cible(liste: dict) -> int:
    """Port V2Ray interne vers WireGuard (config.ports.v2ray.wireguard)."""
    for p in liste["config"]["ports"]["v2ray"]["wireguard"]:
        if p.get("port"):
            return p["port"]
    raise ErreurIvpn("port V2Ray de WireGuard absent de la liste des serveurs")


def config_wg(cle_privee, adresse, liste, passerelle, hote, jeton=None) -> str:
    """Le texte du .conf.  Il passe ensuite par validation.analyser_wg, comme
    un fichier importé : rien de la liste des serveurs n'atteint wg ou le
    pont sans ce contrôle."""
    dns = str(hote.get("local_ip", "172.16.0.1/12")).split("/")[0]
    lignes = [
        f"# IVPN — {passerelle.get('city', '?')} ({hote.get('hostname', '?')}), "
        f"créé le {date.today().isoformat()} par Katakomba",
        "# Katakomba-Emballage = ivpn",
        f"# Katakomba-Serveur = {hote['v2ray']}:{PORT_V2RAY_TCP}",
        f"# Katakomba-Cible = {hote['host']}:{port_cible(liste)}",
        f"# Katakomba-UUID = {liste['config']['ports']['v2ray']['id']}",
    ]
    if jeton:
        lignes.append(f"# Katakomba-Session = {jeton}")
    return "\n".join(lignes + [
        "[Interface]",
        f"PrivateKey = {cle_privee}",
        f"Address = {adresse.split('/')[0]}/32",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {hote['public_key']}",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {hote['host']}:{PORT_WG_DIRECT}",
        "PersistentKeepalive = 25",
        "",
    ])


# ── Ligne de commande ────────────────────────────────────────────────────────

def compte_katakomba(numero: int) -> str:
    """Numéro de compte IVPN n° `numero` (à partir de 1) de la configuration
    de Katakomba, jamais affiché."""
    config = json.loads(CONFIG_KATAKOMBA.read_text())
    for p in config.get("providers", []):
        if p.get("name", "").lower() == "ivpn":
            comptes = p.get("accounts", [])
            if not 1 <= numero <= len(comptes):
                raise ErreurIvpn(f"compte {numero} absent ({len(comptes)} comptes)")
            return base64.b64decode(comptes[numero - 1]["u"]).decode().strip()
    raise ErreurIvpn("aucun fournisseur « ivpn » dans la configuration de Katakomba")


def creer(socks, compte, pays=None, ville=None) -> str:
    """Le texte du .conf.  Ouvre une session sur le compte."""
    liste = serveurs(socks)
    passerelle, hote = choisir_hote(liste, pays, ville)
    privee, publique = generer_cles()
    session = ouvrir_session(socks, compte, publique)
    return config_wg(privee, session["adresse"], liste, passerelle, hote,
                     session["jeton"])


ACTIONS = {
    "serveurs": lambda s, q: {"liste": serveurs(s)},
    "nouvelle": lambda s, q: ouvrir_session(s, q["compte"], q["publique"],
                                            q.get("force", False)),
    "statut":   lambda s, q: statut_session(s, q["jeton"]),
    "cle":      lambda s, q: {"adresse": changer_cle(s, q["jeton"], q["publique"],
                                                     q["active"])},
    "fermer":   lambda s, q: fermer_session(s, q["jeton"]) or {},
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
    except ErreurIvpn as e:
        return {"ok": False, "code": e.code, "message": str(e)}
    except (ErreurPont, OSError, http.client.HTTPException) as e:
        return {"ok": False, "code": RESEAU, "message": f"API injoignable : {e}"[:300]}
    except (KeyError, TypeError, ValueError) as e:
        return {"ok": False, "code": RESEAU, "message": f"réponse inattendue : {e}"[:300]}


def liberer(socks) -> int:
    """Ferme la session gérée de cette machine (désinstallation)."""
    try:
        etat = json.loads(SESSION_GEREE.read_text())
    except FileNotFoundError:
        return 0
    except (OSError, ValueError) as e:
        print(f"IVPN : session gérée illisible ({e}).", file=sys.stderr)
        return 1
    machine = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()[:16]
    if etat.get("machine") != machine:
        # Image disque clonée : la session est celle d'une autre machine.
        SESSION_GEREE.unlink(missing_ok=True)
        return 0
    try:
        fermer_session(socks, etat["jeton"])
    except (ErreurIvpn, ErreurPont, OSError, KeyError) as e:
        print(f"IVPN : session non fermée ({e}) ; sa place se libérera à la "
              "prochaine remise à zéro du compte.", file=sys.stderr)
        return 1
    SESSION_GEREE.unlink(missing_ok=True)
    print("IVPN : session de cette machine fermée, place rendue au compte.")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Sans sous-commande : « creer », comme avant la v4.2.0.
    commande = argv.pop(0) if argv and argv[0] in ("creer", "api", "liberer") else "creer"
    p = argparse.ArgumentParser(prog=f"ivpn.py {commande}",
                                description="Sessions WireGuard IVPN, par "
                                "l'API à travers Tor.")
    p.add_argument("--socks", default="127.0.0.1:9050")
    if commande == "creer":
        p.add_argument("--compte-katakomba", type=int, metavar="N",
                       help="prendre le compte IVPN n° N de /etc/katakomba/config.json "
                            "(sinon : variable IVPN_COMPTE)")
        p.add_argument("--pays", help="code pays, ex. NL")
        p.add_argument("--ville")
        p.add_argument("--sortie", required=True, help="fichier .conf à créer")
    a = p.parse_args(argv)
    if commande == "api":
        print(json.dumps(repondre(a.socks, sys.stdin.read(65536))))
        return 0
    if commande == "liberer":
        return liberer(a.socks)
    try:
        if a.compte_katakomba:
            compte = compte_katakomba(a.compte_katakomba)
        else:
            compte = os.environ.get("IVPN_COMPTE", "").strip()
            if not compte:
                p.error("numéro de compte manquant (--compte-katakomba ou IVPN_COMPTE)")
        texte = creer(a.socks, compte, a.pays, a.ville)
    except (ErreurIvpn, ErreurPont, OSError) as e:
        print(f"IVPN : {e}", file=sys.stderr)
        return 1
    fd = os.open(a.sortie, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(texte)
    entete = texte.splitlines()[0]
    print(f"Écrit : {a.sortie} — {entete[2:]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
