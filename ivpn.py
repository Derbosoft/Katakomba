"""
IVPN : configuration WireGuard d'un compte, obtenue par l'API d'IVPN à
travers Tor.

IVPN ne fournit pas de fichier WireGuard à télécharger : son application
génère une paire de clés, enregistre la clé publique en ouvrant une session
(« appareil ») sur le compte, et reçoit en retour l'adresse du tunnel.  Ce
module fait de même, sans jamais sortir de Tor : l'adresse réelle de la
machine n'est pas liée au compte.

Chaque session occupe une place d'appareil sur le compte (2 ou 7 selon la
formule).  Une session n'est jamais forcée : si le compte est plein, on le
dit, sans déconnecter les autres appareils.

Le fichier produit est un .conf WireGuard ordinaire, plus des commentaires
« # Katakomba-… » qui disent au pont comment joindre le serveur par TCP :
  Katakomba-Emballage  ivpn
  Katakomba-Serveur    adresse V2Ray du serveur, TCP 80
  Katakomba-Cible      adresse WireGuard du serveur, port V2Ray interne
  Katakomba-UUID       identifiant VMess (public, le même pour tous)
  Katakomba-Session    jeton de la session IVPN (pour la fermer plus tard)

Usage :
  python3 ivpn.py --socks unix:/run/…/socks --compte-katakomba 1 \\
                  --pays NL --sortie ivpn-nl.conf
  (le numéro de compte peut aussi venir de la variable IVPN_COMPTE)
"""

import argparse
import base64
import http.client
import json
import os
import random
import ssl
import sys
from datetime import date
from pathlib import Path

from pont_wg import ErreurPont, connexion_tcp

API = "api.ivpn.net"
PORT_WG_DIRECT = 2049            # port UDP ordinaire, pour mémoire (Endpoint)
PORT_V2RAY_TCP = 80              # VMess/TCP côté client (application IVPN)
CONFIG_KATAKOMBA = Path("/etc/katakomba/config.json")


class ErreurIvpn(Exception):
    pass


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
        texte = r.read(5_000_000)
    finally:
        c.close()
    try:
        return r.status, json.loads(texte)
    except ValueError:
        raise ErreurIvpn(f"réponse illisible de l'API (HTTP {r.status})") from None


def serveurs(socks) -> dict:
    statut, liste = requete(socks, "GET", "/v5/servers.json")
    if statut != 200 or "wireguard" not in liste:
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


def ouvrir_session(socks, compte, cle_publique) -> dict:
    """Nouvelle session (appareil) sur le compte, avec la clé WireGuard."""
    statut, r = requete(socks, "POST", "/v4/session/new", {
        "username": compte, "force": False, "wg_public_key": cle_publique})
    code = r.get("status", statut)
    if code == 200 and r.get("token"):
        wg = r.get("wireguard") or {}
        if wg.get("status", 200) != 200 or not wg.get("ip_address"):
            raise ErreurIvpn("session ouverte, mais clé WireGuard refusée : "
                             f"{wg.get('message', '?')}")
        return r
    if code == 602:
        raise ErreurIvpn("compte plein : toutes ses places d'appareil sont "
                         "prises (aucune session n'est forcée)")
    if code in (401, 4011, 400):
        raise ErreurIvpn("compte refusé (inexistant ou expiré)")
    if code == 702 or r.get("captcha_id"):
        raise ErreurIvpn("l'API demande un captcha : réessayer plus tard")
    raise ErreurIvpn(f"refus de l'API : {r.get('message', '?')} (code {code})")


def choisir_hote(liste: dict, pays=None, ville=None):
    """Un serveur WireGuard équipé de V2Ray, le moins chargé du pays demandé."""
    candidats = []
    for passerelle in liste["wireguard"]:
        if pays and passerelle.get("country_code", "").upper() != pays.upper():
            continue
        if ville and ville.lower() not in passerelle.get("city", "").lower():
            continue
        for hote in passerelle.get("hosts", []):
            if hote.get("v2ray") and hote.get("public_key") and hote.get("host"):
                candidats.append((hote.get("load", 100), passerelle, hote))
    if not candidats:
        raise ErreurIvpn("aucun serveur WireGuard + V2Ray ne correspond")
    candidats.sort(key=lambda c: c[0])
    _, passerelle, hote = random.choice(candidats[:3])
    return passerelle, hote


def port_cible(liste: dict) -> int:
    """Port V2Ray interne vers WireGuard (config.ports.v2ray.wireguard)."""
    for p in liste["config"]["ports"]["v2ray"]["wireguard"]:
        if p.get("port"):
            return p["port"]
    raise ErreurIvpn("port V2Ray de WireGuard absent de la liste des serveurs")


def config_wg(cle_privee, session, liste, passerelle, hote) -> str:
    dns = hote.get("local_ip", "172.16.0.1/12").split("/")[0]
    return "\n".join([
        f"# IVPN — {passerelle.get('city', '?')} ({hote['hostname']}), "
        f"créé le {date.today().isoformat()} par Katakomba",
        "# Katakomba-Emballage = ivpn",
        f"# Katakomba-Serveur = {hote['v2ray']}:{PORT_V2RAY_TCP}",
        f"# Katakomba-Cible = {hote['host']}:{port_cible(liste)}",
        f"# Katakomba-UUID = {liste['config']['ports']['v2ray']['id']}",
        f"# Katakomba-Session = {session['token']}",
        "[Interface]",
        f"PrivateKey = {cle_privee}",
        f"Address = {session['wireguard']['ip_address'].split('/')[0]}/32",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {hote['public_key']}",
        "AllowedIPs = 0.0.0.0/0",
        f"Endpoint = {hote['host']}:{PORT_WG_DIRECT}",
        "PersistentKeepalive = 25",
        "",
    ])


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
    return config_wg(privee, session, liste, passerelle, hote)


def main(argv=None):
    p = argparse.ArgumentParser(description="Configuration WireGuard IVPN, "
                                "obtenue par l'API à travers Tor.")
    p.add_argument("--socks", default="127.0.0.1:9050")
    p.add_argument("--compte-katakomba", type=int, metavar="N",
                   help="prendre le compte IVPN n° N de /etc/katakomba/config.json "
                        "(sinon : variable IVPN_COMPTE)")
    p.add_argument("--pays", help="code pays, ex. NL")
    p.add_argument("--ville")
    p.add_argument("--sortie", required=True, help="fichier .conf à créer")
    a = p.parse_args(argv)
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
