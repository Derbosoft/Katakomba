#!/usr/bin/env python3
"""
Katakomba — état lisible depuis l'hôte d'une machine virtuelle (v4.13.0).

Lancé par systemd pour chaque connexion reçue sur le port vsock de
katakomba-vsock.socket (Accept=yes) : la connexion est l'entrée et la sortie
standard.  Activé par « sudo katakomba vsock on ».

Seul l'hôte de la machine virtuelle est servi (CID 2) : sur une machine qui
héberge elle-même des machines virtuelles, ce sont elles qui se
connecteraient, et elles n'ont rien à demander ici.

Protocole : une ligne, la commande ; une ligne de JSON en réponse, puis la
connexion se ferme.

    status    l'état du daemon, le JSON de /run/katakomba.sock
    ip        {"ip": "…"} : l'adresse de sortie, demandée par le tunnel
    doctor    le diagnostic, comme « katakomba doctor --json »
    restart   {"ok": true} une fois le service redémarré

Rien d'autre : ni configuration, ni arrêt, ni levée du blocage.
"""

import json
import socket
import subprocess
import sys

STATUS_SOCKET = "/run/katakomba.sock"
CLI = "/opt/katakomba/katakomba-cli.sh"
COMMANDES = ("status", "ip", "doctor", "restart")
LIGNE_MAX = 64
VMADDR_CID_HOST = getattr(socket, "VMADDR_CID_HOST", 2)


def pair_admis(conn) -> bool:
    """La connexion vient de l'hôte de la machine virtuelle, par vsock."""
    if conn.family != getattr(socket, "AF_VSOCK", 40):
        return False
    try:
        cid, _port = conn.getpeername()
    except (OSError, ValueError):
        return False
    return cid == VMADDR_CID_HOST


def lire_commande(conn) -> str:
    """Première ligne reçue, au plus LIGNE_MAX octets, en 10 s."""
    conn.settimeout(10)
    recu = b""
    while b"\n" not in recu and len(recu) <= LIGNE_MAX:
        bloc = conn.recv(LIGNE_MAX + 1 - len(recu))
        if not bloc:
            break
        recu += bloc
    return recu.split(b"\n", 1)[0].decode("ascii", errors="replace").strip()


def _executer(*cmd, delai):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=delai,
                           stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def _statut() -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(3)
        s.connect(STATUS_SOCKET)
        return json.loads(s.makefile().readline())
    finally:
        s.close()


def repondre(commande: str, executer=_executer, statut=_statut) -> dict:
    """Réponse à une commande, sous forme d'objet JSON."""
    if commande == "status":
        try:
            return statut()
        except (OSError, ValueError) as e:
            return {"erreur": f"état du daemon illisible ({e.__class__.__name__}) — "
                              "service arrêté ?"}
    if commande == "ip":
        rc, sortie = executer("bash", CLI, "ip", delai=20)
        ligne = sortie.strip().splitlines()[-1] if sortie.strip() else ""
        if rc == 0 and ligne and " " not in ligne:
            return {"ip": ligne}
        return {"erreur": ligne or "adresse de sortie inconnue"}
    if commande == "doctor":
        _rc, sortie = executer("bash", CLI, "doctor", "--json", delai=110)
        try:
            return json.loads(sortie)
        except ValueError:
            return {"erreur": "diagnostic illisible"}
    if commande == "restart":
        rc, _sortie = executer("bash", CLI, "restart", delai=90)
        return {"ok": True} if rc == 0 else {"erreur": "redémarrage refusé ou échoué"}
    return {"erreur": "commande inconnue", "commandes": list(COMMANDES)}


def main() -> int:
    conn = socket.socket(fileno=sys.stdin.fileno())
    try:
        if not pair_admis(conn):
            return 1
        reponse = repondre(lire_commande(conn))
        conn.sendall((json.dumps(reponse, ensure_ascii=False) + "\n").encode())
        return 0
    except OSError:
        return 1
    finally:
        conn.detach()


if __name__ == "__main__":
    sys.exit(main())
