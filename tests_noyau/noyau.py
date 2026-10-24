"""Outils des vérifications sur vrai noyau (voir lancer.sh).

Garde-fou : rien ne tourne hors d'un espace réseau neuf.  Le daemon de test
(FakeDaemon, tests/helpers.py) écrit ses fichiers dans un bac à sable ; ses
commandes ip/iptables, elles, sont réelles, mais ne voient que cet espace."""

import ipaddress
import os
import socket
import subprocess
import threading
import time
import unittest

DANS_LE_BAC = os.environ.get("KATAKOMBA_NOYAU") == "1"


def _verifier_isolement():
    if not DANS_LE_BAC:
        return "lancer avec bash tests_noyau/lancer.sh"
    if os.readlink("/proc/self/ns/net") == os.environ.get("KATAKOMBA_NS_HOTE"):
        return "espace réseau de la machine : refus"
    liens = subprocess.run(["ip", "-o", "link", "show"], capture_output=True,
                           text=True).stdout.split("\n")
    noms = {l.split(":")[1].strip().split("@")[0] for l in liens if l.count(":") >= 2}
    if noms - {"lo"}:
        return f"espace réseau déjà occupé ({', '.join(sorted(noms))}) : refus"
    return ""


RAISON = _verifier_isolement()
if DANS_LE_BAC and RAISON:
    raise SystemExit(f"tests_noyau : {RAISON}")


def sh(cmd, ok=True, entree=None):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=entree)
    if ok and r.returncode:
        raise AssertionError(f"« {cmd} » : {r.stderr.strip()}")
    return r.stdout


def root_reel() -> bool:
    """Root de la machine (CI), et non root d'un espace utilisateur : seul
    le premier peut prendre une autre identité (setpriv)."""
    try:
        with open("/proc/self/uid_map") as f:
            return f.read().split()[:3] == ["0", "0", "4294967295"]
    except OSError:
        return False


class Pair:
    """Second espace réseau relié par une paire veth : le routeur local et,
    derrière lui, « Internet » (adresses ajoutées sur sa boucle locale)."""

    def __init__(self, adresse="192.168.1.1/24", hote="192.168.1.20/24"):
        self.proc = subprocess.Popen(["unshare", "-n", "sleep", "3600"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.enfants = [self.proc]
        for _ in range(100):
            if os.readlink(f"/proc/{self.proc.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.01)
        self.pid = self.proc.pid
        sh(f"ip link add eth0 type veth peer name eth0 netns {self.pid}")
        sh(f"ip addr add {hote} dev eth0 && ip link set eth0 up && ip link set lo up")
        self.run(f"ip link set lo up && ip addr add {adresse} dev eth0 && ip link set eth0 up")
        self.run(f"ip route add default via {hote.split('/')[0]}")
        # Comme un vrai routeur : ses requêtes ARP partent de son adresse LAN,
        # pas de celle du client d'Internet qu'il relaie (portée ici par sa
        # boucle locale) — que le filtrage strict de la machine jetterait.
        self.run("echo 2 > /proc/sys/net/ipv4/conf/eth0/arp_announce")
        self.adresse = adresse.split("/")[0]

    def run(self, cmd, ok=True, entree=None):
        return sh(f"nsenter -t {self.pid} -n sh -c '{cmd}'", ok=ok, entree=entree)

    def internet(self, adresse):
        """Une adresse « sur Internet », portée par le pair."""
        self.run(f"ip addr add {adresse}/32 dev lo")

    def serveur(self, port):
        """Serveur TCP d'écho dans le pair, IPv4 et IPv6."""
        code = ("import socket\n"
                f"s=socket.create_server(('::', {port}), family=socket.AF_INET6,"
                " dualstack_ipv6=True)\n"
                "while True:\n"
                "    c,_=s.accept(); c.sendall(c.recv(64)); c.close()\n")
        # Sortie fermée : un enfant qui la garderait ouverte ferait attendre
        # le lanceur jusqu'à sa fin.
        p = subprocess.Popen(["nsenter", "-t", str(self.pid), "-n", "python3", "-c", code],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.enfants.append(p)
        time.sleep(0.3)
        return p

    def serveur_udp(self, port):
        """Écho UDP dans le pair (un résolveur DNS, par exemple)."""
        code = ("import socket\n"
                f"s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', {port}))\n"
                "while True:\n"
                "    d,a=s.recvfrom(64); s.sendto(d, a)\n")
        p = subprocess.Popen(["nsenter", "-t", str(self.pid), "-n", "python3", "-c", code],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.enfants.append(p)
        time.sleep(0.3)

    def joindre(self, adresse, port, source=None, delai=2.0) -> bool:
        """Connexion TCP DEPUIS le pair (un client venu d'Internet)."""
        lier = f"s.bind(('{source}', 0)); " if source else ""
        code = ("import socket,sys\n"
                f"s=socket.socket(); s.settimeout({delai}); {lier}\n"
                f"s.connect(('{adresse}', {port})); s.sendall(b'kk'); "
                "sys.exit(0 if s.recv(8)==b'kk' else 1)")
        r = subprocess.run(["nsenter", "-t", str(self.pid), "-n", "python3", "-c", code],
                           capture_output=True)
        return r.returncode == 0

    def fermer(self):
        for p in self.enfants:
            p.kill()
            p.wait()


def joindre(adresse, port, delai=2.0, source=None) -> str:
    """Connexion TCP depuis la machine : « ok », « refus » ou « muet »."""
    s = socket.socket(socket.AF_INET6 if ":" in adresse else socket.AF_INET)
    s.settimeout(delai)
    try:
        if source:
            s.bind((source, 0))
        s.connect((adresse, port))
        s.sendall(b"kk")
        return "ok" if s.recv(8) == b"kk" else "muet"
    # EPERM : refusé sur place par le pare-feu (REJECT en sortie, UDP).
    except (ConnectionRefusedError, PermissionError):
        return "refus"
    except OSError:
        return "muet"
    finally:
        s.close()


def udp(adresse, port, delai=1.0) -> str:
    """Datagramme depuis la machine : « ok » (écho reçu), « refus » ou « muet »."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(delai)
    try:
        s.connect((adresse, port))
        s.send(b"kk")
        return "ok" if s.recv(8) == b"kk" else "muet"
    # EPERM : refusé sur place par le pare-feu (REJECT en sortie, UDP).
    except (ConnectionRefusedError, PermissionError):
        return "refus"
    except OSError:
        return "muet"
    finally:
        s.close()


class Ecoute:
    """Serveur TCP d'écho sur la machine (SSH, service web…)."""

    def __init__(self, port):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("0.0.0.0", port))
        self.s.listen(8)
        self.s.settimeout(0.2)
        self.fin = False
        self.fil = threading.Thread(target=self._boucle, daemon=True)
        self.fil.start()

    def _boucle(self):
        while not self.fin:
            try:
                c, _ = self.s.accept()
            except OSError:
                continue
            try:
                c.settimeout(5)
                c.sendall(c.recv(64))
            except OSError:
                pass
            c.close()

    def fermer(self):
        # Fermé sous un accept() en cours, le port resterait pris jusqu'à son
        # retour : le test suivant ne pourrait pas s'y lier.
        self.fin = True
        self.fil.join()
        self.s.close()


def via(ip, marque=None) -> str:
    """Interface que le noyau choisirait pour joindre `ip`."""
    m = f" mark {marque}" if marque else ""
    return sh(f"ip -4 route get {ip}{m}").split(" dev ")[1].split()[0]


REGLAGES = {"refus": [], "ifconfig": ("10.8.0.2", "255.255.255.0"), "topology": "subnet",
            "tun_mtu": 1500, "routes": [], "dns": []}


def daemon_de_test(**config):
    """Vrai daemon (tous les mixins), commandes réelles, fichiers en bac à
    sable.  Passerelle d'origine 192.168.1.1 sur eth0, comme le pair."""
    from tests.helpers import FakeDaemon
    import daemon.network as m_network
    # Réglage noyau propre à CET espace réseau : le vrai fichier.
    m_network.SRC_VALID_MARK = __import__("pathlib").Path(
        "/proc/sys/net/ipv4/conf/all/src_valid_mark")
    d = FakeDaemon(config=config, _tun_iface="tun-katakomba",
                   _orig_gw="192.168.1.1", _orig_iface="eth0")
    d._interface_existe = lambda nom: True      # /sys est celui de la machine
    d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
    return d


def sans_passe_droit_hors_root(d):
    """En espace utilisateur, seul l'uid 0 existe : iptables refuse la règle
    « --uid-owner » de Tor sur tout autre uid.  On la retire alors — le reste
    des règles, dans le même ordre, est vérifié tel quel ; elle-même l'est en
    root réel (CI), avec un vrai programme lancé sous cet utilisateur."""
    if root_reel():
        return
    vraies = d._kill_switch_rules
    d._kill_switch_rules = lambda v6, fwd, uid: [
        r for r in vraies(v6, fwd, uid) if "--uid-owner" not in r]


def monter_tunnel(d, relais=()):
    """Interface tunnel réelle (personne ne la lit : ce qui y entre est
    perdu, comme dans un tunnel mort) et montage par le vrai daemon."""
    sh("ip tuntap add dev tun-katakomba mode tun")
    d.tor_process = type("P", (), {"pid": 1})()
    d._tor_relay_ips = lambda: set(relais)
    assert d._monter_tunnel(dict(REGLAGES)), "\n".join(m for _n, m in d.logs)


class CasNoyau(unittest.TestCase):
    """Chaque test part d'un espace réseau vide et y revient."""

    def setUp(self):
        if not DANS_LE_BAC:
            self.skipTest(RAISON)
        # Nettoyage enregistré AVANT de rien créer : il tourne même si le
        # reste du setUp échoue, sans quoi tous les tests suivants héritent
        # des interfaces du précédent.
        self.pair = None
        self.addCleanup(self._nettoyer)
        self.pair = Pair()

    def _nettoyer(self):
        if self.pair:
            self.pair.fermer()
        sh("ip link del tun-katakomba", ok=False)
        sh("ip link del eth0", ok=False)
        for t in ("iptables", "ip6tables"):
            for table in ("filter", "mangle", "nat"):
                sh(f"{t} -t {table} -F; {t} -t {table} -X", ok=False)
        sh("ip rule del priority 30300; ip rule del priority 30301; "
           "ip route flush table 19265", ok=False)
        restant = sh("ip -o link show")
        assert "eth0" not in restant and "tun-katakomba" not in restant, restant


__all__ = ["CasNoyau", "Ecoute", "Pair", "daemon_de_test", "ipaddress", "joindre",
           "monter_tunnel", "root_reel", "sans_passe_droit_hors_root", "sh", "udp", "via"]
