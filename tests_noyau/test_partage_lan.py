"""Partage LAN : le DNS des clients, demandé à la passerelle, sort dans le
tunnel vers celui du VPN, et suit ses changements (v4.10.0).  Rejoué sur un
vrai noyau : un client dans son propre espace réseau, et ce qui entre dans
tun-katakomba lu sur le périphérique lui-même."""

import fcntl
import os
import select
import struct
import subprocess
import time

from tests_noyau.noyau import CasNoyau, daemon_de_test, monter_tunnel, sh

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000


def _somme(octets: bytes) -> int:
    if len(octets) % 2:
        octets += b"\0"
    s = sum(struct.unpack(f"!{len(octets) // 2}H", octets))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Tunnel:
    """L'autre bout de tun-katakomba : lit les paquets que le noyau y envoie
    et peut répondre, comme le ferait le serveur VPN."""

    def __init__(self):
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(self.fd, TUNSETIFF,
                    struct.pack("16sH", b"tun-katakomba", IFF_TUN | IFF_NO_PI))

    def requete_dns(self, delai=3.0):
        """Premier datagramme UDP vers le port 53 : (source, destination, paquet)."""
        fin = time.monotonic() + delai
        while time.monotonic() < fin:
            if not select.select([self.fd], [], [], 0.2)[0]:
                continue
            p = os.read(self.fd, 2048)
            if p[0] >> 4 != 4 or p[9] != 17:
                continue
            ihl = (p[0] & 0xF) * 4
            if struct.unpack("!H", p[ihl + 2:ihl + 4])[0] == 53:
                return (".".join(map(str, p[12:16])), ".".join(map(str, p[16:20])), p)
        return None

    def repondre(self, p: bytes, donnees: bytes):
        """Réponse du « DNS du VPN » au datagramme reçu."""
        ihl = (p[0] & 0xF) * 4
        sport, dport = struct.unpack("!HH", p[ihl:ihl + 4])
        udp = struct.pack("!HHHH", dport, sport, 8 + len(donnees), 0) + donnees
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                                   p[16:20], p[12:16]))
        ip[10:12] = struct.pack("!H", _somme(bytes(ip)))
        os.write(self.fd, bytes(ip) + udp)

    def fermer(self):
        os.close(self.fd)


class PartageLanDnsTest(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip route add default via 192.168.1.1 dev eth0")
        # Le client, dans son propre espace réseau, branché sur la carte de partage.
        self.client = subprocess.Popen(["unshare", "-n", "sleep", "3600"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.client.wait)
        self.addCleanup(self.client.kill)
        for _ in range(100):
            if os.readlink(f"/proc/{self.client.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.01)
        sh(f"ip link add ens19 type veth peer name eth0 netns {self.client.pid}")
        self.addCleanup(sh, "ip link del ens19", ok=False)
        self.chez_client("ip link set lo up && ip addr add 10.0.0.50/24 dev eth0 && "
                         "ip link set eth0 up && ip route add default via 10.0.0.1")
        # Comme sur le poste du rapport : partage monté avec le tunnel.
        self.d = daemon_de_test(lan_auto=True, lan_iface="ens19", lan_gateway="10.0.0.1",
                                lan_subnet="10.0.0.0/24", lan_dhcp=False)
        monter_tunnel(self.d, ("85.1.1.1",))
        self.tun = Tunnel()
        self.addCleanup(self.tun.fermer)

    def chez_client(self, cmd):
        return sh(f"nsenter -t {self.client.pid} -n sh -c '{cmd}'")

    def question(self, donnees=b"question"):
        """Datagramme du client vers la passerelle, port 53 ; réponse lue en tâche de fond."""
        code = ("import socket,sys\n"
                "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)\n"
                f"s.sendto({donnees!r}, ('10.0.0.1', 53))\n"
                "d,a=s.recvfrom(64); sys.stdout.write(a[0]+' '+d.decode())\n")
        return subprocess.Popen(["nsenter", "-t", str(self.client.pid), "-n", "python3", "-c", code],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def aller_retour(self, dns_attendu):
        client = self.question()
        vu = self.tun.requete_dns()
        self.assertIsNotNone(vu, "la requête du client n'est pas entrée dans le tunnel")
        source, destination, paquet = vu
        self.assertEqual(destination, dns_attendu)
        self.assertEqual(source, "10.8.0.2", "requête non masquée derrière l'adresse du tunnel")
        self.tun.repondre(paquet, b"reponse")
        sortie, _ = client.communicate(timeout=5)
        # La réponse revient au client comme venue de la passerelle.
        self.assertEqual(sortie, "10.0.0.1 reponse")

    def test_dns_redirige_et_suit_la_reconnexion(self):
        self.d._vpn_dns_ips = ["10.111.20.1"]
        self.assertTrue(self.d._setup_lan_sharing())
        self.aller_retour("10.111.20.1")
        # Reconnexion vers un autre serveur IVPN : même interface, autre DNS.
        self.d._vpn_dns_ips = ["10.25.20.1"]
        self.assertTrue(self.d._setup_lan_sharing())
        self.aller_retour("10.25.20.1")
        self.assertEqual(sh("iptables -t nat -S PREROUTING").count("KATAKOMBA_LAN_DNS"), 1)

    def test_tcp(self):
        """DNS sur TCP (réponses longues) : chaque paquet de la connexion,
        pas seulement le premier, doit prendre le tunnel."""
        self.d._vpn_dns_ips = ["10.111.20.1"]
        self.d._setup_lan_sharing()
        code = ("import socket\n"
                "s=socket.socket(); s.settimeout(3)\n"
                "try: s.connect((\"10.0.0.1\", 53))\n"
                "except OSError: pass\n")
        client = subprocess.Popen(["nsenter", "-t", str(self.client.pid), "-n", "python3", "-c", code],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        vus = []
        fin = time.monotonic() + 2.5
        while time.monotonic() < fin and len(vus) < 2:
            if select.select([self.tun.fd], [], [], 0.2)[0]:
                p = os.read(self.tun.fd, 2048)
                if p[0] >> 4 == 4 and p[9] == 6:
                    vus.append(".".join(map(str, p[16:20])))
        client.wait()
        # Le SYN, puis sa retransmission : tous deux dans le tunnel.
        self.assertGreaterEqual(len(vus), 2, vus)
        self.assertEqual(set(vus), {"10.111.20.1"})

    def test_exception_avant_le_marquage(self):
        regles = sh("iptables -t mangle -S KATAKOMBA_RETOUR").splitlines()
        dns = [i for i, r in enumerate(regles) if "-i ens19" in r and "--dport 53 -j RETURN" in r]
        marque = [i for i, r in enumerate(regles) if "CONNMARK" in r]
        self.assertEqual(len(dns), 2, regles)
        self.assertLess(max(dns), min(marque), regles)

    def test_demontage_ne_laisse_rien(self):
        self.d._vpn_dns_ips = ["10.111.20.1"]
        self.d._setup_lan_sharing()
        self.d._teardown_lan_sharing()
        self.assertNotIn("KATAKOMBA_LAN_DNS", sh("iptables -t nat -S"))
