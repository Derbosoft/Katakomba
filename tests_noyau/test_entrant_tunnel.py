"""Rien de neuf n'entre par le tunnel (v4.12.0).  Le fournisseur VPN — ou
tout autre client de son réseau, s'il ne les isole pas — écrit dans le
tunnel : ni la machine ni ce qu'elle route (partage LAN, machines
virtuelles) ne doivent lui répondre.  Un service joignable par l'adresse du
tunnel se laisse reconnaître : l'empreinte d'une clé SSH, comparée aux scans
publics d'Internet, donne l'adresse réelle.  Seules passent les réponses à
ce que la machine a ouvert."""

import os
import select
import struct
import subprocess
import sys
import time

from tests_noyau.noyau import CasNoyau, daemon_de_test, monter_tunnel, sh
from tests_noyau.test_partage_lan import Tunnel, _somme

TUN_IP = "10.8.0.2"            # adresse du tunnel posée par monter_tunnel
FOURNISSEUR = "10.111.20.1"


def datagramme(source, destination, sport, dport, donnees=b"kk") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(donnees), 0) + donnees
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                               bytes(map(int, source.split("."))),
                               bytes(map(int, destination.split(".")))))
    ip[10:12] = struct.pack("!H", _somme(bytes(ip)))
    return bytes(ip) + udp


class EntrantParLeTunnelTest(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip route add default via 192.168.1.1 dev eth0")
        self.d = daemon_de_test()
        monter_tunnel(self.d, ("85.1.1.1",))
        self.tun = Tunnel()
        self.addCleanup(self.tun.fermer)
        # Un service de la machine, à l'écoute sur toutes les adresses.
        code = ("import socket\n"
                "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 5556))\n"
                "while True:\n"
                "    d,a=s.recvfrom(64); s.sendto(d, a)\n")
        self.service = subprocess.Popen([sys.executable, "-c", code],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.service.wait)
        self.addCleanup(self.service.kill)
        time.sleep(0.3)

    def _reponse(self, delai=1.5):
        """Premier datagramme UDP que la machine renvoie dans le tunnel."""
        fin = time.monotonic() + delai
        while time.monotonic() < fin:
            if not select.select([self.tun.fd], [], [], 0.2)[0]:
                continue
            p = os.read(self.tun.fd, 2048)
            if p[0] >> 4 == 4 and p[9] == 17:
                return ".".join(map(str, p[12:16]))
        return None

    def test_service_de_la_machine_injoignable_par_le_tunnel(self):
        self.d._entree_tunnel_on()
        self.addCleanup(self.d._entree_tunnel_off)
        os.write(self.tun.fd, datagramme(FOURNISSEUR, TUN_IP, 40000, 5556))
        self.assertIsNone(self._reponse(), "un service de la machine répond par le tunnel")

    def test_temoin_sans_la_garde(self):
        """Témoin : sans la garde, le service répond — sinon le test
        précédent ne prouverait rien."""
        os.write(self.tun.fd, datagramme(FOURNISSEUR, TUN_IP, 40000, 5556))
        self.assertEqual(self._reponse(), TUN_IP)

    def test_reponses_a_ce_que_la_machine_a_ouvert(self):
        """La machine écrit par le tunnel ; la réponse du serveur revient."""
        self.d._entree_tunnel_on()
        self.addCleanup(self.d._entree_tunnel_off)
        code = ("import socket,sys\n"
                "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                f"s.bind(('{TUN_IP}', 40002)); s.settimeout(3)\n"
                "s.sendto(b'kk', ('203.0.113.9', 7000))\n"
                "try: s.recvfrom(64); sys.exit(0)\n"
                "except OSError: sys.exit(1)\n")
        client = subprocess.Popen([sys.executable, "-c", code],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fin = time.monotonic() + 2
        while time.monotonic() < fin:
            if select.select([self.tun.fd], [], [], 0.2)[0]:
                p = os.read(self.tun.fd, 2048)
                if p[0] >> 4 == 4 and p[9] == 17 and p[16:20] == bytes([203, 0, 113, 9]):
                    break
        else:
            self.fail("le datagramme de la machine n'est pas entré dans le tunnel")
        os.write(self.tun.fd, datagramme("203.0.113.9", TUN_IP, 7000, 40002))
        self.assertEqual(client.wait(5), 0, "la réponse n'est pas revenue")
