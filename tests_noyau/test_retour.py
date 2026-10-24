"""Retour des connexions entrantes (v3.10.0) : une session SSH sur un serveur
survit au tunnel, et ce que la machine émet reste dans le tunnel."""

import subprocess
import sys
import time

import daemon.network as m_network

from tests_noyau.noyau import CasNoyau, Ecoute, daemon_de_test, joindre, monter_tunnel, sh, via

CLIENT = "203.0.113.10"      # l'administrateur, quelque part sur Internet


class RetourTest(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip route add default via 192.168.1.1 dev eth0")
        self.pair.internet(CLIENT)
        self.ecoute = Ecoute(2222)
        self.addCleanup(self.ecoute.fermer)
        self.d = daemon_de_test()

    def test_avant_le_tunnel(self):
        self.assertTrue(self.pair.joindre("192.168.1.20", 2222, source=CLIENT))

    def test_connexion_entrante_avec_le_tunnel(self):
        monter_tunnel(self.d)
        self.assertTrue(self.d._retour_actif)
        self.assertTrue(self.pair.joindre("192.168.1.20", 2222, source=CLIENT))

    def test_sans_le_retour_la_session_tombe(self):
        """Témoin : c'est bien le retour qui fait passer la réponse."""
        monter_tunnel(self.d)
        self.d._retour_entrant_off(force=True)
        self.assertFalse(self.pair.joindre("192.168.1.20", 2222, source=CLIENT, delai=1))

    def test_le_trafic_emis_reste_dans_le_tunnel(self):
        monter_tunnel(self.d)
        self.pair.serveur(8080)
        self.assertEqual(via(CLIENT), "tun-katakomba")
        self.assertEqual(joindre(CLIENT, 8080, delai=1), "muet")

    def test_session_ouverte_avant_le_tunnel(self):
        """La réponse suivante d'une session déjà ouverte part elle aussi par
        la carte réseau, sans attendre un paquet du client."""
        code = ("import socket,sys\n"
                f"s=socket.socket(); s.bind(('{CLIENT}', 0)); s.settimeout(5)\n"
                "s.connect(('192.168.1.20', 2222)); print('ouvert', flush=True)\n"
                "sys.stdin.readline(); s.sendall(b'kk')\n"
                "sys.exit(0 if s.recv(8) == b'kk' else 1)\n")
        client = subprocess.Popen(["nsenter", "-t", str(self.pair.pid), "-n",
                                   sys.executable, "-c", code],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.assertEqual(client.stdout.readline().strip(), "ouvert")
        monter_tunnel(self.d)
        client.stdin.write("\n")
        client.stdin.flush()
        self.assertEqual(client.wait(10), 0)

    def test_filtrage_de_chemin_inverse_strict(self):
        """rp_filter=1 : sans src_valid_mark, le noyau jetterait les paquets
        du client, que la table principale renvoie vers le tunnel."""
        try:
            for i in ("all", "eth0"):
                with open(f"/proc/sys/net/ipv4/conf/{i}/rp_filter", "w") as f:
                    f.write("1\n")
        except OSError as e:
            self.skipTest(f"rp_filter non modifiable ici ({e})")
        monter_tunnel(self.d)
        self.assertEqual(m_network.SRC_VALID_MARK.read_text().strip(), "1")
        self.assertTrue(self.pair.joindre("192.168.1.20", 2222, source=CLIENT))
        m_network.SRC_VALID_MARK.write_text("0\n")
        time.sleep(0.1)
        self.assertFalse(self.pair.joindre("192.168.1.20", 2222, source=CLIENT, delai=1),
                         "le témoin passe : le test ne prouve rien")
