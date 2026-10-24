"""Blocage hors tunnel et blocage IPv6, sur de vraies connexions : ce qui doit
être refusé l'est, ce qui doit passer passe."""

import socket
import subprocess
import sys

import daemon.firewall as m_firewall

from tests_noyau.noyau import (CasNoyau, Ecoute, daemon_de_test, joindre, root_reel,
                               sans_passe_droit_hors_root, sh, udp)

INTERNET = "203.0.113.10"
EXCLU = "198.51.100.7"           # dans une exclusion configurée
INTERNET6 = "2001:db8:ffff::10"


class BlocageTest(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip route add default via 192.168.1.1 dev eth0")
        for a in (INTERNET, EXCLU):
            self.pair.internet(a)
        self.pair.serveur(80)
        self.pair.serveur_udp(53)
        self.pair.serveur_udp(5353)
        # Tor tourne sous son propre utilisateur ; ici, nobody.
        self.addCleanup(setattr, m_firewall, "TOR_USER", m_firewall.TOR_USER)
        m_firewall.TOR_USER = "nobody"
        self.d = daemon_de_test(excluded_ips=["198.51.100.0/24"])
        sans_passe_droit_hors_root(self.d)
        self.addCleanup(self.d._kill_switch_off, True)

    def test_sans_blocage_tout_sort(self):
        self.assertEqual(joindre(INTERNET, 80), "ok")
        self.assertEqual(udp("192.168.1.1", 53), "ok")

    def test_internet_refuse_aussitot(self):
        self.assertTrue(self.d._kill_switch_on())
        self.assertEqual(joindre(INTERNET, 80), "refus", "pas de reset : l'application attend")

    def test_ce_qui_passe(self):
        self.assertTrue(self.d._kill_switch_on())
        self.assertEqual(joindre("192.168.1.1", 80), "ok", "réseau local coupé")
        self.assertEqual(joindre(EXCLU, 80), "ok", "exclusion coupée")
        self.assertEqual(udp("192.168.1.1", 5353), "ok", "UDP local coupé")

    def test_dns_local_refuse(self):
        """Sinon les requêtes iraient au routeur, donc au fournisseur d'accès."""
        self.assertTrue(self.d._kill_switch_on())
        self.assertEqual(udp("192.168.1.1", 53), "refus")

    def test_le_tunnel_passe(self):
        sh("ip tuntap add dev tun-katakomba mode tun && ip link set tun-katakomba up")
        sh(f"ip route add {INTERNET}/32 dev tun-katakomba")
        self.assertTrue(self.d._kill_switch_on())
        # Personne ne lit le tunnel : la connexion y part et s'y perd, sans refus.
        self.assertEqual(joindre(INTERNET, 80, delai=1), "muet")

    def test_connexion_sortante_deja_ouverte_coupee(self):
        """« ESTABLISHED » seul laisserait continuer une connexion ouverte à
        découvert : seul le sens réponse des connexions entrantes passe."""
        s = socket.create_connection((INTERNET, 80), timeout=2)
        self.addCleanup(s.close)
        self.assertTrue(self.d._kill_switch_on())
        with self.assertRaises(OSError):
            s.sendall(b"kk")
            if s.recv(8) != b"kk":
                raise OSError("rien reçu")

    def test_reponses_aux_connexions_entrantes(self):
        ecoute = Ecoute(2222)
        self.addCleanup(ecoute.fermer)
        self.assertTrue(self.d._kill_switch_on())
        self.assertTrue(self.pair.joindre("192.168.1.20", 2222, source=INTERNET))

    def test_tor_passe_seul(self):
        if not root_reel():
            self.skipTest("prendre l'identité de nobody exige le vrai root")
        self.assertTrue(self.d._kill_switch_on())
        code = (f"import socket; s=socket.create_connection(('{INTERNET}', 80), timeout=2); "
                "s.sendall(b'kk'); assert s.recv(8) == b'kk'")
        r = subprocess.run(["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups",
                            sys.executable, "-c", code], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual(joindre(INTERNET, 80), "refus")

    def test_retrait_complet(self):
        self.assertTrue(self.d._kill_switch_on())
        self.d._kill_switch_off()
        self.assertEqual(joindre(INTERNET, 80), "ok")
        for t in ("iptables", "ip6tables"):
            self.assertNotIn("KATAKOMBA", sh(f"{t} -S"), t)


class Ipv6Test(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip -6 addr add 2001:db8:1::20/64 dev eth0 nodad")
        self.pair.run("ip -6 addr add 2001:db8:1::1/64 dev eth0 nodad && "
                      f"ip -6 addr add {INTERNET6}/128 dev lo")
        sh("ip -6 route add default via 2001:db8:1::1 dev eth0")
        self.pair.serveur(80)
        self.addCleanup(setattr, m_firewall, "TOR_USER", m_firewall.TOR_USER)
        m_firewall.TOR_USER = "nobody"
        self.d = daemon_de_test()
        sans_passe_droit_hors_root(self.d)
        self.addCleanup(self.d._ipv6_block_off)
        self.addCleanup(self.d._kill_switch_off, True)

    def test_sans_blocage(self):
        self.assertEqual(joindre(INTERNET6, 80), "ok")

    def test_blocage_ipv6(self):
        self.d._ipv6_block_on()
        self.assertTrue(self.d._ipv6_blocked)
        self.assertEqual(joindre(INTERNET6, 80, delai=1), "muet")
        self.d._ipv6_block_off()
        self.assertEqual(joindre(INTERNET6, 80), "ok")

    def test_blocage_hors_tunnel_en_ipv6(self):
        self.assertTrue(self.d._kill_switch_on())
        self.assertEqual(joindre(INTERNET6, 80), "refus")
