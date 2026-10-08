"""Réseau : passerelle, réseaux connectés, routes exclues, protection des guards."""

import unittest

from tests.helpers import FakeDaemon, Recorder, patched_run, provider  # noqa: F401
import daemon.network as m_network


SCOPE_LINK = (
    "192.168.50.0/24 dev eth0 proto kernel scope link src 192.168.50.20 metric 100\n"
    "10.20.20.0/22 dev tun0 proto kernel scope link src 10.20.20.19\n"
)


class GatewayTest(unittest.TestCase):
    """_get_default_gateway : c'est le déclencheur du correctif #6."""

    def _gw(self, route_output):
        d = FakeDaemon()
        with patched_run(Recorder({"route show default": (0, route_output)})):
            return d._get_default_gateway()

    def test_route_normale(self):
        self.assertEqual(
            self._gw("default via 192.168.50.1 dev eth0 proto dhcp src 192.168.50.20 metric 100"),
            ("192.168.50.1", "eth0"))

    def test_point_a_point_sans_via(self):
        """« default dev ppp0 » : pas de passerelle -> protection /32 impossible."""
        self.assertEqual(self._gw("default dev ppp0 scope link"), (None, None))

    def test_aucune_route(self):
        self.assertEqual(self._gw(""), (None, None))

    def test_ligne_tronquee(self):
        """Moins de 5 champs : ne doit pas lever d'exception."""
        self.assertEqual(self._gw("default via"), (None, None))

    def test_plusieurs_routes_prend_la_premiere(self):
        out = ("default via 10.0.0.1 dev eth0 metric 100\n"
               "default via 10.0.0.2 dev eth1 metric 200\n")
        self.assertEqual(self._gw(out), ("10.0.0.1", "eth0"))


class ConnectedNetworksTest(unittest.TestCase):

    def test_parse_scope_link(self):
        d = FakeDaemon()
        with patched_run(Recorder({"scope link": (0, SCOPE_LINK)})):
            nets = [str(n) for n in d._connected_networks()]
        self.assertEqual(nets, ["192.168.50.0/24", "10.20.20.0/22"])

    def test_lignes_invalides_ignorees(self):
        bad = "pas-un-reseau dev x\n999.1.1.0/24 dev y\n10.1.0.0/16 dev z scope link\n"
        d = FakeDaemon()
        with patched_run(Recorder({"scope link": (0, bad)})):
            nets = [str(n) for n in d._connected_networks()]
        self.assertEqual(nets, ["10.1.0.0/16"])


class BuildRouteArgsTest(unittest.TestCase):
    """Correctif #1 (IPv6) et correctif du piège scope-link."""

    def _args(self, excluded, scope_link=SCOPE_LINK):
        d = FakeDaemon(config={"excluded_ips": excluded})
        with patched_run(Recorder({"scope link": (0, scope_link)})):
            return d._build_route_args(), d

    def test_reseau_route_via_routeur(self):
        args, _ = self._args(["10.0.20.0/24"])
        self.assertEqual(args, ["--route", "10.0.20.0", "255.255.255.0", "net_gateway"])

    def test_ip_seule_devient_slash_32(self):
        args, _ = self._args(["192.168.1.7"])
        self.assertEqual(args, ["--route", "192.168.1.7", "255.255.255.255", "net_gateway"])

    def test_ipv6_rejete(self):
        """#1 : --route est IPv4 ; une entrée v6 doit être écartée AVEC un avertissement."""
        args, d = self._args(["2001:db8::/32"])
        self.assertEqual(args, [], "une option --route IPv6 a été générée")
        self.assertTrue(d.has_log("IPv6 non supporté", "WARN"), d.log_dump())

    def test_entree_invalide_rejetee(self):
        args, d = self._args(["pas-une-ip"])
        self.assertEqual(args, [])
        self.assertTrue(d.has_log("Route ignorée (invalide)", "WARN"))

    def test_reseau_directement_connecte_ignore(self):
        """Le piège scope-link : exclure son propre LAN casse le routage local."""
        args, d = self._args(["192.168.50.0/24"])
        self.assertEqual(args, [], "le réseau local a été routé via net_gateway")
        self.assertTrue(d.has_log("directement connecté"))

    def test_sous_reseau_d_un_reseau_connecte_ignore(self):
        args, _ = self._args(["192.168.50.128/25"])
        self.assertEqual(args, [])

    def test_surensemble_d_un_reseau_connecte_conserve(self):
        """10.0.0.0/8 n'est PAS un sous-réseau de 192.168.50.0/24 : à conserver."""
        args, _ = self._args(["10.0.0.0/8"])
        self.assertEqual(args, ["--route", "10.0.0.0", "255.0.0.0", "net_gateway"])

    def test_melange_conserve_l_ordre_et_filtre(self):
        args, _ = self._args(["10.0.20.0/24", "2001:db8::/32", "192.168.50.0/24",
                              "bidon", "10.0.10.0/24"])
        self.assertEqual(args, ["--route", "10.0.20.0", "255.255.255.0", "net_gateway",
                                "--route", "10.0.10.0", "255.255.255.0", "net_gateway"])

    def test_aucune_exclusion(self):
        self.assertEqual(self._args([])[0], [])


class ProtectedRoutesTest(unittest.TestCase):

    def _daemon(self, tmp):
        d = FakeDaemon()
        d._orig_gw, d._orig_iface = "192.168.50.1", "eth0"
        m_network.TOR_ROUTES_FILE = tmp
        return d

    def setUp(self):
        import tempfile
        self._tmpdir = tempfile.TemporaryDirectory()
        self.routes_file = __import__("pathlib").Path(self._tmpdir.name) / "routes.txt"
        self._saved = m_network.TOR_ROUTES_FILE

    def tearDown(self):
        m_network.TOR_ROUTES_FILE = self._saved
        self._tmpdir.cleanup()

    def test_ajoute_et_persiste(self):
        d = self._daemon(self.routes_file)
        r = Recorder()
        with patched_run(r):
            d._add_protected_routes({"1.2.3.4", "5.6.7.8"}, "test")
        self.assertEqual(r.count("route replace", "1.2.3.4/32", "via 192.168.50.1"), 1)
        self.assertEqual(r.count("route replace", "5.6.7.8/32"), 1)
        self.assertEqual(d._protected_routes, {"1.2.3.4", "5.6.7.8"})
        self.assertEqual(set(self.routes_file.read_text().split()), {"1.2.3.4", "5.6.7.8"})

    def test_ne_reajoute_pas_une_ip_connue(self):
        d = self._daemon(self.routes_file)
        with patched_run(Recorder()):
            d._add_protected_routes({"1.2.3.4"}, "a")
        r = Recorder()
        with patched_run(r):
            d._add_protected_routes({"1.2.3.4"}, "b")
        self.assertEqual(r.count("route replace"), 0, "route ajoutée deux fois")

    def test_filtre_loopback_nul_et_ipv6(self):
        d = self._daemon(self.routes_file)
        r = Recorder()
        with patched_run(r):
            d._add_protected_routes(
                {"127.0.0.1", "0.0.0.0", "2001:db8::1", "pas-une-ip", "8.8.8.8"}, "t")
        self.assertEqual(r.count("route replace"), 1, r.dump())
        self.assertEqual(d._protected_routes, {"8.8.8.8"})

    def test_protect_sans_passerelle_ne_fait_rien(self):
        """#6 : sans passerelle, aucune route n'est posée (d'où l'alerte ajoutée)."""
        d = FakeDaemon()
        d._orig_gw, d.tor_process = None, object()
        r = Recorder()
        with patched_run(r):
            d._protect_tor_routes()
        self.assertEqual(r.calls, [])

    def test_protect_utilise_le_controlport_en_priorite(self):
        d = self._daemon(self.routes_file)
        d.tor_process = type("P", (), {"pid": 99})()
        d._tor_relay_ips = lambda: {"77.1.1.1"}
        r = Recorder()
        with patched_run(r):
            d._protect_tor_routes()
        self.assertTrue(r.ran("route replace", "77.1.1.1/32"))
        self.assertEqual(r.count("ss -tnp"), 0, "repli ss utilisé alors que ControlPort a répondu")
        self.assertTrue(d.has_log("via ControlPort"))

    def test_protect_repli_sur_ss(self):
        d = self._daemon(self.routes_file)
        d.tor_process = type("P", (), {"pid": 99})()
        d._tor_relay_ips = lambda: set()
        # Format RÉEL de « ss -tnp state established » : le filtre par état
        # supprime la colonne State, il ne reste que 4 champs et le pair est
        # en index 3 (vérifié sur la machine, cf. commentaire de _protect_tor_routes).
        ss = ("Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
              "0 0 192.168.50.20:41234 88.1.1.1:9001 users:((\"tor\",pid=99,fd=9))\n"
              "0 0 192.168.50.20:41235 [2001:db8::5]:443 users:((\"tor\",pid=99,fd=10))\n"
              "0 0 192.168.50.20:41236 99.9.9.9:443 users:((\"autre\",pid=7,fd=3))\n")
        r = Recorder({"ss -tnp": (0, ss)})
        with patched_run(r):
            d._protect_tor_routes()
        self.assertTrue(r.ran("route replace", "88.1.1.1/32"))
        self.assertFalse(r.ran("route replace", "99.9.9.9"), "socket d'un autre process pris")
        self.assertFalse(any("2001" in c for c in r.calls), "pair IPv6 pris en compte")

    def test_cleanup_supprime_courantes_et_persistees(self):
        d = self._daemon(self.routes_file)
        self.routes_file.write_text("11.11.11.11\n22.22.22.22\n")
        d._protected_routes = {"33.33.33.33"}
        r = Recorder()
        with patched_run(r):
            d._cleanup_tor_routes()
        for ip in ("11.11.11.11", "22.22.22.22", "33.33.33.33"):
            self.assertTrue(r.ran("route del", f"{ip}/32"), f"{ip} non supprimée")
        self.assertFalse(self.routes_file.exists())
        self.assertEqual(d._protected_routes, set())


if __name__ == "__main__":
    unittest.main()
