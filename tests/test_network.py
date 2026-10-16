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
        self.assertTrue(d.has_log("ne gère que l'IPv4", "WARN"), d.log_dump())

    def test_entree_invalide_rejetee(self):
        args, d = self._args(["pas-une-ip"])
        self.assertEqual(args, [])
        self.assertTrue(d.has_log("Exclusion ignorée", "WARN"))

    def test_exclusion_trop_large_vers_internet_refusee(self):
        """Quatre /2, plus précis que les routes du tunnel, faisaient sortir
        tout Internet hors du tunnel — avec l'adresse réelle."""
        args, d = self._args(["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2",
                              "8.0.0.0/8"])
        self.assertEqual(args, [])
        self.assertTrue(d.has_log("trop large", "WARN"))

    def test_exclusion_publique_etroite_admise(self):
        args, _ = self._args(["203.0.113.0/24"])
        self.assertEqual(args, ["--route", "203.0.113.0", "255.255.255.0", "net_gateway"])

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


class MontageTunnelTest(unittest.TestCase):
    """OpenVPN ne touche plus au réseau : le daemon pose adresse et routes."""

    REGLAGES = {"ifconfig": ("10.8.0.2", "255.255.255.0"), "topology": "subnet",
                "tun_mtu": None, "routes": [], "dns": [], "refus": []}

    def _monter(self, reglages=None, rec=None, **cfg):
        import ipaddress
        d = FakeDaemon(config=cfg, _tun_iface="tun-katakomba",
                       _orig_gw="192.168.1.1", _orig_iface="eth0")
        d.ordre = []
        d._protect_tor_routes = lambda: d.ordre.append("guards")
        d._connected_networks = lambda: [ipaddress.ip_network("192.168.1.0/24")]
        r = rec or Recorder()
        vrai = r.__call__

        def espion(*cmd, **kw):
            d.ordre.append(" ".join(cmd))
            return vrai(*cmd, **kw)
        with patched_run(espion):
            ok = d._monter_tunnel({**self.REGLAGES, **(reglages or {})})
        return d, r, ok

    def test_guards_proteges_avant_toute_route_du_tunnel(self):
        """Sinon Tor joindrait ses relais par le tunnel qui dépend d'eux."""
        d, r, ok = self._monter()
        self.assertTrue(ok)
        self.assertEqual(d.ordre[0], "guards")
        self.assertTrue(r.ran("ip addr add 10.8.0.2/24 dev tun-katakomba"))
        self.assertTrue(r.ran("ip link set dev tun-katakomba up"))
        for moitie in ("0.0.0.0/1", "128.0.0.0/1"):
            # Portée globale : sinon elles passeraient pour des réseaux locaux.
            self.assertTrue(r.ran(f"ip route replace {moitie} dev tun-katakomba scope global"),
                            moitie)

    def test_point_a_point(self):
        _, r, _ = self._monter({"ifconfig": ("10.8.0.6", "10.8.0.5"), "topology": "net30"})
        self.assertTrue(r.ran("ip addr add 10.8.0.6 peer 10.8.0.5 dev tun-katakomba"))

    def test_exclusions_via_la_passerelle_d_origine(self):
        d, r, _ = self._monter(excluded_ips=["203.0.113.0/24"])
        self.assertTrue(r.ran("ip route replace 203.0.113.0/24 via 192.168.1.1 dev eth0"))
        self.assertEqual(d._routes_exclues, ["203.0.113.0/24"])

    def test_route_poussee_vers_le_lan_ignoree(self):
        """Elle détournerait le trafic du réseau local vers le fournisseur VPN."""
        import ipaddress
        d, r, _ = self._monter({"routes": [ipaddress.ip_network("192.168.1.0/24"),
                                           ipaddress.ip_network("10.9.0.0/16")]})
        self.assertFalse(r.ran("192.168.1.0/24 dev tun-katakomba"))
        self.assertTrue(r.ran("ip route replace 10.9.0.0/16 dev tun-katakomba"))
        self.assertTrue(d.has_log("recouvre un réseau local", "WARN"))

    def test_refus_journalises(self):
        d, _, _ = self._monter({"refus": ["route poussée refusée : x via net_gateway"]})
        self.assertTrue(d.has_log("via net_gateway", "WARN"))

    def test_sans_adresse_rien_n_est_monte(self):
        d, r, ok = self._monter({"ifconfig": None})
        self.assertFalse(ok)
        self.assertEqual(r.calls, [])
        self.assertTrue(d.has_log("aucune adresse", "ERROR"))

    def test_echec_de_l_adresse_arrete_le_montage(self):
        d, r, ok = self._monter(rec=Recorder({"addr add": (1, "")}))
        self.assertFalse(ok)
        self.assertFalse(r.ran("0.0.0.0/1"), "routes posées sur un tunnel sans adresse")

    def test_creation_et_suppression_de_l_interface(self):
        d = FakeDaemon(_tun_iface="tun-katakomba")
        r = Recorder()
        with patched_run(r):
            self.assertTrue(d._creer_tun("katakomba-vpn"))
            d._routes_exclues = ["203.0.113.0/24"]
            d._demonter_tunnel()
        self.assertTrue(r.ran("ip tuntap add dev tun-katakomba mode tun user katakomba-vpn "
                              "group katakomba-vpn"))
        self.assertTrue(r.ran("ip route del 203.0.113.0/24"))
        self.assertEqual(r.calls[-1], "ip link del dev tun-katakomba")
        self.assertEqual(d._routes_exclues, [])


class RetourEntrantTest(unittest.TestCase):
    """Réponses aux connexions entrantes (SSH…) par la carte d'origine.

    Le comportement réel (session SSH ouverte avant le tunnel qui survit,
    nouvelle connexion acceptée, trafic émis par la machine toujours dans le
    tunnel, filtrage de chemin inverse strict) a été vérifié sur un noyau,
    avec un vrai OpenVPN, dans un espace réseau isolé ; ces tests en gardent
    la forme et l'ordre."""

    REGLAGES = MontageTunnelTest.REGLAGES

    def setUp(self):
        m_network.SRC_VALID_MARK.write_text("0\n")

    def _monter(self, rec=None, gw="192.168.1.1"):
        import ipaddress
        d = FakeDaemon(_tun_iface="tun-katakomba", _orig_gw=gw,
                       _orig_iface="eth0" if gw else None)
        d._protect_tor_routes = lambda: None
        d._connected_networks = lambda: [ipaddress.ip_network("192.168.1.0/24")]
        r = rec or Recorder()
        with patched_run(r):
            ok = d._monter_tunnel(dict(self.REGLAGES))
        return d, r, ok

    def test_pose_avant_les_routes_du_tunnel(self):
        """Pas une seule réponse d'une session SSH ouverte dans le tunnel."""
        d, r, ok = self._monter()
        self.assertTrue(ok)
        self.assertTrue(d._retour_actif)
        regle = r.calls.index(next(c for c in r.calls if "lookup 19265" in c))
        moitie = r.calls.index("ip route replace 0.0.0.0/1 dev tun-katakomba scope global")
        self.assertLess(regle, moitie)
        self.assertLess(r.calls.index(next(c for c in r.calls if "-I OUTPUT -j KATAKOMBA_RETOUR_OUT" in c)),
                        moitie)

    def test_marquage_des_seules_connexions_entrantes(self):
        _, r, _ = self._monter()
        avant = [c.split(" -A KATAKOMBA_RETOUR ", 1)[1] for c in r.calls
                 if " -A KATAKOMBA_RETOUR " in c]
        sortie = [c.split(" -A KATAKOMBA_RETOUR_OUT ", 1)[1] for c in r.calls
                  if " -A KATAKOMBA_RETOUR_OUT " in c]
        # Reçu de l'extérieur, sens « aller », vers la machine : ouverte par
        # le correspondant.  Venue du tunnel : y répondre, donc exclue.
        self.assertEqual(avant[:2], ["-i lo -j RETURN", "-i tun-katakomba -j RETURN"])
        self.assertIn("--ctdir ORIGINAL -m addrtype --dst-type LOCAL -j CONNMARK", avant[2])
        # Émis dans le sens « retour », sauf vers l'adresse du tunnel.
        self.assertIn("--ctdir REPLY ! --ctorigdst 10.8.0.2 -j CONNMARK", sortie[1])
        for chaine in (avant, sortie):
            self.assertIn("-m connmark --mark 0x1000000/0x1000000 -j MARK", chaine[-1])
        self.assertTrue(r.ran("iptables -t mangle -I PREROUTING -j KATAKOMBA_RETOUR"))

    def test_routage_des_paquets_marques(self):
        _, r, _ = self._monter()
        # Table principale sans ses routes /0 et /1 (défaut, moitiés du
        # tunnel) : réseaux locaux, exclusions et relais Tor restent valables.
        self.assertTrue(r.ran("ip rule add priority 30300 fwmark 0x1000000/0x1000000 "
                              "lookup main suppress_prefixlength 1"))
        self.assertTrue(r.ran("ip rule add priority 30301 fwmark 0x1000000/0x1000000 "
                              "lookup 19265"))
        self.assertTrue(r.ran("ip route replace default via 192.168.1.1 dev eth0 table 19265"))

    def test_filtrage_de_chemin_inverse_strict(self):
        d, _, _ = self._monter()
        self.assertEqual(m_network.SRC_VALID_MARK.read_text().strip(), "1")
        with patched_run(Recorder()):
            d._demonter_tunnel()
        self.assertEqual(m_network.SRC_VALID_MARK.read_text().strip(), "0", "valeur non rendue")

    def test_retire_au_demontage(self):
        d, _, _ = self._monter()
        r = Recorder({" -D ": (1, ""), "rule del": (1, "")})
        with patched_run(r):
            d._demonter_tunnel()
        self.assertFalse(d._retour_actif)
        for attendu in ("iptables -t mangle -D PREROUTING -j KATAKOMBA_RETOUR",
                        "iptables -t mangle -X KATAKOMBA_RETOUR_OUT",
                        "ip rule del priority 30300", "ip rule del priority 30301",
                        "ip route flush table 19265"):
            self.assertTrue(r.ran(attendu), attendu)
        self.assertLess(r.calls.index("ip link del dev tun-katakomba"),
                        r.calls.index("ip route flush table 19265"))

    def test_sans_passerelle_le_tunnel_monte_quand_meme(self):
        """Un poste de travail n'en a pas besoin : erreur visible, pas de panne."""
        d, r, ok = self._monter(gw=None)
        self.assertTrue(ok)
        self.assertFalse(d._retour_actif)
        self.assertTrue(d.has_log("session distante serait coupée", "ERROR"))
        self.assertFalse(r.ran("lookup 19265"))

    def test_echec_tout_ou_rien(self):
        """Module noyau absent (connmark…) : rien ne reste à moitié posé."""
        d, r, ok = self._monter(rec=Recorder({"CONNMARK": (1, "")}))
        self.assertTrue(ok, "le tunnel doit monter malgré tout")
        self.assertFalse(d._retour_actif)
        self.assertTrue(d.has_log("Retour des connexions entrantes impossible", "ERROR"))
        self.assertFalse(r.ran("ip rule add"))
        self.assertTrue(r.ran("iptables -t mangle -X KATAKOMBA_RETOUR"))
        self.assertEqual(m_network.SRC_VALID_MARK.read_text().strip(), "0")

    def test_reconnexion_sans_doublon(self):
        """Chaque montage repart d'un état propre (adresse du tunnel changée)."""
        d, _, _ = self._monter()
        r = Recorder()
        with patched_run(r):
            d._monter_tunnel(dict(self.REGLAGES, ifconfig=("10.8.0.7", "255.255.255.0")))
        nettoyage = r.calls.index("ip rule del priority 30300")
        self.assertLess(nettoyage, r.calls.index(next(c for c in r.calls if "ip rule add" in c)))
        self.assertTrue(r.ran("! --ctorigdst 10.8.0.7"))

    def test_nettoye_au_demarrage_du_service(self):
        d = FakeDaemon()
        r = Recorder({" -D ": (1, ""), "rule del": (1, "")})
        with patched_run(r):
            d.cleanup_stale_rules()
        self.assertTrue(r.ran("iptables -t mangle -X KATAKOMBA_RETOUR"))
        self.assertTrue(r.ran("ip route flush table 19265"))

    def test_expose_au_statut(self):
        d, _, _ = self._monter()
        self.assertTrue(d._status_snapshot()["incoming_return"])


if __name__ == "__main__":
    unittest.main()
