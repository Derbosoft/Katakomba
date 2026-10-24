"""Ce que systemd-networkd efface à son redémarrage, et que le daemon repose
(v3.12.1) : rejoué sur un vrai noyau."""

import daemon.firewall as m_firewall

from tests_noyau.noyau import CasNoyau, daemon_de_test, monter_tunnel, sh, via

RELAIS = ("85.1.1.1", "85.2.2.2", "85.3.3.3", "85.4.4.4", "85.5.5.5")


class NetworkdTest(CasNoyau):

    def setUp(self):
        super().setUp()
        sh("ip route add default via 192.168.1.1 dev eth0")
        sh("ip link add ens19 type dummy && ip link set ens19 up")
        self.addCleanup(sh, "ip link del ens19", ok=False)
        self._admissible = m_firewall.interface_lan_admissible
        m_firewall.interface_lan_admissible = lambda nom: True     # carte factice
        self.addCleanup(setattr, m_firewall, "interface_lan_admissible", self._admissible)
        self.d = daemon_de_test(lan_iface="ens19", lan_gateway="10.0.0.1",
                                lan_subnet="10.0.0.0/24", lan_dhcp=False,
                                excluded_ips=["10.20.0.0/16"])
        monter_tunnel(self.d, RELAIS)
        self.assertTrue(self.d._setup_lan_sharing())

    def etat(self):
        return {"relais": all(via(ip) == "eth0" for ip in RELAIS),
                "exclusion": via("10.20.1.1") == "eth0",
                "internet": via("1.1.1.1") == "tun-katakomba",
                "retour": self.d._retour_en_place(),
                "lan": "10.0.0.1/24" in sh("ip -4 -o addr show dev ens19").split()}

    def test_etat_initial_et_entretien_sans_objet(self):
        self.assertTrue(all(self.etat().values()), self.etat())
        self.assertFalse(self.d._entretien_routage())

    def test_redemarrage_de_networkd(self):
        for ip in ("85.1.1.1", "85.3.3.3", "85.5.5.5"):
            sh(f"ip route del {ip}/32")
        sh("ip route del 10.20.0.0/16")
        sh("ip rule del priority 30300; ip rule del priority 30301; ip route flush table 19265")
        sh("ip addr flush dev ens19")
        # L'incident du 23/10 : les relais d'entrée partent dans le tunnel.
        self.assertEqual(via("85.1.1.1"), "tun-katakomba")
        self.assertFalse(any(v for k, v in self.etat().items() if k != "internet"))

        self.assertTrue(self.d._entretien_routage())
        self.assertTrue(all(self.etat().values()), self.etat())
        self.assertTrue(self.d.has_log("3 route(s) /32 Tor effacée(s)", "WARN"))
        # Reposé une fois, pas empilé.
        self.assertEqual(sh("ip -4 rule show").count("30301:"), 1)
        self.assertEqual(sh("iptables -t mangle -S PREROUTING").count("KATAKOMBA_RETOUR"), 1)
        self.d.logs.clear()
        self.assertFalse(self.d._entretien_routage())
        self.assertEqual(self.d.logs, [])

    def test_moities_d_internet_retirees(self):
        sh("ip route del 0.0.0.0/1; ip route del 128.0.0.0/1")
        self.assertEqual(via("1.1.1.1"), "eth0")
        self.d._entretien_routage()
        self.assertEqual(via("1.1.1.1"), "tun-katakomba")
        self.assertTrue(all(via(ip) == "eth0" for ip in RELAIS))

    def test_demontage_complet(self):
        self.d._teardown_lan_sharing()
        self.d._demonter_tunnel()
        self.assertNotIn("30301:", sh("ip -4 rule show"))
        self.assertEqual(sh("ip -4 route show table 19265"), "")
        self.assertNotIn("KATAKOMBA_RETOUR", sh("iptables -t mangle -S"))
