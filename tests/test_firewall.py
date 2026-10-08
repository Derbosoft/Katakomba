"""Pare-feu : blocage IPv6, partage LAN, plage DHCP de dnsmasq."""

import ipaddress
import pathlib
import unittest

import daemon.firewall as m_firewall
from tests.helpers import FakeDaemon, FakeProc, Recorder, patched_run


LAN_CFG = {"lan_iface": "ens19", "lan_gateway": "10.0.0.1",
           "lan_subnet": "10.0.0.0/24", "lan_dhcp": False}


def lan_rec(**extra):
    """Enregistreur réaliste : « iptables -C » renvoie 1 quand la règle est
    absente (sinon le code saute à raison le -A qui suit)."""
    return Recorder({"-t nat -C": (1, ""), **extra})


class Ipv6BlockTest(unittest.TestCase):

    def test_chaines_creees_et_branchees(self):
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        self.assertTrue(d._ipv6_blocked)
        self.assertTrue(r.ran("ip6tables -N KATAKOMBA_KS6"))
        self.assertTrue(r.ran("ip6tables -I OUTPUT -j KATAKOMBA_KS6"))
        self.assertTrue(r.ran("ip6tables -I FORWARD -j KATAKOMBA_KS6_FWD"))
        # Le tunnel et lo doivent être exemptés AVANT le DROP final.
        self.assertTrue(r.ran("-A KATAKOMBA_KS6 -o tun0 -j RETURN"))
        self.assertTrue(r.ran("-A KATAKOMBA_KS6 -j DROP"))

    def test_ordre_return_avant_drop(self):
        """Un DROP placé avant les RETURN couperait tout l'IPv6 local."""
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        chain = [c for c in r.calls if "-A KATAKOMBA_KS6 " in c]
        self.assertEqual(chain[-1], "ip6tables -A KATAKOMBA_KS6 -j DROP",
                         f"le DROP n'est pas la dernière règle : {chain}")

    def test_idempotent(self):
        d = FakeDaemon(_tun_iface="tun0")
        with patched_run(Recorder()):
            d._ipv6_block_on()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        self.assertEqual(r.calls, [], "règles réinstallées une seconde fois")

    def test_echec_output_annule_l_activation(self):
        d = FakeDaemon(_tun_iface="tun0")
        with patched_run(Recorder({"-I OUTPUT": (1, "")})):
            d._ipv6_block_on()
        self.assertFalse(d._ipv6_blocked)
        self.assertTrue(d.has_log("ip6tables OUTPUT", "ERROR"))

    def test_off_supprime_et_reinitialise(self):
        d = FakeDaemon(_tun_iface="tun0")
        with patched_run(Recorder()):
            d._ipv6_block_on()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_off()
        self.assertFalse(d._ipv6_blocked)
        self.assertTrue(r.ran("-D OUTPUT -j KATAKOMBA_KS6"))
        self.assertTrue(r.ran("-X KATAKOMBA_KS6"))
        self.assertTrue(r.ran("-D FORWARD -j KATAKOMBA_KS6_FWD"))
        self.assertTrue(r.ran("-X KATAKOMBA_KS6_FWD"))

    def test_off_sans_activation_ne_fait_rien(self):
        d = FakeDaemon()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_off()
        self.assertEqual(r.calls, [])


class LanSharingTest(unittest.TestCase):
    """Correctif #5 : les règles suivent le nom de l'interface tunnel."""

    def _daemon(self, **cfg):
        d = FakeDaemon(config={**LAN_CFG, **cfg}, _tun_iface="tun0")
        d._get_default_gateway = lambda: ("192.168.50.1", "eth0")
        return d

    def test_activation_pose_les_regles(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertTrue(d._lan_active)
        self.assertEqual(d._lan_tun, "tun0")
        self.assertTrue(r.ran("ip addr add 10.0.0.1/24 dev ens19"))
        self.assertTrue(r.ran("sysctl -w net.ipv4.ip_forward=1"))
        self.assertTrue(r.ran("-t nat -A POSTROUTING", "-s 10.0.0.0/24 -o tun0 -j MASQUERADE"))
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun0 -j RETURN"))
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -j DROP"))

    def test_drop_en_dernier(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            d._setup_lan_sharing()
        chain = [c for c in r.calls if "-A KATAKOMBA_LAN_FWD" in c]
        self.assertTrue(chain[-1].endswith("-i ens19 -j DROP"),
                        f"le DROP n'est pas en dernier : {chain}")

    def test_refuse_l_interface_uplink(self):
        """Flusher l'uplink couperait tout le réseau : refus catégorique."""
        d = self._daemon(lan_iface="eth0")          # = interface de la route par défaut
        r = lan_rec()
        with patched_run(r):
            self.assertFalse(d._setup_lan_sharing())
        self.assertFalse(d._lan_active)
        self.assertEqual(r.calls, [], "des commandes ont été exécutées malgré le refus")
        self.assertTrue(d.has_log("porte la route par défaut", "ERROR"))

    def test_refuse_sans_interface(self):
        d = self._daemon(lan_iface="")
        with patched_run(lan_rec()):
            self.assertFalse(d._setup_lan_sharing())
        self.assertTrue(d.has_log("aucune interface configurée", "ERROR"))

    def test_refuse_sous_reseau_invalide(self):
        d = self._daemon(lan_subnet="pas-un-reseau")
        with patched_run(lan_rec()):
            self.assertFalse(d._setup_lan_sharing())
        self.assertTrue(d.has_log("sous-réseau invalide", "ERROR"))

    def test_echec_ip_addr_add(self):
        d = self._daemon()
        with patched_run(lan_rec(**{"addr add": (1, "")})):
            self.assertFalse(d._setup_lan_sharing())
        self.assertFalse(d._lan_active)

    def test_rappel_sans_changement_ne_refait_rien(self):
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertEqual(r.calls, [], "règles reconstruites sans raison")
        self.assertEqual(d.logs[-1][1], "Partage LAN actif : ens19 (10.0.0.1/24) → tun0.")

    def test_changement_de_tunnel_reconstruit(self):
        """Le cœur de #5 : tun0 -> tun1 doit réécrire NAT et FORWARD."""
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        d._tun_iface = "tun1"
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertEqual(d._lan_tun, "tun1")
        self.assertTrue(r.ran("-t nat -D POSTROUTING", "-o tun0 -j MASQUERADE"),
                        "ancienne règle NAT tun0 non supprimée")
        self.assertTrue(r.ran("-t nat -A POSTROUTING", "-o tun1 -j MASQUERADE"),
                        "nouvelle règle NAT tun1 absente")
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun1 -j RETURN"))
        self.assertFalse(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun0"),
                         "RETURN encore posé sur l'ancienne interface")
        self.assertTrue(d.has_log("interface tunnel changée", "WARN"))

    def test_teardown_cible_l_interface_creee(self):
        """La règle NAT doit être retirée avec _lan_tun, pas avec _tun_iface."""
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        d._tun_iface = "tun9"                      # le tunnel a encore bougé
        r = lan_rec()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertTrue(r.ran("-t nat -D POSTROUTING", "-o tun0 -j MASQUERADE"),
                        f"mauvaise interface visée : {r.dump()}")
        self.assertFalse(r.ran("-o tun9"))
        self.assertFalse(d._lan_active)
        self.assertEqual(d._lan_tun, "")

    def test_teardown_sans_activation_ne_fait_rien(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertEqual(r.calls, [])

    def test_masquerade_non_dupliquee(self):
        """-C avant -A : si la règle existe déjà, ne pas l'empiler."""
        d = self._daemon()
        r = Recorder({"-t nat -C": (0, "")})   # règle déjà présente
        with patched_run(r):
            d._setup_lan_sharing()
        self.assertEqual(r.count("-t nat -A POSTROUTING"), 0,
                         "règle NAT ajoutée alors qu'elle existait")


class DnsmasqRangeTest(unittest.TestCase):
    """Bornes DHCP de dnsmasq.

    On exerce la VRAIE méthode et on inspecte la ligne de commande construite :
    le thread est exécuté de façon synchrone et Popen est capturé.  Recalculer
    les bornes dans le test ne testerait que le test.
    """

    def _dnsmasq_cmd(self, subnet, gw="10.0.0.1", dhcp=True):
        import tempfile
        d = FakeDaemon(config={**LAN_CFG, "lan_dhcp": dhcp})
        captured = {}

        class SyncThread:
            def __init__(self, target=None, daemon=None):
                self._target = target

            def start(self):
                self._target()

        def fake_popen(cmd, **kw):
            captured["cmd"] = list(cmd)
            return FakeProc()

        saved = (m_firewall.shutil.which, m_firewall.threading.Thread,
                 m_firewall.subprocess.Popen, m_firewall.LAN_DNSMASQ_PID)
        m_firewall.shutil.which = lambda n: "/usr/sbin/dnsmasq"
        m_firewall.threading.Thread = SyncThread
        m_firewall.subprocess.Popen = fake_popen
        with tempfile.TemporaryDirectory() as tmp:
            # Jamais le vrai /etc/katakomba : la méthode fait unlink().
            m_firewall.LAN_DNSMASQ_PID = pathlib.Path(tmp) / "dnsmasq.pid"
            try:
                d._start_lan_dnsmasq("ens19", gw,
                                     ipaddress.ip_network(subnet, strict=False))
            finally:
                (m_firewall.shutil.which, m_firewall.threading.Thread,
                 m_firewall.subprocess.Popen, m_firewall.LAN_DNSMASQ_PID) = saved
        return d, captured.get("cmd")

    def _plage(self, subnet):
        _, cmd = self._dnsmasq_cmd(subnet)
        if cmd is None:
            return None
        for a in cmd:
            if a.startswith("--dhcp-range="):
                debut, fin, _bail = a.split("=", 1)[1].split(",")
                return (debut, fin)
        return None

    def test_pas_de_serveur_dns(self):
        """Les clients reçoivent 1.1.1.1 ; dnsmasq n'a aucun amont à servir."""
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24")
        self.assertIn("--port=0", cmd)

    def test_slash_24_plage_centrale(self):
        self.assertEqual(self._plage("10.0.0.0/24"), ("10.0.0.100", "10.0.0.200"))

    def test_slash_28_plage_reduite(self):
        self.assertEqual(self._plage("10.0.0.0/28"), ("10.0.0.4", "10.0.0.11"))

    def test_slash_30_deux_hotes(self):
        self.assertEqual(self._plage("10.0.0.0/30"), ("10.0.0.1", "10.0.0.2"))

    def test_slash_31_trop_petit_pas_de_dnsmasq(self):
        d, cmd = self._dnsmasq_cmd("10.0.0.0/31")
        self.assertIsNone(cmd, "dnsmasq lancé sur un sous-réseau sans hôte")
        self.assertTrue(d.has_log("trop petit pour le DHCP", "WARN"))

    def test_slash_8_instantane_sans_explosion_memoire(self):
        """Un /8 = 16 M d'adresses : le calcul doit rester arithmétique."""
        import time
        t0 = time.monotonic()
        plage = self._plage("10.0.0.0/8")
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertEqual(plage, ("10.0.0.100", "10.0.0.200"))

    def test_plage_dans_le_sous_reseau(self):
        for subnet in ("10.0.0.0/24", "192.168.5.0/26", "172.16.0.0/20"):
            debut, fin = self._plage(subnet)
            net = ipaddress.ip_network(subnet)
            self.assertIn(ipaddress.ip_address(debut), net, subnet)
            self.assertIn(ipaddress.ip_address(fin), net, subnet)
            self.assertLessEqual(ipaddress.ip_address(debut),
                                 ipaddress.ip_address(fin), subnet)

    def test_options_dhcp_essentielles(self):
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24", gw="10.0.0.1")
        joined = " ".join(cmd)
        self.assertIn("--interface=ens19", joined)
        self.assertIn("--bind-interfaces", joined)
        self.assertIn("--dhcp-option=3,10.0.0.1", joined)   # passerelle
        self.assertIn("--no-resolv", joined)
        self.assertIn("--pid-file=", joined)

    def test_dnsmasq_absent_avertit(self):
        d = FakeDaemon(config={**LAN_CFG, "lan_dhcp": True})
        saved = m_firewall.shutil.which
        m_firewall.shutil.which = lambda n: None
        try:
            d._start_lan_dnsmasq("ens19", "10.0.0.1",
                                 ipaddress.ip_network("10.0.0.0/24"))
        finally:
            m_firewall.shutil.which = saved
        self.assertTrue(d.has_log("dnsmasq non installé", "WARN"))


if __name__ == "__main__":
    unittest.main()
