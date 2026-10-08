"""Watchdog : lecture des compteurs, test de connectivité, filet anti-inertie."""

import socket
import time
import unittest

import daemon.watchdog as m_watchdog
from tests.helpers import FakeDaemon, FakeProc, Recorder, patched_run


PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes
    lo:   12345     100    0    0    0     0          0         0
  eth0: 999888     500    0    0    0     0          0         0
   tun0: 4242424    3000    0    0    0     0          0         0
"""


class ReadRxTest(unittest.TestCase):

    def _read(self, iface, content=PROC_NET_DEV):
        from unittest.mock import mock_open, patch
        d = FakeDaemon(_tun_iface=iface)
        with patch("builtins.open", mock_open(read_data=content)):
            return d._read_tun0_rx()

    def test_lit_les_octets_recus_de_la_bonne_interface(self):
        self.assertEqual(self._read("tun0"), 4242424)

    def test_ne_confond_pas_les_interfaces(self):
        self.assertEqual(self._read("eth0"), 999888)

    def test_interface_absente_renvoie_zero(self):
        self.assertEqual(self._read("tun9"), 0)

    def test_fichier_illisible_renvoie_zero(self):
        from unittest.mock import patch
        d = FakeDaemon(_tun_iface="tun0")
        with patch("builtins.open", side_effect=OSError("pas de /proc")):
            self.assertEqual(d._read_tun0_rx(), 0)

    def test_sur_le_vrai_proc_net_dev(self):
        """Intégration (lecture seule) : le parseur doit tenir sur la sortie
        réelle du noyau, pas seulement sur un échantillon figé."""
        import pathlib
        proc = pathlib.Path("/proc/net/dev")
        if not proc.exists():
            self.skipTest("/proc/net/dev absent")
        ifaces = [ln.split(":", 1)[0].strip()
                  for ln in proc.read_text().splitlines() if ":" in ln]
        self.assertIn("lo", ifaces, "format de /proc/net/dev inattendu")
        d = FakeDaemon(_tun_iface="lo")
        octets = d._read_tun0_rx()
        self.assertIsInstance(octets, int)
        self.assertGreater(octets, 0, "loopback à 0 octet reçu : parsing suspect")


class VpnIsActiveTest(unittest.TestCase):

    def test_process_vivant(self):
        d = FakeDaemon()
        p = FakeProc(returncode=None)
        p._rc = None
        d.openvpn_process = p
        with patched_run(Recorder({"pgrep": (1, "")})):
            self.assertTrue(d._vpn_is_active())

    def test_un_autre_openvpn_ne_compte_pas(self):
        """L'ancien repli « pgrep -x openvpn » prenait n'importe quel OpenVPN
        de la machine (autre VPN, test manuel) pour le tunnel du daemon."""
        d = FakeDaemon()
        d.openvpn_process = None
        r = Recorder({"pgrep": (0, "1234")})
        with patched_run(r):
            self.assertFalse(d._vpn_is_active())
        self.assertFalse(r.ran("pgrep"), r.dump())

    def test_aucun_openvpn(self):
        d = FakeDaemon()
        d.openvpn_process = None
        with patched_run(Recorder({"pgrep": (1, "")})):
            self.assertFalse(d._vpn_is_active())


class ConnectivityTest(unittest.TestCase):
    """Deux endpoints, testés EN PARALLÈLE : une panne ponctuelle de l'un ne
    déclenche rien, et un tunnel mort ne coûte qu'un seul délai d'attente."""

    def _check(self, link_rc=0, echecs=(), grace=False, muets=()):
        """`echecs` : endpoints qui refusent ; `muets` : qui ne répondent
        jamais (délai d'attente)."""
        import errno
        d = FakeDaemon(_tun_iface="tun0")
        d._tunnel_up_time = time.time() if grace else time.time() - 3600
        tentes, selects = [], []

        class FakeSock:
            def __init__(self, *a, **k):
                self.idx = None
                self.ferme = False

            def setsockopt(self, *a):
                pass

            def setblocking(self, b):
                pass

            def connect_ex(self, addr):
                self.idx = len(tentes)
                tentes.append(addr)
                return errno.EINPROGRESS

            def getsockopt(self, *a):
                return errno.ECONNREFUSED if self.idx in echecs else 0

            def close(self):
                self.ferme = True

        def fake_select(r, w, x, t):
            selects.append(t)
            prets = [s for s in w if s.idx not in muets]
            return [], prets, []

        saved = (m_watchdog.socket.socket, m_watchdog.select.select)
        m_watchdog.socket.socket = FakeSock
        m_watchdog.select.select = fake_select
        try:
            with patched_run(Recorder({"ip link show": (link_rc, "")})):
                return d._check_connectivity(), tentes, selects
        finally:
            m_watchdog.socket.socket, m_watchdog.select.select = saved

    def test_interface_absente(self):
        ok, tentes, _ = self._check(link_rc=1)
        self.assertFalse(ok)
        self.assertEqual(tentes, [], "connexion tentée sans interface")

    def test_delai_de_grace(self):
        ok, tentes, _ = self._check(grace=True)
        self.assertTrue(ok)
        self.assertEqual(tentes, [], "test réseau pendant le délai de grâce")

    def test_les_deux_endpoints_lances_ensemble(self):
        ok, tentes, selects = self._check()
        self.assertTrue(ok)
        self.assertEqual([a[0] for a in tentes], ["1.1.1.1", "9.9.9.9"])
        self.assertEqual(len(selects), 1, "attente séquentielle des endpoints")

    def test_un_endpoint_en_panne_suffit_pas(self):
        ok, _, _ = self._check(echecs=(0,))
        self.assertTrue(ok, "un endpoint en panne suffit à déclarer la panne")

    def test_les_deux_endpoints_en_panne(self):
        ok, tentes, _ = self._check(echecs=(0, 1))
        self.assertFalse(ok)
        self.assertEqual(len(tentes), 2)

    def test_tunnel_muet_un_seul_delai(self):
        """Tunnel mort : les deux délais courent en même temps (5 s, pas 10)."""
        ok, _, selects = self._check(muets=(0, 1))
        self.assertFalse(ok)
        self.assertEqual(len(selects), 1)
        self.assertLessEqual(selects[0], m_watchdog.WatchdogMixin._CONN_TIMEOUT)

    def test_endpoints_independants(self):
        """Deux opérateurs distincts : pas deux résolveurs du même fournisseur."""
        hotes = [h for h, _ in m_watchdog.WatchdogMixin._CONN_ENDPOINTS]
        self.assertEqual(len(set(hotes)), 2)
        self.assertNotIn("1.0.0.1", hotes, "1.0.0.1 est le même opérateur que 1.1.1.1")


class GraduatedRecoveryTest(unittest.TestCase):
    """Relance d'OpenVPN seul d'abord ; redémarrage complet en second."""

    def _daemon(self, tor_sain=True):
        d = FakeDaemon(config={"auto_reconnect": True})
        d.appels = []
        d._tor_is_healthy = lambda: tor_sain
        d._restart_openvpn = lambda: d.appels.append("leger")
        d._full_restart = lambda: d.appels.append("complet")
        return d

    def test_tor_sain_relance_legere(self):
        d = self._daemon()
        d._recover()
        self.assertEqual(d.appels, ["leger"])
        self.assertTrue(d._light_restart_done)
        self.assertGreater(d._light_restart_at, 0)

    def test_tor_malade_redemarrage_complet(self):
        d = self._daemon(tor_sain=False)
        d._recover()
        self.assertEqual(d.appels, ["complet"])

    def test_seconde_panne_escalade(self):
        d = self._daemon()
        d._recover()
        d._recover()
        self.assertEqual(d.appels, ["leger", "complet"])
        self.assertTrue(d.has_log("n'a pas suffi", "ERROR"))

    def test_relance_legere_reelle(self):
        """NEWNYM, reconnexion sans failover, processus arrêté."""
        d = FakeDaemon()
        p = FakeProc(returncode=None)
        p._rc = None
        d.openvpn_process = p
        d._new_tor_circuit = lambda: d.logs.append(("OK", "newnym"))
        d._restart_openvpn()
        self.assertTrue(p.terminated)
        self.assertTrue(d._circuit_retry, "la boucle ferait un failover")
        self.assertFalse(d._stop_vpn, "la boucle ne reconnecterait pas")
        self.assertTrue(d.has_log("newnym"))

    def test_tor_sain_selon_le_controlport(self):
        d = FakeDaemon()
        p = FakeProc(returncode=None)
        p._rc = None
        d.tor_process = p
        d._tor_ctrl = lambda *c, **k: "250-status/circuit-established=1\r\n250 OK"
        self.assertTrue(d._tor_is_healthy())
        d._tor_ctrl = lambda *c, **k: "250-status/circuit-established=0\r\n250 OK"
        self.assertFalse(d._tor_is_healthy())

        def muet(*c, **k):
            raise OSError("timeout")
        d._tor_ctrl = muet
        self.assertFalse(d._tor_is_healthy())

    def test_tor_arrete_jamais_sain(self):
        d = FakeDaemon()
        d.tor_process = None
        self.assertFalse(d._tor_is_healthy())


class MonitorLoopTest(unittest.TestCase):
    """Boucle de surveillance, sur une horloge simulée."""

    def _boucle(self, d, ticks, verifs=()):
        import types
        horloge = [1_000_000.0]
        n = [0]
        resultats = list(verifs)
        d.verifs = []

        def dormir(s):
            horloge[0] += s
            n[0] += 1
            if n[0] > ticks:
                d._stop_flag = True

        def verifier():
            d.verifs.append(horloge[0])
            return resultats.pop(0) if resultats else True

        d._check_connectivity = verifier
        d._read_tun0_rx = lambda: 0
        d._protect_tor_routes = lambda: None
        d._ensure_dns_config = lambda: None
        d._vpn_is_active = lambda: True
        m_watchdog.time = types.SimpleNamespace(sleep=dormir,
                                                time=lambda: horloge[0])
        saved = m_watchdog._sd_notify
        m_watchdog._sd_notify = lambda m: None
        try:
            d._monitor_loop()
        finally:
            m_watchdog.time = time
            m_watchdog._sd_notify = saved
        return horloge

    def _daemon(self):
        d = FakeDaemon(config={"auto_reconnect": True})
        d._tunnel_up = True
        d._vpn_loop_active = True
        d.appels = []
        d._recover = lambda: d.appels.append("recover")
        d._full_restart = lambda: d.appels.append("complet")
        return d

    def test_confirmation_trois_secondes_apres_le_premier_echec(self):
        d = self._daemon()
        self._boucle(d, ticks=8, verifs=[False, False])
        self.assertEqual(d.appels, ["recover"])
        self.assertEqual(d.verifs[1] - d.verifs[0], 3,
                         "le second avis attend encore un cycle de 9 s")

    def test_echec_isole_sans_suite(self):
        d = self._daemon()
        self._boucle(d, ticks=12, verifs=[False, True, True])
        self.assertEqual(d.appels, [])

    def test_succes_rearme_la_relance_legere(self):
        d = self._daemon()
        d._light_restart_done = True
        self._boucle(d, ticks=4, verifs=[True])
        self.assertFalse(d._light_restart_done)

    def test_tunnel_absent_trop_longtemps_apres_relance_legere(self):
        d = self._daemon()
        d._tunnel_up = False
        d._light_restart_at = 1_000_000.0 - 60
        self._boucle(d, ticks=4)
        self.assertEqual(d.appels, ["complet"])
        self.assertTrue(d.has_log("après la relance", "ERROR"))

    def test_relance_legere_aboutie_pas_d_escalade(self):
        d = self._daemon()
        d._light_restart_at = 1_000_000.0 - 60     # tunnel revenu entre-temps
        self._boucle(d, ticks=4)
        self.assertEqual(d.appels, [])
        self.assertEqual(d._light_restart_at, 0.0)


class InertNetTest(unittest.TestCase):
    """Filet anti-inertie : aucune impasse ne doit être définitive."""

    def test_seuils_coherents(self):
        W = m_watchdog.WatchdogMixin
        self.assertLess(W._INERT_WARN_TICKS, W._INERT_EXIT_TICKS)
        self.assertEqual(W._INERT_EXIT_TICKS * 3, 120, "le seuil de sortie doit rester à 2 min")

    def test_rafraichissement_des_guards_toutes_les_30s(self):
        self.assertEqual(m_watchdog.WatchdogMixin._GUARD_REFRESH_TICKS * 3, 30)

    def test_delai_de_grace_de_30s(self):
        self.assertEqual(m_watchdog.WatchdogMixin._CONN_GRACE, 30)


class FullRestartTest(unittest.TestCase):

    def test_plus_d_attente_fixe_de_6_secondes(self):
        import types
        d = self._daemon()
        pauses = []
        m_watchdog.time = types.SimpleNamespace(sleep=pauses.append, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertLessEqual(sum(pauses), 1, f"pauses : {pauses}")

    def _daemon(self):
        d = FakeDaemon(config={"auto_reconnect": True})
        d._tunnel_up, d._tun_iface = True, "tun0"
        d.appels = []
        for nom in ("_stop_openvpn", "_stop_tor", "_cleanup_tor_routes",
                    "_ipv6_block_off"):
            setattr(d, nom, (lambda n: lambda: d.appels.append(n))(nom))
        d._wait_vpn_loop_exit = lambda timeout=15.0: d.appels.append("_wait") or True
        d._check_socks_port = lambda: False
        d._start_services = lambda: d.appels.append("_start") or True
        return d

    def test_sequence_d_arret_puis_relance(self):
        import types
        d = self._daemon()
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        for attendu in ("_stop_openvpn", "_stop_tor", "_wait",
                        "_cleanup_tor_routes", "_ipv6_block_off", "_start"):
            self.assertIn(attendu, d.appels, f"{attendu} non appelé")
        self.assertLess(d.appels.index("_stop_openvpn"), d.appels.index("_start"))

    def test_blocage_garde_pendant_le_redemarrage(self):
        """Le redémarrage complet est une reconnexion : rien ne doit fuir."""
        import types
        d = self._daemon()
        d._kill_active = True
        d._kill_switch_off = lambda force=False: d.appels.append("_kill_switch_off")
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertNotIn("_kill_switch_off", d.appels)
        self.assertTrue(d._kill_active)

    def test_etat_reinitialise(self):
        import types
        d = self._daemon()
        d._conn_fail_count, d._reconnect_vpn_count = 5, 4
        d._conn_restart_pending = True
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertEqual(d._conn_fail_count, 0)
        self.assertEqual(d._reconnect_vpn_count, 0)
        self.assertFalse(d._conn_restart_pending)
        self.assertFalse(d._tunnel_up)
        self.assertFalse(d._stop_vpn, "_stop_vpn resté armé : la boucle ne repartirait pas")
        self.assertFalse(d._stop_tor_flag)

    def test_reparation_d_urgence_au_seuil(self):
        import types
        d = self._daemon()
        d._full_restart_count = m_watchdog.REPAIR_THRESHOLD - 1
        appele = []
        d._emergency_repair = lambda: appele.append(1)
        m_watchdog.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            d._full_restart()
        finally:
            m_watchdog.time = time
        self.assertEqual(appele, [1], "réparation d'urgence non déclenchée au seuil")


if __name__ == "__main__":
    unittest.main()


class RaisonDeReconnexionTest(unittest.TestCase):
    """La relance légère se déclare : `doctor` y voit une reconnexion voulue."""

    def test_relance_legere_nommee(self):
        d = FakeDaemon()
        p = FakeProc(returncode=None)
        p._rc = None
        d.openvpn_process = p
        d._new_tor_circuit = lambda: None
        d._restart_openvpn()
        self.assertIn("relance d'OpenVPN", d._reconnect_reason)
