"""Cycle de vie : ControlPort réel, nettoyage au démarrage, arrêt propre.

Couvre le code socket de _tor_ctrl (celui qui avait provoqué les timeouts
ControlPort) plutôt qu'un remplaçant, et les séquences d'orchestration.
"""

import pathlib
import tempfile
import types
import unittest

import daemon.core as m_core
import daemon.tor as m_tor
from tests.helpers import FakeDaemon, Recorder, patched_run


class FakeSocket:
    """Socket TCP factice : rejoue des réponses, enregistre les envois."""

    instances = []

    def __init__(self, *a, **k):
        self.envoyes = []
        self.reponses = list(FakeSocket.scenario)
        self.ferme = False
        FakeSocket.instances.append(self)

    scenario = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.ferme = True

    def settimeout(self, t):
        pass

    def connect(self, addr):
        self.addr = addr

    def sendall(self, data):
        self.envoyes.append(data)

    def recv(self, n):
        return self.reponses.pop(0) if self.reponses else b""

    def close(self):
        self.ferme = True


class TorCtrlTest(unittest.TestCase):
    """Le batching est la correction des timeouts : UNE connexion pour N commandes."""

    def setUp(self):
        FakeSocket.instances = []
        self._saved_socket = m_tor.socket.socket
        self._saved_cookie = m_tor.TOR_COOKIE
        self._tmp = tempfile.TemporaryDirectory()
        # Jamais le vrai cookie (root-only) : chemin temporaire déterministe.
        m_tor.TOR_COOKIE = pathlib.Path(self._tmp.name) / "cookie"
        m_tor.socket.socket = FakeSocket

    def tearDown(self):
        m_tor.socket.socket = self._saved_socket
        m_tor.TOR_COOKIE = self._saved_cookie
        self._tmp.cleanup()

    def test_une_seule_connexion_pour_plusieurs_commandes(self):
        FakeSocket.scenario = [b"250 OK\r\n"] * 12
        d = FakeDaemon()
        d._tor_ctrl("GETINFO a", "GETINFO b", "GETINFO c")
        self.assertEqual(len(FakeSocket.instances), 1,
                         "plusieurs connexions ouvertes : le batching est cassé")

    def test_authentification_avec_cookie(self):
        m_tor.TOR_COOKIE.write_bytes(b"\xde\xad\xbe\xef")
        FakeSocket.scenario = [b"250 OK\r\n", b"250 OK\r\n"]
        FakeDaemon()._tor_ctrl("GETINFO version")
        envoi = FakeSocket.instances[0].envoyes[0]
        self.assertEqual(envoi, b"AUTHENTICATE deadbeef\r\n")

    def test_authentification_sans_cookie(self):
        FakeSocket.scenario = [b"250 OK\r\n", b"250 OK\r\n"]
        FakeDaemon()._tor_ctrl("GETINFO version")
        self.assertEqual(FakeSocket.instances[0].envoyes[0], b"AUTHENTICATE\r\n")

    def test_refus_d_authentification_leve(self):
        FakeSocket.scenario = [b"515 Authentication failed\r\n"]
        with self.assertRaises(OSError):
            FakeDaemon()._tor_ctrl("GETINFO version")

    def test_commandes_envoyees_dans_l_ordre(self):
        FakeSocket.scenario = [b"250 OK\r\n"] * 6
        FakeDaemon()._tor_ctrl("GETINFO a", "GETINFO b")
        envoyes = FakeSocket.instances[0].envoyes
        self.assertEqual(envoyes[1], b"GETINFO a\r\n")
        self.assertEqual(envoyes[2], b"GETINFO b\r\n")

    def test_quit_envoye_en_fin(self):
        FakeSocket.scenario = [b"250 OK\r\n"] * 4
        FakeDaemon()._tor_ctrl("GETINFO a")
        self.assertEqual(FakeSocket.instances[0].envoyes[-1], b"QUIT\r\n")

    def test_reponse_multiligne_terminee_par_250(self):
        FakeSocket.scenario = [
            b"250 OK\r\n",                                  # auth
            b"250+ns/id/$X=\r\nr Relay 1.2.3.4 9001 0\r\n",  # début
            b".\r\n250 OK\r\n",                             # fin
        ]
        out = FakeDaemon()._tor_ctrl("GETINFO ns/id/$X")
        self.assertIn("1.2.3.4", out)

    def test_erreur_en_premiere_ligne_termine_la_reponse(self):
        """« 552 » sans rien avant : l'ancienne lecture attendait le timeout
        (8 s) puis perdait toute la liste des relais."""
        FakeSocket.scenario = [
            b"250 OK\r\n",
            b'552 Unrecognized key "ns/id/$X"\r\n',
            b"250+ns/id/$Y=\r\nr R 2026-07-25 10:00:00 4.4.4.4 9001 0\r\n.\r\n250 OK\r\n",
        ]
        out = FakeDaemon()._tor_ctrl("GETINFO ns/id/$X", "GETINFO ns/id/$Y")
        premiere, seconde = out.split("\n", 1)
        self.assertTrue(premiere.startswith("552"), out)
        self.assertNotIn("4.4.4.4", premiere, "deux réponses fusionnées")
        self.assertIn("4.4.4.4", seconde)

    def test_ligne_250_dans_un_bloc_de_donnees_ne_termine_pas(self):
        FakeSocket.scenario = [
            b"250 OK\r\n",
            b"250+x=\r\n250 pas une fin\r\n.\r\n250 OK\r\n",
        ]
        out = FakeDaemon()._tor_ctrl("GETINFO x")
        self.assertTrue(out.endswith("250 OK\r\n"), repr(out))

    def test_cookie_en_lien_symbolique_ignore(self):
        cible = pathlib.Path(self._tmp.name) / "secret"
        cible.write_bytes(b"\x01\x02")
        m_tor.TOR_COOKIE.symlink_to(cible)
        FakeSocket.scenario = [b"250 OK\r\n", b"250 OK\r\n"]
        FakeDaemon()._tor_ctrl("GETINFO version")
        self.assertEqual(FakeSocket.instances[0].envoyes[0], b"AUTHENTICATE\r\n")

    def test_erreur_5xx_termine_la_lecture(self):
        FakeSocket.scenario = [b"250 OK\r\n", b"\r\n552 Unrecognized key\r\n"]
        out = FakeDaemon()._tor_ctrl("GETINFO inexistant")
        self.assertIn("552", out)

    def test_socket_ferme(self):
        FakeSocket.scenario = [b"250 OK\r\n"] * 4
        FakeDaemon()._tor_ctrl("GETINFO a")
        self.assertTrue(FakeSocket.instances[0].ferme, "socket non fermé")

    def test_connexion_coupee_ne_boucle_pas(self):
        """recv() renvoyant b'' doit sortir de la boucle, pas tourner à vide."""
        FakeSocket.scenario = [b"250 OK\r\n"]      # puis plus rien
        out = FakeDaemon()._tor_ctrl("GETINFO a")
        self.assertEqual(out, "")


class CleanupStaleRulesTest(unittest.TestCase):
    """Au démarrage, aucune trace d'une session précédente ne doit subsister."""

    def _run(self, cfg=None):
        d = FakeDaemon(config=cfg or {"lan_subnet": "10.0.0.0/24"})
        d._cleanup_tor_routes = lambda: d.logs.append(("INFO", "_cleanup_tor_routes"))
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_core.LAN_DNSMASQ_PID
            m_core.LAN_DNSMASQ_PID = pathlib.Path(tmp) / "dnsmasq.pid"
            r = Recorder()
            try:
                with patched_run(r):
                    d.cleanup_stale_rules()
            finally:
                m_core.LAN_DNSMASQ_PID = saved
        return d, r

    def test_purge_les_jumps_en_boucle(self):
        """Des crashs répétés peuvent empiler plusieurs jumps identiques."""
        d = FakeDaemon(config={"lan_subnet": ""})
        d._cleanup_tor_routes = lambda: None
        # -D réussit 3 fois puis échoue : la boucle doit s'arrêter là.
        appels = {"n": 0}

        def run(*cmd):
            ligne = " ".join(cmd)
            if "-D OUTPUT -j KATAKOMBA_KS6" in ligne:
                appels["n"] += 1
                return types.SimpleNamespace(
                    returncode=0 if appels["n"] <= 3 else 1, stdout=b"", stderr=b"")
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory() as tmp:
            saved = m_core.LAN_DNSMASQ_PID
            m_core.LAN_DNSMASQ_PID = pathlib.Path(tmp) / "p.pid"
            try:
                with patched_run(run):
                    d.cleanup_stale_rules()
            finally:
                m_core.LAN_DNSMASQ_PID = saved
        self.assertEqual(appels["n"], 4, "la boucle de purge ne s'arrête pas correctement")

    def test_supprime_les_trois_chaines(self):
        _, r = self._run()
        for chaine in ("KATAKOMBA_KS6", "KATAKOMBA_KS6_FWD", "KATAKOMBA_LAN_FWD",
                       "KATAKOMBA_KILL", "KATAKOMBA_KILL_FWD", "KATAKOMBA_KILL6",
                       "KATAKOMBA_KILL6_FWD"):
            self.assertTrue(r.ran("-F", chaine), f"{chaine} non vidée")
            self.assertTrue(r.ran("-X", chaine), f"{chaine} non supprimée")

    def test_nat_lan_pour_tun0_et_tun1(self):
        _, r = self._run()
        for tun in ("tun0", "tun1"):
            self.assertTrue(r.ran("-t nat -D POSTROUTING", f"-o {tun}"),
                            f"NAT non nettoyé pour {tun}")

    def test_dnsmasq_cible_par_pid_file(self):
        _, r = self._run()
        pkills = r.matching("pkill")
        self.assertTrue(pkills, "dnsmasq du partage non arrêté")
        for c in pkills:
            self.assertIn("dnsmasq.pid", c,
                          "pkill trop large : tuerait les dnsmasq de libvirt")

    def test_routes_tor_nettoyees(self):
        d, _ = self._run()
        self.assertTrue(any("_cleanup_tor_routes" in m for _, m in d.logs))

    def test_sous_reseau_lan_invalide_ne_plante_pas(self):
        d, _ = self._run(cfg={"lan_subnet": "pas-un-reseau"})
        self.assertTrue(d.has_log("Nettoyage terminé", "OK"))

    def test_sans_sous_reseau_lan(self):
        _, r = self._run(cfg={"lan_subnet": ""})
        self.assertEqual(r.count("-t nat -D POSTROUTING"), 0)


class RunOrderTest(unittest.TestCase):

    def test_blocage_pose_avant_tor(self):
        """Rien ne doit sortir à découvert, même pendant le bootstrap de Tor."""
        from tests.helpers import provider
        d = FakeDaemon(config={"providers": [provider("vpn-a")]})
        ordre = []
        for nom in ("_check_dns_stack", "cleanup_stale_rules", "_kill_switch_on",
                    "_start_status_server"):
            setattr(d, nom, (lambda n: lambda: ordre.append(n))(nom))
        d._start_services = lambda: ordre.append("_start_services") or False
        saved = m_core._ensure_private_dir
        m_core._ensure_private_dir = lambda *a, **k: None
        try:
            with self.assertRaises(SystemExit):
                d.run()
        finally:
            m_core._ensure_private_dir = saved
        self.assertLess(ordre.index("cleanup_stale_rules"), ordre.index("_kill_switch_on"))
        self.assertLess(ordre.index("_kill_switch_on"), ordre.index("_start_services"))


class HandleSignalTest(unittest.TestCase):
    """L'arrêt propre doit tout défaire, dans le bon ordre, et sortir en 0."""

    def _daemon(self):
        d = FakeDaemon()
        d.appels = []
        for nom in ("_stop_openvpn", "_stop_tor", "_revert_vpn_dns",
                    "_cleanup_tor_routes", "_teardown_lan_sharing",
                    "_ipv6_block_off", "_remove_dns_split", "_stop_status_server",
                    "_kill_switch_off"):
            setattr(d, nom, (lambda n: lambda: d.appels.append(n))(nom))
        return d

    def test_tout_est_defait(self):
        d = self._daemon()
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_core.AUTH_TMP
            m_core.AUTH_TMP = pathlib.Path(tmp) / "auth.tmp"
            m_core.AUTH_TMP.write_text("user\npass\n")
            try:
                with self.assertRaises(SystemExit) as ctx:
                    d.handle_signal(15, None)
            finally:
                existe_encore = m_core.AUTH_TMP.exists()
                m_core.AUTH_TMP = saved
        self.assertEqual(ctx.exception.code, 0, "sortie non nulle sur arrêt demandé")
        self.assertFalse(existe_encore, "auth.tmp laissé sur le disque")
        for nom in ("_stop_openvpn", "_stop_tor", "_revert_vpn_dns",
                    "_cleanup_tor_routes", "_teardown_lan_sharing",
                    "_ipv6_block_off", "_remove_dns_split", "_stop_status_server",
                    "_kill_switch_off"):
            self.assertIn(nom, d.appels, f"{nom} non appelé à l'arrêt")
        # Blocage levé seulement une fois le tunnel et Tor arrêtés.
        self.assertGreater(d.appels.index("_kill_switch_off"), d.appels.index("_stop_tor"))

    def test_drapeaux_armes_avant_l_arret(self):
        d = self._daemon()
        etats = []
        d._stop_openvpn = lambda: etats.append(
            (d._stop_flag, d._stop_vpn, d._stop_tor_flag))
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_core.AUTH_TMP
            m_core.AUTH_TMP = pathlib.Path(tmp) / "a"
            try:
                with self.assertRaises(SystemExit):
                    d.handle_signal(15, None)
            finally:
                m_core.AUTH_TMP = saved
        self.assertEqual(etats, [(True, True, True)],
                         "les boucles pourraient repartir pendant l'arrêt")

    def test_openvpn_arrete_avant_tor(self):
        """Couper Tor d'abord ferait échouer OpenVPN au lieu de l'arrêter proprement."""
        d = self._daemon()
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_core.AUTH_TMP
            m_core.AUTH_TMP = pathlib.Path(tmp) / "a"
            try:
                with self.assertRaises(SystemExit):
                    d.handle_signal(15, None)
            finally:
                m_core.AUTH_TMP = saved
        self.assertLess(d.appels.index("_stop_openvpn"), d.appels.index("_stop_tor"))


class WaitTorReadyTest(unittest.TestCase):
    """L'attente réelle contient un wait(2) par tour : on le neutralise pour
    que la suite reste rapide, sans toucher à la logique testée."""

    @staticmethod
    def _daemon(progression=None, pose=False):
        import threading
        d = FakeDaemon()

        class EventRapide(threading.Event):
            def wait(self, timeout=None):        # pas d'attente réelle
                return self.is_set()

        ev = EventRapide()
        if pose:
            ev.set()
        d._tor_ready = ev
        if progression is not None:
            valeurs = iter(progression)
            d._tor_bootstrap_progress = lambda: next(valeurs, progression[-1])
        return d

    def test_evenement_deja_pose(self):
        self.assertTrue(self._daemon(pose=True)._wait_tor_ready(1))

    def test_bootstrap_detecte_par_le_controlport(self):
        d = self._daemon(progression=[100])
        self.assertTrue(d._wait_tor_ready(5))
        self.assertTrue(d._tor_ready.is_set(), "l'événement devrait être posé")
        self.assertTrue(d.has_log("Bootstrap 100 % (ControlPort)", "OK"))

    def test_progression_journalisee_une_fois_par_palier(self):
        d = self._daemon(progression=[10, 10, 50, 50, 100])
        d._wait_tor_ready(10)
        paliers = [m for _, m in d.logs if "Bootstrap" in m and "%" in m]
        self.assertLessEqual(len(paliers), 4, f"journal trop bavard : {paliers}")

    def test_delai_depasse(self):
        d = self._daemon(progression=[5])
        self.assertFalse(d._wait_tor_ready(0.05))

    def test_arret_demande_interrompt_l_attente(self):
        d = self._daemon(progression=[5])
        d._stop_flag = True
        self.assertFalse(d._wait_tor_ready(10))

    def test_progression_indisponible_n_empeche_pas_l_attente(self):
        """-1 (ControlPort muet) ne doit ni planter ni polluer le journal."""
        d = self._daemon(progression=[-1])
        self.assertFalse(d._wait_tor_ready(0.05))
        self.assertEqual([m for _, m in d.logs if "Bootstrap" in m], [])


class StatusServerTest(unittest.TestCase):

    def test_socket_indisponible_ne_bloque_pas_le_demarrage(self):
        d = FakeDaemon(config={"providers": []})
        saved = m_core.__dict__.get("STATUS_SOCKET")
        import daemon.status as m_status
        s_saved = m_status.STATUS_SOCKET
        m_status.STATUS_SOCKET = pathlib.Path("/nulle/part/impossible.sock")
        try:
            d._start_status_server()          # ne doit pas lever
        finally:
            m_status.STATUS_SOCKET = s_saved
        self.assertTrue(d.has_log("Socket de statut indisponible", "WARN"))

    def test_cycle_complet_sur_un_socket_temporaire(self):
        import json
        import socket as pysocket
        import daemon.status as m_status
        d = FakeDaemon(config={"providers": []})
        with tempfile.TemporaryDirectory() as tmp:
            saved = m_status.STATUS_SOCKET
            m_status.STATUS_SOCKET = pathlib.Path(tmp) / "s.sock"
            try:
                d._start_status_server()
                self.assertTrue(m_status.STATUS_SOCKET.exists())
                with pysocket.socket(pysocket.AF_UNIX) as c:
                    c.settimeout(3)
                    c.connect(str(m_status.STATUS_SOCKET))
                    ligne = c.makefile().readline()
                snap = json.loads(ligne)
                self.assertIn("version", snap)
                d._stop_flag = True
                d._stop_status_server()
                self.assertFalse(m_status.STATUS_SOCKET.exists())
            finally:
                m_status.STATUS_SOCKET = saved


class RunTimeoutTest(unittest.TestCase):
    """Une commande système bloquée ne doit plus geler le daemon."""

    def test_commande_bloquee_interrompue(self):
        import subprocess
        import types
        vus = {}

        def run(argv, **k):
            vus.update(k)
            raise subprocess.TimeoutExpired(argv, k.get("timeout"))

        saved = m_core.subprocess
        m_core.subprocess = types.SimpleNamespace(
            run=run, TimeoutExpired=subprocess.TimeoutExpired,
            CompletedProcess=subprocess.CompletedProcess)
        try:
            r = m_core._run("iptables", "-L")
        finally:
            m_core.subprocess = saved
        self.assertEqual(vus.get("timeout"), m_core.RUN_TIMEOUT)
        self.assertEqual(r.returncode, 124)
        self.assertEqual((r.stdout, r.stderr), (b"", b"timeout"))

    def test_delai_inferieur_au_watchdog_systemd(self):
        """WatchdogSec=90 : une commande bloquée doit rendre la main avant."""
        self.assertLess(m_core.RUN_TIMEOUT, 90)


if __name__ == "__main__":
    unittest.main()
