"""Tor : parsing du ControlPort, bootstrap, NEWNYM, batching des requêtes."""

import unittest

from tests.helpers import FakeDaemon, Recorder, patched_run


# Consensus « microdesc » (défaut des clients Tor) : 8 champs, pas de digest.
NS_MICRODESC = (
    "250+ns/id/$AAAA=\r\n"
    "r Relay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-07-25 10:00:00 77.1.2.3 9001 0\r\n"
    "s Fast Guard Running Stable Valid\r\n"
    ".\r\n250 OK\r\n"
)
# Consensus « ns » complet : 9 champs (digest supplémentaire).
NS_FULL = (
    "250+ns/id/$BBBB=\r\n"
    "r Relay2 BBBBBBBBBBBBBBBBBBBBBBBBBBB CCCCCCCCCCCCCCCCCCCCCCCCCCC "
    "2026-07-25 10:00:00 88.4.5.6 443 0\r\n"
    "s Fast Running Valid\r\n"
    ".\r\n250 OK\r\n"
)


class TorRelayIpsTest(unittest.TestCase):
    """_tor_relay_ips alimente la protection /32 : un parsing faux = boucle de routage."""

    def _run_with(self, ctrl_responses):
        d = FakeDaemon()
        seen = []

        def fake_ctrl(*commands, timeout=3.0):
            seen.append(list(commands))
            return ctrl_responses.pop(0) if ctrl_responses else ""

        d._tor_ctrl = fake_ctrl
        return d, d._tor_relay_ips(), seen

    def test_format_microdesc_8_champs(self):
        orcon = "250+orcon-status=\r\n$AAAA~Relay1 CONNECTED\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, NS_MICRODESC])
        self.assertEqual(ips, {"77.1.2.3"})

    def test_format_ns_9_champs(self):
        orcon = "250+orcon-status=\r\n$BBBB~Relay2 CONNECTED\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, NS_FULL])
        self.assertEqual(ips, {"88.4.5.6"})

    def test_les_deux_formats_melanges(self):
        orcon = ("250+orcon-status=\r\n$AAAA~R1 CONNECTED\r\n"
                 "$BBBB~R2 CONNECTED\r\n.\r\n250 OK\r\n")
        _, ips, _ = self._run_with([orcon, NS_MICRODESC + NS_FULL])
        self.assertEqual(ips, {"77.1.2.3", "88.4.5.6"})

    def test_batching_une_seule_connexion(self):
        """Correctif des timeouts ControlPort : toutes les requêtes ns/id en UN appel."""
        orcon = ("250+orcon-status=\r\n"
                 + "".join(f"$FP{i}~R{i} CONNECTED\r\n" for i in range(12))
                 + ".\r\n250 OK\r\n")
        _, _, seen = self._run_with([orcon, ""])
        self.assertEqual(len(seen), 2, "plus de 2 connexions au ControlPort")
        self.assertEqual(len(seen[1]), 12, "les requêtes ns/id ne sont pas groupées")

    def test_plafonne_a_32_relais(self):
        orcon = ("250+orcon-status=\r\n"
                 + "".join(f"$FP{i}~R{i} CONNECTED\r\n" for i in range(50))
                 + ".\r\n250 OK\r\n")
        _, _, seen = self._run_with([orcon, ""])
        self.assertEqual(len(seen[1]), 32, "le plafond de 32 requêtes n'est pas respecté")

    def test_relais_non_connectes_ignores(self):
        orcon = ("250+orcon-status=\r\n$AAAA~R1 LAUNCHED\r\n"
                 "$BBBB~R2 CLOSED\r\n.\r\n250 OK\r\n")
        d = FakeDaemon()
        calls = []
        d._tor_ctrl = lambda *c, timeout=3.0: (calls.append(c), orcon)[1]
        self.assertEqual(d._tor_relay_ips(), set())
        self.assertEqual(len(calls), 1, "requête ns/id émise sans relais connecté")

    def test_controlport_en_erreur_renvoie_ensemble_vide(self):
        """Doit permettre le repli sur ss, pas propager l'exception."""
        d = FakeDaemon()

        def boom(*c, timeout=3.0):
            raise OSError("connexion refusée")

        d._tor_ctrl = boom
        self.assertEqual(d._tor_relay_ips(), set())
        self.assertTrue(d.has_log("relais indisponibles", "WARN"))

    def test_lignes_trop_courtes_ignorees(self):
        orcon = "250+orcon-status=\r\n$AAAA~R1 CONNECTED\r\n.\r\n250 OK\r\n"
        ns = "250+ns/id/$AAAA=\r\nr Relay1 AAA 9001 0\r\ns Fast\r\n.\r\n250 OK\r\n"
        _, ips, _ = self._run_with([orcon, ns])
        self.assertEqual(ips, set())


class BootstrapProgressTest(unittest.TestCase):

    def _prog(self, response):
        d = FakeDaemon()
        d._tor_ctrl = lambda *c, **k: response
        return d._tor_bootstrap_progress()

    # Format réel de la réponse : PROGRESS= est un jeton séparé par des
    # espaces (« NOTICE BOOTSTRAP PROGRESS=n TAG=… SUMMARY="…" »).  Le
    # parseur a bien atteint 100 % par cette voie en production.
    def test_progression_lue(self):
        self.assertEqual(
            self._prog('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=75 '
                       'TAG=loading_status SUMMARY="Loading networkstatus"'), 75)

    def test_cent_pour_cent(self):
        self.assertEqual(
            self._prog('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 '
                       'TAG=done SUMMARY="Done"'), 100)

    def test_absent_renvoie_moins_un(self):
        self.assertEqual(self._prog("250 OK"), -1)

    def test_exception_renvoie_moins_un(self):
        d = FakeDaemon()

        def boom(*c, **k):
            raise OSError("nope")

        d._tor_ctrl = boom
        self.assertEqual(d._tor_bootstrap_progress(), -1)


class NewCircuitTest(unittest.TestCase):

    def test_succes(self):
        d = FakeDaemon()
        sent = []
        d._tor_ctrl = lambda *c, **k: (sent.extend(c), "250 OK")[1]
        d._new_tor_circuit()
        self.assertEqual(sent, ["SIGNAL NEWNYM"])
        self.assertTrue(d.has_log("Nouveau circuit demandé", "OK"))

    def test_reponse_inattendue(self):
        d = FakeDaemon()
        d._tor_ctrl = lambda *c, **k: "515 Command not recognized"
        d._new_tor_circuit()
        self.assertTrue(d.has_log("réponse inattendue", "WARN"))

    def test_exception_journalisee_sans_lever(self):
        d = FakeDaemon()

        def boom(*c, **k):
            raise OSError("socket fermé")

        d._tor_ctrl = boom
        d._new_tor_circuit()          # ne doit pas lever
        self.assertTrue(d.has_log("NEWNYM", "WARN"))


class StopTorTest(unittest.TestCase):

    def test_terminate_puis_reap(self):
        from tests.helpers import FakeProc
        d = FakeDaemon()
        proc = FakeProc(returncode=None)
        proc._rc = None                      # process vivant
        d.tor_process = proc
        with patched_run(Recorder()):
            d._stop_tor()
        self.assertTrue(proc.terminated)
        self.assertTrue(d._stop_tor_flag)

    def test_pkill_si_pas_de_process(self):
        d = FakeDaemon()
        d.tor_process = None
        r = Recorder()
        with patched_run(r):
            d._stop_tor()
        self.assertFalse(r.ran("pkill -x tor"),
                         "pkill -x tor couperait aussi le Tor de Tor Browser")
        self.assertTrue(r.ran("pkill -f", "katakomba/tor"), r.dump())


class RelayIpsFormatsTest(unittest.TestCase):
    """Formats réels de GETINFO orconn-status."""

    def _ips(self, orcon, ns):
        d = FakeDaemon()
        reponses = [orcon, ns]
        d._tor_ctrl = lambda *c, **k: reponses.pop(0)
        return d._tor_relay_ips()

    def test_une_seule_connexion_format_monoligne(self):
        """Avec une seule connexion, Tor répond sur UNE ligne — non lue avant."""
        orcon = "250-orconn-status=$AAAA~Relay1 CONNECTED\r\n250 OK\r\n"
        self.assertEqual(self._ips(orcon, NS_MICRODESC), {"77.1.2.3"})

    def test_relais_absent_du_consensus_n_efface_pas_les_autres(self):
        orcon = ("250+orconn-status=\r\n$AAAA~R1 CONNECTED\r\n"
                 "$CCCC~Parti CONNECTED\r\n.\r\n250 OK\r\n")
        ns = NS_MICRODESC + '\n552 Unrecognized key "ns/id/$CCCC"\r\n'
        self.assertEqual(self._ips(orcon, ns), {"77.1.2.3"})


class PrepareTorTest(unittest.TestCase):
    """torrc validé et copié, paramètres vitaux imposés, DataDirectory sûr."""

    def setUp(self):
        import pathlib
        import tempfile
        import daemon.tor as m_tor
        self.m = m_tor
        self._tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self._tmp.name)
        self.saved = {k: getattr(m_tor, k) for k in
                      ("TORRC_FILE", "TORRC_RUN", "TOR_DATA_DIR",
                       "LEGACY_TOR_DATA", "STATE_DIR")}
        m_tor.TORRC_FILE = base / "conf" / "torrc"
        m_tor.TORRC_FILE.parent.mkdir()
        m_tor.TORRC_RUN = base / "run" / "torrc"
        m_tor.STATE_DIR = base / "state"
        m_tor.TOR_DATA_DIR = base / "state" / "tor_data"
        m_tor.LEGACY_TOR_DATA = base / "conf" / "tor_data"

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(self.m, k, v)
        self._tmp.cleanup()

    def test_torrc_valide_copie_a_l_identique(self):
        self.m.TORRC_FILE.write_text("SafeLogging 1\nNumEntryGuards 3\n")
        d = FakeDaemon()
        chemin = d._prepare_torrc()
        self.assertEqual(chemin, str(self.m.TORRC_RUN))
        self.assertEqual(self.m.TORRC_RUN.read_text(),
                         "SafeLogging 1\nNumEntryGuards 3\n")

    def test_transport_plugin_refuse(self):
        """« exec » dans un torrc = programme lancé en root."""
        self.m.TORRC_FILE.write_text(
            "SafeLogging 1\nClientTransportPlugin x exec /tmp/charge\n")
        d = FakeDaemon()
        chemin = d._prepare_torrc()
        self.assertEqual(self.m.TORRC_RUN.read_text(), "",
                         "le torrc refusé a été transmis à Tor")
        self.assertEqual(chemin, str(self.m.TORRC_RUN))
        self.assertTrue(d.has_log("torrc refusé", "ERROR"), d.log_dump())

    def test_lien_symbolique_ignore(self):
        cible = self.m.TORRC_FILE.parent / "ailleurs"
        cible.write_text("SafeLogging 1\n")
        self.m.TORRC_FILE.symlink_to(cible)
        d = FakeDaemon()
        d._prepare_torrc()
        self.assertEqual(self.m.TORRC_RUN.read_text(), "")
        self.assertTrue(d.has_log("illisible", "ERROR"))

    def test_torrc_absent_configuration_de_base(self):
        d = FakeDaemon()
        d._prepare_torrc()
        self.assertEqual(self.m.TORRC_RUN.read_text(), "")
        self.assertEqual(d.logs, [], d.log_dump())

    def test_parametres_vitaux_imposes_apres_le_torrc(self):
        d = FakeDaemon()
        cmd = d._tor_command("debian-tor")
        i_torrc = cmd.index("--torrc-file")
        for opt, val in (("--SocksPort", "9050"), ("--ControlPort", "9051"),
                         ("--DataDirectory", str(self.m.TOR_DATA_DIR)),
                         ("--Log", "notice stdout"), ("--User", "debian-tor")):
            self.assertIn(opt, cmd)
            self.assertGreater(cmd.index(opt), i_torrc)
            self.assertEqual(cmd[cmd.index(opt) + 1], val)

    def test_sans_utilisateur_pas_d_option_user(self):
        self.assertNotIn("--User", FakeDaemon()._tor_command(None))

    def test_data_dir_cree_prive(self):
        import os
        import stat
        d = FakeDaemon()
        user = d._prepare_tor_data_dir()
        self.assertIsNone(user, "hors root, Tor ne peut pas changer d'utilisateur")
        mode = stat.S_IMODE(os.stat(self.m.TOR_DATA_DIR).st_mode)
        self.assertEqual(mode, 0o700)

    def test_ancien_data_dir_non_root_jamais_migre(self):
        """Seul un répertoire réel appartenant à root est repris : un membre
        du groupe pourrait sinon imposer ses propres guards."""
        self.m.LEGACY_TOR_DATA.mkdir()
        (self.m.LEGACY_TOR_DATA / "state").write_text("piege")
        FakeDaemon()._prepare_tor_data_dir()
        self.assertFalse((self.m.TOR_DATA_DIR / "state").exists())

    def test_data_dir_en_lien_symbolique_refuse(self):
        self.m.STATE_DIR.mkdir()
        (self.m.STATE_DIR / "ailleurs").mkdir()
        self.m.TOR_DATA_DIR.symlink_to(self.m.STATE_DIR / "ailleurs")
        with self.assertRaises(PermissionError):
            FakeDaemon()._prepare_tor_data_dir()


if __name__ == "__main__":
    unittest.main()
