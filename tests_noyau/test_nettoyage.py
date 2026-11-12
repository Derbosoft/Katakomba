"""Le script de nettoyage de l'unité systemd (install.sh), exécuté pour de
bon : de vraies chaînes iptables, dans l'espace réseau du test.  Seuls
systemctl, systemd-run, pkill et sleep sont remplacés, et ses chemins sous
/run et /etc redirigés vers un dossier temporaire.

v4.7.0 : le blocage hors tunnel n'est levé que si le service s'ARRÊTE ; il
reste posé quand le service redémarre ou sort en échec."""

import os
import pathlib
import stat
import subprocess
import tempfile

import daemon.firewall as m_firewall

from tests_noyau.noyau import CasNoyau, daemon_de_test, sans_passe_droit_hors_root, sh

RACINE = pathlib.Path(__file__).resolve().parents[1]

FAUX = {
    # « systemctl list-jobs » : la tâche en cours sur le service, s'il y en a.
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$KK_JOURNAL"\n'
                 'case "$1" in\n'
                 '  list-jobs) [ -z "$KK_TACHE" ] || echo "42 katakomba.service $KK_TACHE running" ;;\n'
                 '  is-active) echo "$KK_ACTIF" ;;\n'
                 'esac\nexit 0\n',
    "systemd-run": '#!/bin/sh\necho "systemd-run $*" >> "$KK_JOURNAL"\n',
    "sleep": '#!/bin/sh\necho "sleep $*" >> "$KK_JOURNAL"\n',
    "pkill": '#!/bin/sh\nexit 1\n',
}


class NettoyageTest(CasNoyau):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        installeur = (RACINE / "install.sh").read_text()
        debut = installeur.index("<< 'CLEANUP_EOF'\n") + len("<< 'CLEANUP_EOF'\n")
        script = installeur[debut:installeur.index("\nCLEANUP_EOF\n", debut)]
        script = script.replace("/run/", f"{self.tmp}/run/").replace(
            "/etc/", f"{self.tmp}/etc/")
        self.assertNotIn(' /run', script)
        self.assertNotIn(' /etc', script)
        (self.tmp / "run").mkdir()
        (self.tmp / "faux").mkdir()
        self.script = self.tmp / "katakomba-cleanup.sh"
        self.script.write_text(script)
        for nom, texte in {**FAUX, "katakomba-cleanup.sh": script}.items():
            chemin = self.tmp / ("faux" if nom in FAUX else "") / nom
            chemin.write_text(texte)
            chemin.chmod(chemin.stat().st_mode | stat.S_IXUSR)
        self.journal = self.tmp / "journal"
        self.echec = self.tmp / "run" / "katakomba-echec"
        # Le blocage hors tunnel et la garde du compte VPN, posés par le daemon.
        self.addCleanup(setattr, m_firewall, "TOR_USER", m_firewall.TOR_USER)
        m_firewall.TOR_USER = "nobody"
        d = daemon_de_test()
        sans_passe_droit_hors_root(d)
        self.assertTrue(d._kill_switch_on())
        sh("iptables -N KATAKOMBA_VPN && iptables -I OUTPUT -j KATAKOMBA_VPN")

    def _lancer(self, mode="", tache="", resultat="success", statut="0", actif="inactive"):
        self.journal.write_text("")
        env = {**os.environ, "PATH": f"{self.tmp}/faux:{os.environ['PATH']}",
               "KK_JOURNAL": str(self.journal), "KK_TACHE": tache, "KK_ACTIF": actif,
               "SERVICE_RESULT": resultat, "EXIT_STATUS": statut}
        r = subprocess.run([str(self.script), *([mode] if mode else [])], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout, self.journal.read_text()

    def _blocage(self) -> bool:
        regles = sh("iptables -S") + sh("ip6tables -S")
        poses = [c in regles for c in ("-A OUTPUT -j KATAKOMBA_KILL\n",
                                       "-A FORWARD -j KATAKOMBA_KILL_FWD\n",
                                       "-A OUTPUT -j KATAKOMBA_KILL6\n",
                                       "-A FORWARD -j KATAKOMBA_KILL6_FWD\n")]
        self.assertIn(sum(poses), (0, 4), "blocage à moitié retiré")
        return all(poses)

    def test_arret_demande_blocage_leve(self):
        self._lancer("apres", tache="stop")
        self.assertFalse(self._blocage())
        self.assertNotIn("KATAKOMBA", sh("iptables -S") + sh("ip6tables -S"))

    def test_arret_demande_pendant_la_pause_d_un_echec(self):
        """SERVICE_RESULT vaut alors « signal » (ExecStartPre tué) : c'est la
        tâche qui décide, pas lui.  Vérifié sur systemd 259."""
        self._lancer("apres", tache="stop", resultat="signal")
        self.assertFalse(self._blocage())

    def test_redemarrage_blocage_garde(self):
        for tache in ("restart", "try-restart"):
            sortie, journal = self._lancer("apres", tache=tache)
            self.assertTrue(self._blocage(), tache)
            self.assertIn("gardé", sortie)
            self.assertFalse(self.echec.exists(), "un redémarrage n'est pas un échec")
            self.assertIn("filet", journal)

    def test_sortie_en_echec_blocage_garde_et_filet_pose(self):
        """Tor bloqué (240 s puis sortie 1), plantage, watchdog : aucune
        tâche, résultat en échec."""
        for resultat in ("exit-code", "signal", "watchdog", "timeout"):
            self.echec.unlink(missing_ok=True)
            sortie, journal = self._lancer("apres", resultat=resultat, statut="1")
            self.assertTrue(self._blocage(), resultat)
            self.assertTrue(self.echec.exists(), "pause du lancement suivant non demandée")
            lance = [l for l in journal.splitlines() if l.startswith("systemd-run")]
            self.assertEqual(len(lance), 1, journal)
            self.assertIn("--on-active=30", lance[0])
            self.assertTrue(lance[0].endswith(f"{self.script} filet"), lance[0])

    def test_sortie_propre_ou_sans_fournisseur_blocage_leve(self):
        """Systemd ne relance pas : garder le blocage couperait la machine
        d'Internet, service arrêté."""
        self._lancer("apres", resultat="success")
        self.assertFalse(self._blocage())

    def test_sortie_78_blocage_leve(self):
        self._lancer("apres", resultat="exit-code", statut="78")
        self.assertFalse(self._blocage())
        self.assertFalse(self.echec.exists())

    def test_avant_le_demarrage_blocage_garde(self):
        _sortie, journal = self._lancer("avant")
        self.assertTrue(self._blocage())
        self.assertNotIn("sleep", journal)
        self.assertNotIn("KATAKOMBA_VPN", sh("iptables -S"), "garde du compte VPN restée")

    def test_avant_le_demarrage_pause_apres_un_echec(self):
        self.echec.write_text("")
        _sortie, journal = self._lancer("avant")
        self.assertIn("sleep 19", journal)
        self.assertFalse(self.echec.exists())
        self.assertTrue(self._blocage())

    def test_filet_service_reparti_rien(self):
        for actif in ("active", "activating", "deactivating"):
            self._lancer("filet", actif=actif)
            self.assertTrue(self._blocage(), actif)
            self.assertIn("KATAKOMBA_VPN", sh("iptables -S"), "le filet a nettoyé sous un service en marche")

    def test_filet_service_reste_arrete_blocage_leve(self):
        """Arrêt demandé pendant l'attente de redémarrage : systemd n'exécute
        plus ExecStopPost (vérifié sur systemd 259)."""
        for actif in ("inactive", "failed"):
            self._lancer("filet", actif=actif)
            self.assertFalse(self._blocage(), actif)

    def test_sans_argument_tout_est_retire(self):
        self.echec.write_text("")
        self._lancer()
        self.assertFalse(self._blocage())
        self.assertFalse(self.echec.exists())
        self.assertNotIn("KATAKOMBA", sh("iptables -S") + sh("ip6tables -S"))
