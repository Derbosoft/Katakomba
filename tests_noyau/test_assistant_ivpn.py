"""
WireGuard géré : l'assistant de l'API IVPN (ivpn.py), lancé par le vrai
daemon comme en production — « python3 -I », depuis /, sans aucun droit en
root réel (CI), depuis un dossier rangé comme /opt/katakomba.  Sans réseau
dans cet espace : la réponse doit être une erreur JSON propre, jamais une
trace (import manqué, exception non rattrapée).
"""

import os
import shutil
import tempfile
import time
from pathlib import Path

import daemon.gestion_wg as m_gestion_wg
from tests_noyau.noyau import CasNoyau, daemon_de_test, root_reel

RACINE = Path(__file__).resolve().parents[1]


class AssistantIvpnTest(CasNoyau):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        code = Path(tmp.name) / "code"
        code.mkdir()
        os.chmod(tmp.name, 0o755)
        os.chmod(code, 0o755)
        for f in ("ivpn.py", "pont_wg.py"):
            shutil.copy(RACINE / f, code)
            (code / f).chmod(0o644)
        self.addCleanup(setattr, m_gestion_wg, "SCRIPT_DIR", m_gestion_wg.SCRIPT_DIR)
        m_gestion_wg.SCRIPT_DIR = code
        self.d = daemon_de_test()
        if root_reel():
            import pwd
            nobody = pwd.getpwnam("nobody")
            self.d._utilisateur_vpn = lambda: (nobody.pw_uid, nobody.pw_gid)
        else:
            # Espace utilisateur : setgroups interdit, seul l'uid 0 existe.
            vrai = m_gestion_wg.subprocess.run

            def run(*a, **k):
                for cle in ("user", "group", "extra_groups"):
                    k.pop(cle, None)
                return vrai(*a, **k)
            self.addCleanup(setattr, m_gestion_wg.subprocess, "run", vrai)
            m_gestion_wg.subprocess.run = run
            self.d._utilisateur_vpn = lambda: (0, 0)

    def test_erreur_propre_sans_reseau(self):
        debut = time.monotonic()
        r = self.d._api_ivpn({"action": "statut", "jeton": "x"})
        self.assertEqual((r["ok"], r["code"]), (False, 0), r)
        self.assertIn("API injoignable", r["message"])
        self.assertLess(time.monotonic() - debut, 30)

    def test_requete_inconnue(self):
        r = self.d._api_ivpn({"action": "rm"})
        self.assertEqual(r, {"ok": False, "code": 0, "message": "requête illisible"})
