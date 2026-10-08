"""polkit : connexion sans mot de passe pour le groupe katakomba, et rien
de plus ; invites propres à Katakomba pour les actions privilégiées.

La règle JavaScript est exécutée pour de vrai (node ou gjs) contre un faux
polkit, en mémoire : ni polkitd ni aucune commande système ne sont
sollicités, aucune règle n'est installée sur la machine."""

import json
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGLE = ROOT / "polkit" / "50-katakomba.rules"
POLITIQUE = ROOT / "polkit" / "org.katakomba.policy"
INSTALL = (ROOT / "install.sh").read_text()
CLI = (ROOT / "katakomba-cli.sh").read_text()
MODELE = (ROOT / "gui" / "modele.py").read_text()

# Faux polkit : même API que polkitd (addRule, Result, action.lookup,
# subject.isInGroup).  NOT_HANDLED vaut null, comme dans polkitd.
BANC_JS = r"""
var regles = [];
var polkit = {Result: {YES: "yes", NO: "no", AUTH_ADMIN: "auth_admin",
                       AUTH_ADMIN_KEEP: "auth_admin_keep", NOT_HANDLED: null},
              addRule: function (f) { regles.push(f); }};
%s
var cas = %s;
var sortie = cas.map(function (c) {
    var action = {id: c.id, lookup: function (k) { return c.details[k]; }};
    var sujet = {local: c.local, active: c.active, user: "alice",
                 isInGroup: function (g) { return c.groupes.indexOf(g) >= 0; }};
    for (var i = 0; i < regles.length; i++) {
        var r = regles[i](action, sujet);
        if (r !== null && r !== undefined) return r;
    }
    return null;
});
"""


def _interprete():
    if shutil.which("node"):
        return ["node", "-e"], "console.log(JSON.stringify(sortie));"
    if shutil.which("gjs"):
        return ["gjs", "-c"], "print(JSON.stringify(sortie));"
    return None, None


def cas(verbe="start", unite="katakomba.service", groupes=("katakomba",),
        local=True, active=True, ident="org.freedesktop.systemd1.manage-units"):
    return {"id": ident, "details": {"unit": unite, "verb": verbe},
            "groupes": list(groupes), "local": local, "active": active}


@unittest.skipUnless(_interprete()[0], "ni node ni gjs pour exécuter la règle")
class RegleTest(unittest.TestCase):

    def evaluer(self, *liste):
        cmd, fin = _interprete()
        js = BANC_JS % (REGLE.read_text(), json.dumps(list(liste))) + fin
        r = subprocess.run(cmd + [js], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_groupe_connecte_et_deconnecte_sans_mot_de_passe(self):
        self.assertEqual(self.evaluer(cas("start"), cas("stop"), cas("restart")),
                         ["yes", "yes", "yes"])

    def test_rien_d_autre_n_est_accorde(self):
        refuses = [
            cas("start", groupes=("users",)),                 # hors du groupe
            cas("start", unite="ssh.service"),                # autre service
            cas("start", unite="tor.service"),
            cas("start", unite="katakomba.service.d"),
            cas("reset-failed"), cas("reload"), cas("kill"),  # autres verbes
            cas("start", local=False),                        # session distante (ssh)
            cas("start", active=False),                       # session en arrière-plan
            cas("start", ident="org.freedesktop.systemd1.manage-unit-files"),  # enable
            cas("start", ident="org.freedesktop.policykit.exec"),
        ]
        self.assertEqual(self.evaluer(*refuses), [None] * len(refuses),
                         "la règle accorde plus que start/stop/restart de katakomba")

    def test_syntaxe_es5(self):
        """polkitd (duktape) n'accepte pas let/const/fonctions fléchées."""
        code = "\n".join(l for l in REGLE.read_text().splitlines()
                         if not l.lstrip().startswith("//"))
        self.assertNotRegex(code, r"\b(let|const)\s|=>|`")


class PolitiqueTest(unittest.TestCase):

    def setUp(self):
        self.actions = {a.get("id"): a for a in ET.parse(POLITIQUE).getroot().iter("action")}

    def annotation(self, action, cle):
        return next((a.text for a in action.iter("annotate")
                     if a.get("key") == f"org.freedesktop.policykit.exec.{cle}"), None)

    def test_chaque_action_designe_un_programme_deploye_et_executable(self):
        self.assertTrue(self.actions)
        for ident, action in self.actions.items():
            chemin = self.annotation(action, "path")
            self.assertTrue(chemin.startswith("/opt/katakomba/"), ident)
            nom = chemin.rsplit("/", 1)[1]
            self.assertIn(nom, INSTALL[INSTALL.index("FICHIERS_CODE=("):].split(")")[0])
            self.assertRegex(INSTALL, r'chmod 755 [^\n]*"\$INSTALL_DIR/%s"' % re.escape(nom))

    def test_argv1_sont_des_commandes_root_du_cli(self):
        for action in self.actions.values():
            argv1 = self.annotation(action, "argv1")
            if argv1:
                bloc = CLI[CLI.index(f"    {argv1})"):]
                self.assertIn("_need_root", bloc[:200])

    def test_l_interface_appelle_exactement_ces_actions(self):
        """Chemin ou argument différent : pkexec retomberait sur l'invite
        générique « exécuter … en superutilisateur »."""
        appels = set(re.findall(r'privilegie\("([\w.-]+)"(?:, "(\w+)" if actif else "(\w+)")?\)',
                                MODELE))
        attendus = set()
        for programme, a, b in appels:
            attendus |= {(programme, a), (programme, b)} if a else {(programme, None)}
        declares = {(self.annotation(x, "path").rsplit("/", 1)[1], self.annotation(x, "argv1"))
                    for x in self.actions.values()}
        self.assertEqual(attendus, declares)

    def test_message_en_francais(self):
        for ident, action in self.actions.items():
            langues = {m.get("{http://www.w3.org/XML/1998/namespace}lang")
                       for m in action.iter("message")}
            for code in ("fr", "es", "de", "it", "pt"):
                self.assertIn(code, langues, f"{ident} : invite sans {code}")
            self.assertIn(None, langues, f"{ident} : message par défaut manquant")

    def test_rien_sans_mot_de_passe(self):
        for ident, action in self.actions.items():
            for d in action.iter("defaults"):
                for regle in d:
                    self.assertIn(regle.text, ("auth_admin", "auth_admin_keep"), ident)


class InstallationPolkitTest(unittest.TestCase):

    def test_installe_depuis_les_sources_et_par_le_paquet(self):
        for cible in ("/usr/share/polkit-1/rules.d/50-katakomba.rules",
                      "/usr/share/polkit-1/actions/org.katakomba.policy"):
            self.assertIn(cible, INSTALL)
            self.assertIn(cible.lstrip("/"), (ROOT / "packaging" / "build-deb.sh").read_text())
            self.assertIn(cible, (ROOT / "uninstall.sh").read_text())

    def test_lanceur_nomme_comme_l_application(self):
        """GNOME n'affiche les notifications que si le lanceur porte
        l'identifiant de l'application."""
        self.assertIn('DESKTOP_FILE="/usr/share/applications/org.katakomba.Katakomba.desktop"',
                      INSTALL)
        self.assertTrue((ROOT / "packaging" / "org.katakomba.Katakomba.desktop").is_file())
        self.assertIn("rm -f /usr/share/applications/katakomba.desktop", INSTALL,
                      "l'ancien lanceur ferait doublon dans le menu")
        self.assertIn("X-GNOME-UsesNotifications=true",
                      (ROOT / "packaging" / "org.katakomba.Katakomba.desktop").read_text())


if __name__ == "__main__":
    unittest.main()
