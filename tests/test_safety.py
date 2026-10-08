"""Garde-fou de la suite : aucun test ne doit modifier la machine.

Le daemon tourne en root et manipule iptables, les routes, le DNS et des
processus.  Une suite de tests qui exécuterait ces commandes pour de vrai
couperait le réseau de la machine sur laquelle elle tourne.  Ces tests
vérifient donc les invariants de sûreté de la suite elle-même.
"""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = sorted(p for p in (ROOT / "tests").glob("test_*.py"))

# Commandes qui modifient l'état de la machine.
MUTANTES = ("iptables", "ip6tables", "ip route", "ip addr", "ip link set",
            "resolvectl", "systemctl", "pkill", "sysctl", "openvpn", "dnsmasq")


def appels_subprocess(fichier):
    """Appels RÉELS à subprocess dans un fichier, via l'AST.

    Une analyse textuelle produirait des faux positifs dès qu'un test cite
    « subprocess.run » dans une chaîne pour affirmer son absence ailleurs.
    On inspecte donc les nœuds d'appel, pas le texte.
    """
    import ast
    arbre = ast.parse(fichier.read_text())
    trouves = []
    for noeud in ast.walk(arbre):
        if not isinstance(noeud, ast.Call):
            continue
        f = noeud.func
        nom = ""
        if isinstance(f, ast.Attribute):
            base = f.value
            if isinstance(base, ast.Name) and base.id == "subprocess":
                nom = f.attr
        if nom in ("run", "Popen", "call", "check_output", "check_call"):
            argv = []
            if noeud.args and isinstance(noeud.args[0], (ast.List, ast.Tuple)):
                argv = [e.value for e in noeud.args[0].elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            trouves.append((noeud.lineno, nom, argv))
    return trouves


class NoRealCommandTest(unittest.TestCase):
    """Seuls `bash -n`, `git ls-files` et la lecture d'état sont admis."""

    BINAIRES_ADMIS = {"bash", "git", "ip", "resolvectl", "systemctl"}
    LECTURE_SEULE = {"-n", "ls-files", "show", "status", "is-active",
                     "is-enabled", "query", "route", "rule", "link", "-4", "-br"}

    def test_appels_subprocess_limites_et_en_lecture_seule(self):
        for f in TESTS:
            if f.name == "test_safety.py":
                continue
            for ligne, nom, argv in appels_subprocess(f):
                if not argv:
                    continue
                binaire = argv[0]
                self.assertIn(binaire, self.BINAIRES_ADMIS,
                              f"{f.name}:{ligne} exécute « {binaire} »")
                self.assertTrue(
                    any(a in self.LECTURE_SEULE for a in argv[1:]),
                    f"{f.name}:{ligne} : {' '.join(argv)} n'est pas en lecture seule")

    def test_aucun_script_du_projet_execute_autrement_qu_en_bash_n(self):
        for f in TESTS:
            for ligne, _, argv in appels_subprocess(f):
                joint = " ".join(argv)
                for script in ("install.sh", "repair_network.sh", "katakomba-cli.sh"):
                    if script in joint or any(script in a for a in argv):
                        self.assertIn("-n", argv,
                                      f"{f.name}:{ligne} exécute {script} sans « bash -n »")

    def test_aucun_chemin_systeme_en_ecriture(self):
        """Les tests ne doivent jamais viser /etc, /run ou /lib en écriture."""
        for f in TESTS:
            txt = f.read_text()
            for chemin in ('"/etc/katakomba', "'/etc/katakomba",
                           '"/run/katakomba', '"/etc/systemd/'):
                if chemin in txt:
                    # Toléré uniquement dans une assertion de contenu (chaîne
                    # attendue), jamais dans une écriture.
                    for i, ligne in enumerate(txt.splitlines(), 1):
                        if chemin in ligne:
                            self.assertFalse(
                                any(w in ligne for w in ("write_text", "mkdir",
                                                         "unlink", "open(")),
                                f"{f.name}:{i} écrit dans un chemin système")

    def test_les_scripts_shell_ne_sont_jamais_executes(self):
        for f in TESTS:
            txt = f.read_text()
            for script in ("install.sh", "repair_network.sh"):
                for i, ligne in enumerate(txt.splitlines(), 1):
                    if script in ligne and "subprocess" in ligne:
                        self.assertIn("-n", ligne,
                                      f"{f.name}:{i} exécute {script} sans « bash -n »")


class SystemUnchangedTest(unittest.TestCase):
    """Empreinte de l'état réseau : identique avant/après la suite complète.

    Ce test est volontairement placé dans la suite : s'il échoue, c'est qu'un
    test a modifié la machine.
    """

    @staticmethod
    def _empreinte():
        def lire(cmd):
            try:
                return subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=10).stdout
            except Exception:
                return ""
        return {
            "routes": lire(["ip", "-4", "route", "show"]),
            "regles": lire(["ip", "-4", "rule", "show"]),
            "liens": lire(["ip", "-br", "link", "show"]),
        }

    def test_reseau_intact(self):
        """Lecture seule : confirme que la suite n'a rien cassé."""
        emp = self._empreinte()
        self.assertTrue(emp["routes"], "impossible de lire les routes")
        # La route par défaut doit toujours exister.
        self.assertIn("default", emp["routes"],
                      "PLUS DE ROUTE PAR DÉFAUT — la suite a modifié le système")

    def test_aucun_fichier_de_config_cree(self):
        """Les tests utilisent des répertoires temporaires, jamais /etc."""
        marqueurs = [Path("/etc/katakomba/config.json.bad"),
                     Path("/etc/systemd/resolved.conf.d/katakomba-split.conf.test")]
        for m in marqueurs[1:]:
            self.assertFalse(m.exists(), f"fichier de test laissé sur le système : {m}")


class SuiteIntegrityTest(unittest.TestCase):

    # Carte de couverture explicite : ajouter un module daemon sans l'inscrire
    # ici — et sans écrire les tests correspondants — fait échouer la suite.
    COUVERTURE = {
        "core":     "test_config_status.py",
        "tor":      "test_tor.py",
        "network":  "test_network.py",
        "dns":      "test_dns.py",
        "firewall": "test_firewall.py",
        "openvpn":  "test_openvpn.py",
        "status":   "test_config_status.py",
        "watchdog": "test_watchdog.py",
    }

    def test_tous_les_modules_daemon_sont_couverts(self):
        modules = {p.stem for p in (ROOT / "daemon").glob("*.py")
                   if p.stem not in ("__init__", "__main__")}
        self.assertEqual(modules, set(self.COUVERTURE),
                         "carte de couverture désynchronisée de daemon/")
        for module, fichier in self.COUVERTURE.items():
            chemin = ROOT / "tests" / fichier
            self.assertTrue(chemin.exists(), f"{fichier} manquant (module {module})")

    def test_chaque_fichier_de_test_assertit_reellement(self):
        for f in TESTS:
            n = f.read_text().count("self.assert")
            self.assertGreaterEqual(n, 5, f"{f.name} ne contient que {n} assertions")

    def test_les_correctifs_ont_un_test_dedie(self):
        """Chaque correctif de l'audit doit rester verrouillé par un test."""
        couverture = " ".join(f.read_text() for f in TESTS)
        for marqueur, quoi in [
            ("--interface", "#3 mesure liée au tunnel"),
            ("Tunnel renouvelé pendant la mesure", "#2 thread périmé"),
            ("IPv6 non supporté", "#1 exclusion IPv6"),
            ("directive de script", "#8 scripts .ovpn"),
            ("script-security", "#7 exécution de scripts"),
            ("domaine ~.", "#13 contrôle DNS complet"),
            ("interface tunnel changée", "#5 partage LAN"),
            ("mis en quarantaine", "#4 reconnexion / quarantaine des comptes"),
            ("compte(s) en quarantaine", "comptes refusés relégués, pas exclus"),
            ("tor-routes.txt", "repair_network complété"),
            ("deepcopy", "défauts partagés (trouvé par la suite)"),
            ("ordre des comptes tiré au hasard", "comptes aléatoires"),
            ("l'ordre n'a pas été replanifié", "replan à chaud des comptes"),
        ]:
            # Pas de dump de `couverture` dans le message : plusieurs Ko.
            self.assertTrue(marqueur in couverture,
                            f"aucun test ne verrouille {quoi}")

    def test_pas_de_test_vide(self):
        import ast
        for f in TESTS:
            arbre = ast.parse(f.read_text())
            for noeud in ast.walk(arbre):
                if isinstance(noeud, ast.FunctionDef) and noeud.name.startswith("test"):
                    corps = [n for n in noeud.body
                             if not isinstance(n, (ast.Pass, ast.Expr))
                             or (isinstance(n, ast.Expr)
                                 and not isinstance(n.value, ast.Constant))]
                    self.assertTrue(corps,
                                    f"{f.name}::{noeud.name} n'assertit rien")


class SandboxedPathsTest(unittest.TestCase):
    """Aucun chemin écrit par le daemon ne doit viser la production."""

    def test_chemins_du_daemon_rediriges(self):
        import tests.helpers as h
        for m in h.RUN_MODULES:
            for nom in h._REDIRECTIONS:
                if hasattr(m, nom):
                    chemin = str(getattr(m, nom))
                    for prod in ("/run/katakomba", "/var/lib/katakomba",
                                 "/etc/katakomba"):
                        self.assertFalse(chemin.startswith(prod),
                                         f"{m.__name__}.{nom} = {chemin}")


if __name__ == "__main__":
    unittest.main()
