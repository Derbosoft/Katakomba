"""Scripts shell et unité systemd : syntaxe, complétude du nettoyage, cohérence.

Aucun script n'est EXÉCUTÉ : on vérifie leur syntaxe (bash -n) et leur contenu.
Lancer install.sh ou repair_network.sh couperait le réseau de la machine.
"""

import fnmatch
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
REPAIR = (ROOT / "repair_network.sh").read_text()
CLI = (ROOT / "katakomba-cli.sh").read_text()


class SyntaxTest(unittest.TestCase):

    def test_syntaxe_bash(self):
        for nom in ("install.sh", "repair_network.sh", "katakomba-cli.sh",
                    "uninstall.sh", "packaging/build-deb.sh",
                    "packaging/postinst", "packaging/prerm", "packaging/postrm"):
            r = subprocess.run(["bash", "-n", str(ROOT / nom)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{nom} : {r.stderr}")

    def test_python_compile(self):
        import py_compile
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            fichiers = ([ROOT / "constants.py", ROOT / "main.py",
                         ROOT / "validation.py", ROOT / "adaptation.py"]
                        + sorted((ROOT / "daemon").glob("*.py"))
                        + sorted((ROOT / "gui").glob("*.py")))
            for f in fichiers:
                py_compile.compile(str(f), cfile=f"{tmp}/x.pyc", doraise=True)


class RepairCompletenessTest(unittest.TestCase):
    """repair_network.sh doit annuler TOUT ce que le daemon installe."""

    def test_chaines_ip6tables(self):
        self.assertIn("KATAKOMBA_KS6", REPAIR)
        self.assertIn("KATAKOMBA_KS6_FWD", REPAIR)
        self.assertRegex(REPAIR, r"while ip6tables -D FORWARD -j \"?\$\{?KS6_FWD_CHAIN")

    def test_chaine_lan_et_nat(self):
        self.assertIn("KATAKOMBA_LAN_FWD", REPAIR)
        self.assertIn("MASQUERADE", REPAIR,
                      "la règle NAT du partage LAN n'est pas nettoyée")

    def test_routes_32_des_relais_tor(self):
        self.assertIn("tor-routes.txt", REPAIR,
                      "les routes /32 des relais Tor ne sont pas supprimées")
        self.assertRegex(REPAIR, r'ip route del "\$\{?IP\}?/32"')

    def test_traite_tun0_et_tun1(self):
        """Les .ovpn utilisent « dev tun » : le tunnel peut être tun0 ou tun1."""
        self.assertIn("TUNS=(tun0 tun1)", REPAIR)
        for bloc in ("resolvectl revert", "ip route del 0.0.0.0/1"):
            self.assertIn(bloc, REPAIR)
        self.assertGreaterEqual(REPAIR.count('for T in "${TUNS[@]}"'), 3,
                                "la boucle sur les deux tunnels manque quelque part")

    def test_dropin_dns_supprime(self):
        self.assertIn("katakomba-split.conf", REPAIR)

    def test_dnsmasq_cible_par_pid_file(self):
        """« pkill dnsmasq » tuerait aussi ceux de libvirt."""
        self.assertIn("pkill -f /run/katakomba/dnsmasq.pid", REPAIR)
        self.assertNotRegex(REPAIR, r"pkill\s+(-x\s+)?dnsmasq\s*$")

    def test_numerotation_des_etapes_coherente(self):
        etapes = re.findall(r"\[(\d+)/(\d+)\]", REPAIR)
        self.assertTrue(etapes, "aucune étape numérotée")
        total = etapes[0][1]
        self.assertTrue(all(t == total for _, t in etapes),
                        f"totaux incohérents : {etapes}")
        self.assertEqual([n for n, _ in etapes],
                         [str(i) for i in range(1, int(total) + 1)],
                         "numéros d'étapes non consécutifs")

    def test_mode_internal_saute_le_systemctl_stop(self):
        self.assertIn("--internal", REPAIR)
        self.assertRegex(REPAIR, r"if \[\[ \$INTERNAL -eq 0 \]\]")

    def test_exige_root(self):
        self.assertIn("EUID", REPAIR)

    def test_set_euo_pipefail(self):
        self.assertIn("set -euo pipefail", REPAIR)


class InstallServiceUnitTest(unittest.TestCase):
    """L'unité systemd porte la chaîne de survie : Type=notify + WatchdogSec."""

    def test_type_notify_et_watchdog(self):
        self.assertIn("Type=notify", INSTALL)
        self.assertIn("NotifyAccess=main", INSTALL)
        self.assertIn("WatchdogSec=90", INSTALL)

    def test_relance_illimitee(self):
        self.assertIn("Restart=on-failure", INSTALL)
        self.assertIn("StartLimitIntervalSec=0", INSTALL,
                      "sans cela, une série d'échecs au boot laisse le service mort")

    def test_watchdog_plus_long_que_le_pas_de_ping(self):
        """Les pings sortent toutes les ~3 s : 90 s laisse une marge confortable."""
        w = int(re.search(r"WatchdogSec=(\d+)", INSTALL).group(1))
        self.assertGreaterEqual(w, 30)

    def test_nettoyage_avant_et_apres(self):
        self.assertIn("ExecStartPre=", INSTALL)
        self.assertIn("ExecStopPost=", INSTALL)

    def test_cleanup_traite_les_deux_tunnels(self):
        cleanup = INSTALL[INSTALL.index("CLEANUP_EOF"):]
        self.assertIn("-o tun0 -j MASQUERADE", cleanup)
        self.assertIn("-o tun1 -j MASQUERADE", cleanup)

    def test_cleanup_purge_en_boucle(self):
        """Des crashs répétés peuvent empiler plusieurs jumps identiques."""
        self.assertIn("while ip6tables -D OUTPUT", INSTALL)
        self.assertIn("while iptables  -D FORWARD", INSTALL)

    def test_hook_de_reveil(self):
        """« restart » démarrait aussi un service arrêté exprès."""
        self.assertIn("system-sleep", INSTALL)
        hook = INSTALL[INSTALL.index("SLEEP_EOF"):]
        hook = hook[:hook.index("SLEEP_EOF", 10)]
        self.assertIn("systemctl try-restart katakomba", hook)
        self.assertNotIn("systemctl restart", hook)

    def test_pas_de_relance_sans_fournisseur(self):
        self.assertIn("RestartPreventExitStatus=78", INSTALL)

    def test_repertoire_d_execution_prive(self):
        self.assertIn("RuntimeDirectory=katakomba", INSTALL)
        self.assertIn("RuntimeDirectoryMode=0700", INSTALL)

    def test_durcissement_de_l_unite(self):
        for directive in ("NoNewPrivileges=yes", "ProtectHome=yes",
                          "ProtectSystem=full", "PrivateTmp=yes"):
            self.assertIn(directive, INSTALL)
        # ProtectSystem=full rend /etc en lecture seule : le daemon y écrit
        # sa config et le drop-in DNS.
        self.assertRegex(INSTALL, r"ReadWritePaths=\$CONFIG_DIR .*resolved\.conf\.d")


    def test_tor_systeme_desactive(self):
        """Sinon conflit sur le port 9050."""
        self.assertIn("systemctl disable tor", INSTALL)

    def test_groupe_katakomba_et_permissions(self):
        self.assertIn("groupadd -f katakomba", INSTALL)
        self.assertIn("chmod 2770", INSTALL)

    def test_dnsmasq_optionnel(self):
        """Ne doit plus être installé systématiquement pour être désactivé."""
        deps = re.search(r"apt-get install -y ([^\n]+)", INSTALL).group(1)
        self.assertNotIn("dnsmasq", deps,
                         "dnsmasq est encore dans les dépendances obligatoires")
        self.assertNotIn("dnsutils", deps, "dnsutils n'est utilisé nulle part")
        self.assertIn("command -v dnsmasq", INSTALL)

    def test_dnsmasq_absent_n_est_pas_un_echec(self):
        bloc = INSTALL[INSTALL.index("── Vérification"):]
        self.assertNotRegex(bloc, r"for bin in [^\n]*dnsmasq")

    def test_skip_apt_verifie_avant_de_sauter(self):
        """Rejouable sans réseau, mais jamais sur une machine incomplète.

        Sauter apt sur une machine à laquelle il manque des paquets produirait
        une installation à moitié fonctionnelle, plus dure à diagnostiquer
        qu'un échec franc."""
        self.assertIn("KATAKOMBA_SKIP_APT", INSTALL)
        bloc = INSTALL[INSTALL.index("KATAKOMBA_SKIP_APT"):
                       INSTALL.index("[2/7]")]
        self.assertIn("command -v", bloc, "aucune vérification des binaires")
        self.assertIn("gui_disponible", bloc, "interface graphique non vérifiée")
        self.assertIn("exit 1", bloc, "n'échoue pas quand une dépendance manque")

    def test_aucun_apt_get_hors_garde(self):
        """Chaque appel à apt doit être atteignable seulement sans le garde."""
        for i, ligne in enumerate(INSTALL.splitlines(), 1):
            if "apt-get" not in ligne or ligne.strip().startswith("#"):
                continue
            # Contexte : les 12 lignes précédentes doivent porter le garde.
            debut = max(0, i - 13)
            contexte = "\n".join(INSTALL.splitlines()[debut:i])
            self.assertIn("KATAKOMBA_SKIP_APT", contexte,
                          f"install.sh:{i} appelle apt hors du garde : {ligne.strip()}")

    def test_torrc_par_defaut_non_ecrase(self):
        # « absent » : ni fichier, ni lien symbolique (même pendant).
        self.assertIn('if absent "$TORRC_FILE"', INSTALL)

    def test_torrc_par_defaut_complet(self):
        for cle in ("SocksPort 9050", "ControlPort 9051",
                    "CookieAuthentication 1", "DataDirectory"):
            self.assertIn(cle, INSTALL, f"{cle} absent du torrc par défaut")


class CliTest(unittest.TestCase):

    def test_commandes_privilegiees_exigent_root(self):
        for cmd in ("start", "stop", "restart", "enable", "disable"):
            bloc = CLI[CLI.index(f"    {cmd})"):]
            self.assertIn("_need_root", bloc[:200], f"« {cmd} » ne vérifie pas root")

    def test_lecture_sans_root(self):
        for cmd in ("status", "logs", "follow", "ip"):
            bloc = CLI[CLI.index(f"    {cmd})"):]
            self.assertNotIn("_need_root", bloc[:150], f"« {cmd} » exige root sans raison")

    def test_gui_lance_sans_root(self):
        bloc = CLI[CLI.index("    gui)"):]
        bloc = bloc[:bloc.index("\n        ;;\n")]
        self.assertNotIn("_need_root", bloc)
        self.assertIn("exec python3", bloc)

    def test_gui_transmet_seulement_arriere_plan(self):
        """Lancement à l'ouverture de session : « katakomba gui
        --arriere-plan » arrive jusqu'à main.py ; toute autre option est
        refusée (le CLI ne relaie pas n'importe quoi à Python)."""
        bloc = CLI[CLI.index("    gui)"):CLI.index("    autoriser)")]
        filtre = bloc[bloc.index('for a in "${@:2}"'):bloc.index("done")]
        self.assertIn("--arriere-plan) OPTS+=", filtre)
        self.assertIn("*) echo \"Option inconnue", filtre)
        self.assertIn("exit 2", filtre)
        self.assertIn('exec python3 "$DAEMON_DIR/main.py" "${OPTS[@]}"', bloc)
        self.assertIn("main.py' ${OPTS[*]}\"", bloc, "options perdues via sg")
        self.assertNotIn('"$@"', bloc[bloc.index("done"):], "arguments relayés sans filtre")


class VersionCoherenceTest(unittest.TestCase):

    def test_version_identique_partout(self):
        import sys
        sys.path.insert(0, str(ROOT))
        from constants import VERSION
        for nom in ("README.md", "README.fr.md"):
            txt = (ROOT / nom).read_text()
            self.assertIn(f"# Katakomba — v{VERSION}", txt,
                          f"titre de {nom} désynchronisé de constants.py")
            self.assertIn(f"Version-{VERSION}-blue", txt,
                          f"badge de {nom} désynchronisé")

    def test_jamais_script_security_2_documente(self):
        """La doc ne doit jamais montrer le niveau 2 dans la commande."""
        for nom in ("README.md", "README.fr.md"):
            txt = (ROOT / nom).read_text()
            bloc = txt[txt.index("openvpn\n  --config"):]
            bloc = bloc[:bloc.index("```")]
            self.assertNotIn("--script-security 2", bloc,
                             f"{nom} documente --script-security 2 dans la commande")

    def test_script_security_1_impose_apres_config(self):
        """Le niveau 1 doit être IMPOSÉ, et après --config.

        Ne pas passer l'option du tout ne suffisait pas : le .ovpn peut
        déclarer « script-security 2 » lui-même, et OpenVPN la prend.  Vérifié
        empiriquement — seule une occurrence en ligne de commande placée APRÈS
        --config reprend la main.  C'est donc la POSITION qui fait la sécurité,
        d'où ce test sur l'ordre et pas seulement sur la présence."""
        code = (ROOT / "daemon" / "openvpn.py").read_text()
        self.assertIn('"--script-security",   "1"', code,
                      "le niveau 1 n'est plus imposé en ligne de commande")
        self.assertNotIn('"--script-security",   "2"', code,
                         "niveau 2 réintroduit dans argv")
        i_conf = code.index('"--config",            conf_run')
        i_sec  = code.index('"--script-security",   "1"')
        self.assertGreater(i_sec, i_conf,
                           "--script-security doit venir APRÈS --config, sinon "
                           "le fichier reprend la main")


def _fichiers_suivis():
    """Fichiers suivis par git, ou None si la question n'a pas de sens ici.

    La suite doit pouvoir tourner sur une machine DÉPLOYÉE après une mise à
    jour — c'est tout son intérêt.  Or `git` y est souvent absent, et le
    répertoire d'installation n'est pas un dépôt.  Un test qui plante dans ce
    cas rend la suite inutilisable là où elle sert le plus."""
    if not shutil.which("git"):
        return None
    r = subprocess.run(["git", "ls-files"], cwd=ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:          # hors dépôt
        return None
    return r.stdout.splitlines()


class GitignoreTest(unittest.TestCase):
    """Les secrets ne doivent pas pouvoir être committés par accident."""

    def test_ignore_les_donnees_personnelles(self):
        ign_path = ROOT / ".gitignore"
        if not ign_path.exists():
            self.skipTest("pas de .gitignore (installation déployée)")
        ign = ign_path.read_text()
        for motif in ("providers/*/", "auth.tmp", "id.txt", "__pycache__/"):
            self.assertIn(motif, ign, f"{motif} n'est pas ignoré")

    def test_aucun_ovpn_ni_config_suivi_par_git(self):
        """La règle garde tout son sens DANS un dépôt : un .ovpn contient des
        certificats.  Hors dépôt, elle n'a simplement pas d'objet."""
        suivis = _fichiers_suivis()
        if suivis is None:
            self.skipTest("git absent ou hors dépôt (installation déployée)")
        for f in suivis:
            self.assertFalse(f.startswith("providers/") and f.endswith(".ovpn"),
                             f"fichier .ovpn personnel suivi par git : {f}")
            self.assertNotEqual(f, "config.json")
            self.assertFalse(f.endswith("auth.tmp"), f)


class DoctorCommandTest(unittest.TestCase):
    """« katakomba doctor » : diagnostic en lecture seule, sans root."""

    def test_commande_presente_et_documentee(self):
        self.assertIn("    doctor)", CLI)
        bloc = CLI[CLI.index("help|--help"):]
        self.assertIn("doctor", bloc, "doctor absent de l'aide")

    def test_n_exige_pas_root(self):
        """Doit rester lançable par l'utilisateur, sans invite de mot de passe.

        « sudo » peut apparaître dans un CONSEIL affiché (« sudo katakomba
        restart ») : on vérifie donc l'absence d'INVOCATION privilégiée, pas
        l'absence du mot."""
        bloc = CLI[CLI.index("    doctor)"):]
        bloc = bloc[:bloc.index("    logs)")]
        self.assertNotIn("_need_root", bloc)
        self.assertNotIn("pkexec", bloc)
        for invocation in ('sh("sudo"', '"sudo",', 'subprocess.run(["sudo'):
            self.assertNotIn(invocation, bloc, f"doctor invoque sudo : {invocation}")

    def test_aucune_commande_mutante(self):
        """Un diagnostic ne doit RIEN modifier sur la machine."""
        bloc = CLI[CLI.index("    doctor)"):]
        bloc = bloc[:bloc.index("    logs)")]
        for interdit in ('"iptables"', '"ip6tables"', '"pkill"', '"sysctl"',
                         '"restart"', '"stop"', '"start"',
                         '"route", "add"', '"route", "del"',
                         '"addr", "add"', '"addr", "flush"'):
            self.assertNotIn(interdit, bloc,
                             f"doctor exécute une commande mutante : {interdit}")

    def test_verifie_les_invariants_attendus(self):
        bloc = CLI[CLI.index("    doctor)"):]
        bloc = bloc[:bloc.index("    logs)")]
        for sonde, quoi in [
            ("is-active", "état du service"),
            ("katakomba.sock", "état du daemon"),
            ("tor_ready", "bootstrap Tor"),
            ("last_circuit_kbs", "qualité du circuit"),
            ("accounts_cooldown", "comptes en quarantaine"),
            ("route", "route par défaut et guards /32"),
            ("scope", "piège scope-link"),
            ("resolvectl", "DNS du tunnel"),
            ("~.", "domaine catch-all"),
            ("Default Route", "default-route du tunnel"),
            ("ipv6_blocked", "blocage IPv6"),
            ("api.ipify.org", "sortie Internet réelle"),
            ("--interface", "sortie liée au tunnel"),
        ]:
            self.assertIn(sonde, bloc, f"doctor ne vérifie pas : {quoi}")

    def test_code_de_sortie_non_nul_si_probleme(self):
        bloc = CLI[CLI.index("    doctor)"):]
        self.assertIn("publier(conclusion, 1 if n_ko else (2 if en_cours else 0))", bloc)
        self.assertIn("sys.exit(code)", bloc)

    def test_reconnexion_en_cours_reconnue(self):
        """Pendant une reconnexion voulue, pas de faux KO ni de « restart »."""
        bloc = CLI[CLI.index("    doctor)"):]
        bloc = bloc[:bloc.index("    logs)")]
        self.assertIn('st.get("reconnect_reason"', bloc)
        self.assertIn("bas < RECONNEXION_MAX", bloc)
        for titre in ("Redirection du trafic", "DNS du tunnel",
                      "Chemin des requêtes DNS", "Sortie Internet",
                      "Protection des guards Tor"):
            self.assertIn(f'note(REPORTE, _("{titre}"), NON_VERIFIE)', bloc,
                          f"« {titre} » compté en panne pendant une reconnexion")
        verdict = bloc[bloc.index("# ── Verdict"):]
        self.assertLess(verdict.index("if en_cours:"), verdict.index("elif n_ko:"),
                        "le conseil « restart » interromprait la reconnexion")

    def test_reconnexion_trop_longue_reste_une_panne(self):
        bloc = CLI[CLI.index("    doctor)"):]
        self.assertIn('note(KO, _("Tunnel"), _("fermé{depuis}{cause}")', bloc)

    def test_interface_uplink_non_codee_en_dur(self):
        """Le nom de l'interface varie d'une machine à l'autre."""
        bloc = CLI[CLI.index("    doctor)"):]
        bloc = bloc[:bloc.index("    logs)")]
        self.assertNotIn('"eth0"', bloc, "nom d'interface codé en dur")
        self.assertIn('champs.index("dev")', bloc,
                      "l'uplink devrait être dérivé de la route par défaut")

    def test_sortie_json_pour_l_interface(self):
        """L'interface lit --json : aucun découpage en colonnes, que des
        titres traduits (plus longs en allemand) casseraient."""
        bloc = CLI[CLI.index("    doctor)"):CLI.index("    logs)")]
        self.assertIn('python3 - "$DAEMON_DIR" "${@:2}"', bloc)
        self.assertIn('JSON = "--json" in sys.argv[2:]', bloc)
        self.assertIn("json.dumps({\"resultats\"", bloc)

    def test_diagnostic_traduit_mais_autonome(self):
        """Traductions absentes (ancienne installation) : le diagnostic
        tourne quand même, en français."""
        bloc = CLI[CLI.index("    doctor)"):CLI.index("    logs)")]
        self.assertIn("i18n.activer(os.environ.get(\"KATAKOMBA_LANGUE\", \"\"))", bloc)
        self.assertIn("except Exception:\n    _ = lambda s: s", bloc)

    def test_statut_affiche_la_qualite_du_circuit(self):
        bloc = CLI[CLI.index("    status)"):CLI.index("    doctor)")]
        self.assertIn("last_circuit_kbs", bloc)
        self.assertIn("last_circuit_age", bloc)

class DeploymentTest(unittest.TestCase):
    """Le service root ne doit exécuter que du code modifiable par root seul."""

    def test_service_lance_depuis_opt(self):
        self.assertIn('INSTALL_DIR="/opt/katakomba"', INSTALL)
        self.assertIn("WorkingDirectory=$INSTALL_DIR", INSTALL)
        self.assertNotIn("WorkingDirectory=$SCRIPT_DIR", INSTALL,
                         "le service exécuterait le clone de l'utilisateur")

    def test_code_appartient_a_root(self):
        self.assertIn('chown -R root:root "$INSTALL_DIR"', INSTALL)

    def test_tous_les_modules_deployes(self):
        bloc = INSTALL[INSTALL.index("FICHIERS_CODE=("):]
        bloc = bloc[:bloc.index(")")]
        for f in ("constants.py", "main.py", "validation.py", "adaptation.py",
                  "daemon", "gui",
                  "repair_network.sh", "katakomba-cli.sh"):
            self.assertIn(f, bloc, f"{f} non déployé")

    def test_cli_n_utilise_plus_install_dir(self):
        """Fichier remplaçable par le groupe katakomba : il ne doit pas désigner
        le code exécuté (« sudo katakomba gui »)."""
        self.assertNotIn("$(cat /etc/katakomba/install_dir", CLI)
        self.assertIn('DAEMON_DIR="/opt/katakomba"', CLI)

    def test_ecritures_root_sans_lien_symbolique(self):
        self.assertIn("absent()", INSTALL)
        self.assertIn('if absent "$TORRC_FILE"', INSTALL)

    def test_torrc_par_defaut_accepte_par_le_daemon(self):
        import sys
        sys.path.insert(0, str(ROOT))
        from validation import analyser_torrc
        bloc = INSTALL[INSTALL.index("<< 'TORRC_EOF'") + len("<< 'TORRC_EOF'"):]
        bloc = bloc[:bloc.index("TORRC_EOF")]
        self.assertEqual(analyser_torrc(bloc), [])


class NoBroadKillTest(unittest.TestCase):
    """Jamais « pkill -x openvpn/tor » : un autre VPN, Tor Browser."""

    def test_scripts(self):
        for nom, txt in (("repair_network.sh", REPAIR), ("install.sh", INSTALL)):
            code = "\n".join(l for l in txt.splitlines()
                              if not l.lstrip().startswith("#"))
            self.assertNotRegex(code, r"pkill\s+-x\s+(openvpn|tor)\b", nom)

    def test_daemon(self):
        for f in sorted((ROOT / "daemon").glob("*.py")):
            code = f.read_text()
            self.assertNotIn('"pkill", "-x"', code, f.name)
            self.assertNotIn('"pgrep", "-x"', code, f.name)


PAQ = ROOT / "packaging"
UNINSTALL = (ROOT / "uninstall.sh").read_text()


def _liste_bash(texte, nom):
    """Éléments d'un tableau bash « nom=( … ) » (sur plusieurs lignes)."""
    bloc = texte[texte.index(f"{nom}=(") + len(nom) + 2:]
    return bloc[:bloc.index(")")].split()


class PaquetDebTest(unittest.TestCase):
    """Paquet .deb : même installation que depuis les sources."""

    def test_memes_fichiers_que_l_installation_depuis_les_sources(self):
        self.assertEqual(_liste_bash(INSTALL, "FICHIERS_CODE"),
                         _liste_bash((PAQ / "build-deb.sh").read_text(), "FICHIERS_CODE"))

    def test_tous_les_modules_python_sont_livres(self):
        """Chaque module de premier niveau importé par le daemon ou le GUI
        doit être livré — sinon l'installation démarre puis plante."""
        import re
        livres = _liste_bash(INSTALL, "FICHIERS_CODE")
        sources = list((ROOT / "daemon").glob("*.py")) + list((ROOT / "gui").glob("*.py")) \
            + [ROOT / "main.py"]
        for f in sources:
            for mod in re.findall(r"^\s*(?:from|import)\s+(\w+)", f.read_text(), re.M):
                if (ROOT / f"{mod}.py").exists():
                    self.assertIn(f"{mod}.py", livres, f"{mod}.py (importé par {f.name}) absent")
        for f in ("install.sh", "uninstall.sh"):
            self.assertIn(f, livres)

    def test_postinst_reutilise_install_sh(self):
        post = (PAQ / "postinst").read_text()
        self.assertIn("KATAKOMBA_PAQUET=1 bash /opt/katakomba/install.sh", post)
        self.assertIn("try-restart", post, "une mise à jour doit relancer le daemon actif")

    def test_prerm_ne_desinstalle_pas_sur_mise_a_jour(self):
        prerm = (PAQ / "prerm").read_text()
        self.assertIn("uninstall.sh --paquet", prerm)
        bloc = prerm[prerm.index("case"):]
        self.assertNotIn("upgrade)", bloc)

    def test_postrm_efface_seulement_sur_purge(self):
        postrm = (PAQ / "postrm").read_text()
        self.assertIn("purge)", postrm)
        self.assertNotIn("remove)", postrm)

    def test_dependances(self):
        control = (PAQ / "control.in").read_text()
        depends = next(l for l in control.splitlines() if l.startswith("Depends:"))
        for dep in ("python3-gi", "python3-gi-cairo", "gir1.2-gtk-4.0", "gir1.2-adw-1 (>= 1.5)",
                    "tor", "openvpn", "curl", "iptables",
                    "systemd-resolved", "pkexec"):
            self.assertIn(dep, depends)
        self.assertIn("Architecture: all", control)

    def test_mode_paquet_n_ecrit_pas_dans_usr_local(self):
        bloc = INSTALL[INSTALL.index('if [ "$PAQUET" = "1" ]; then\n    # Un paquet'):]
        bloc = bloc[:bloc.index("fi")]
        self.assertIn('CLI_BIN="/usr/bin/katakomba"', bloc)
        self.assertIn("/usr/lib/katakomba/", bloc)

    def test_lanceur_du_paquet(self):
        desktop = (PAQ / "org.katakomba.Katakomba.desktop").read_text()
        self.assertIn("Exec=/usr/bin/katakomba gui", desktop)

    def test_ancien_cli_retire_s_il_est_le_notre(self):
        self.assertIn('grep -qs "Katakomba — CLI wrapper" /usr/local/bin/katakomba',
                      INSTALL)
        self.assertIn("# Katakomba — CLI wrapper", CLI)


class DesinstallationTest(unittest.TestCase):

    def test_reglages_conserves_sans_purge(self):
        bloc = UNINSTALL[UNINSTALL.index('if [ "$PAQUET" = "0" ]'):]
        bloc = bloc[:bloc.index('if [ "$PURGE" = "1" ]; then\n    echo')]
        self.assertIn("! -name providers", bloc, "les fournisseurs seraient effacés")
        self.assertNotIn("/etc/katakomba", bloc)

    def test_purge_efface_tout(self):
        bloc = UNINSTALL[UNINSTALL.index('if [ "$PURGE" = "1" ]; then\n    echo'):]
        for chemin in ("/etc/katakomba", "/var/lib/katakomba", "providers"):
            self.assertIn(chemin, bloc)

    def test_nettoyage_reseau_avant_retrait(self):
        self.assertLess(UNINSTALL.index("katakomba-cleanup.sh; do"),
                        UNINSTALL.index("rm -f /etc/systemd/system/katakomba.service"))

    def test_cli_renvoie_vers_apt_si_installe_par_paquet(self):
        bloc = CLI[CLI.index("    uninstall|desinstaller)"):]
        self.assertIn("dpkg-query", bloc)
        self.assertIn("apt remove katakomba", bloc)


class AccesGuiTest(unittest.TestCase):
    """Un débutant ne doit jamais rester bloqué sur une erreur de droits."""

    def test_commande_autoriser(self):
        bloc = CLI[CLI.index("    autoriser)"):]
        self.assertIn("usermod -aG katakomba", bloc[:bloc.index(";;")])

    def test_interface_refusee_en_root(self):
        """GTK en root : pas d'accès à l'écran Wayland, et aucune utilité."""
        bloc = CLI[CLI.index("    gui)"):CLI.index("    autoriser)")]
        self.assertLess(bloc.index('if [ "$EUID" -eq 0 ]'), bloc.index("exec python3"))

    def test_sg_seulement_s_il_existe(self):
        """Absent d'Ubuntu 26.04 : ne jamais l'appeler à l'aveugle."""
        bloc = CLI[CLI.index("    gui)"):CLI.index("    autoriser)")]
        self.assertIn("command -v sg", bloc)

    def test_message_distingue_session_et_absence_d_acces(self):
        app = (ROOT / "gui" / "app.py").read_text()
        self.assertIn("fermez votre session", app)
        self.assertIn("sudo katakomba autoriser", app)


def _bloc_migration():
    debut = INSTALL.index("# ── Migration : Tor-VPN Manager → Katakomba")
    return INSTALL[debut:INSTALL.index("# ── [1/7]", debut)]


class MigrationTest(unittest.TestCase):
    """Reprise d'une installation « Tor-VPN Manager » (v3.7.0 et avant)."""

    def test_migration_avant_toute_installation(self):
        m = INSTALL.index("# ── Migration : Tor-VPN Manager → Katakomba")
        self.assertLess(m, INSTALL.index("groupadd -f katakomba"),
                        "le groupe doit être renommé avant d'être créé")
        self.assertLess(m, INSTALL.index('mkdir -p "$CONFIG_DIR"'))
        self.assertLess(INSTALL.index("absent() {"), m)

    def test_ancien_service_arrete_avant_deplacement(self):
        bloc = _bloc_migration()
        self.assertLess(bloc.index("systemctl disable --now tor-vpn-manager"),
                        bloc.index('mv "$ANCIEN" "$NOUVEAU"'))

    def test_groupe_renomme_gid_conserve(self):
        self.assertIn("groupmod -n katakomba torvpn", _bloc_migration())

    def test_repertoires_repris_sans_ecraser(self):
        bloc = _bloc_migration()
        for paire in ('"/etc/tor-vpn-manager:$CONFIG_DIR"',
                      '"/var/lib/tor-vpn-manager:$STATE_DIR"'):
            self.assertIn(paire, bloc)
        self.assertIn('absent "$NOUVEAU"', bloc)
        self.assertIn("cp -a -n /opt/tor-vpn-manager/providers/.", bloc)

    def test_reecriture_sans_suivre_les_liens(self):
        bloc = _bloc_migration()
        self.assertIn("os.O_NOFOLLOW", bloc)
        self.assertIn("O_EXCL", bloc)

    def test_ancien_cli_retire_seulement_s_il_est_le_notre(self):
        bloc = _bloc_migration()
        self.assertIn('grep -qs "Tor-VPN Manager — CLI wrapper" /usr/local/bin/tor-vpn',
                      bloc)

    def test_anciens_fichiers_systeme_retires(self):
        bloc = _bloc_migration()
        for f in ("/etc/systemd/system/tor-vpn-manager.service",
                  "/lib/systemd/system-sleep/tor-vpn-sleep",
                  "/etc/systemd/resolved.conf.d/tor-vpn-split.conf",
                  "/usr/share/applications/tor-vpn-gui.desktop"):
            self.assertIn(f, bloc)

    def test_ancien_code_retire_apres_reprise_de_la_config(self):
        self.assertLess(INSTALL.index('"/opt/tor-vpn-manager"; do'),
                        INSTALL.index("    rm -rf /opt/tor-vpn-manager\n"))

    def test_service_relance_s_il_tournait(self):
        self.assertIn("systemctl is-active tor-vpn-manager &>/dev/null && ANCIEN_ACTIF=true",
                      _bloc_migration())
        self.assertIn('if [ "$ANCIEN_ACTIF" = true ]; then\n    systemctl start katakomba',
                      INSTALL)

    def test_paquet_remplace_l_ancien(self):
        control = (ROOT / "packaging" / "control.in").read_text()
        self.assertIn("Conflicts: tor-vpn-manager", control)
        self.assertIn("Replaces: tor-vpn-manager", control)


class NomUniformeTest(unittest.TestCase):
    """Plus d'ancien nom dans le code, hors migration et compatibilité."""

    _ANCIEN = re.compile(r"tor-vpn|torvpn|tor_vpn|Tor-VPN|TORVPN|\.tvpn")

    def test_aucun_ancien_nom_hors_migration(self):
        migration = _bloc_migration()
        tolere = ("tor-vpn-dnsmasq.pid",          # pid d'avant la v3.7.0
                  ".tvpn",                        # anciennes sauvegardes importables
                  ": tor-vpn-manager")            # Conflicts/Replaces du paquet
        # Scripts locaux de l'utilisateur, ignorés par git : hors projet.
        ignores = [l.strip().lstrip("/") for l in
                   (ROOT / ".gitignore").read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
        restes = []
        for f in sorted(ROOT.rglob("*")):
            rel = f.relative_to(ROOT)
            if (not f.is_file() or rel.parts[0] in ("dist", "tests", "assets", "providers")
                    or any(p.startswith(".") for p in rel.parts)
                    or any(fnmatch.fnmatch(str(rel), m) for m in ignores)
                    or "__pycache__" in rel.parts or f.suffix == ".md"):
                continue
            for n, ligne in enumerate(f.read_text(errors="replace").splitlines(), 1):
                if not self._ANCIEN.search(ligne) or any(t in ligne for t in tolere):
                    continue
                if f.name == "install.sh" and (ligne in migration
                                               or "/opt/tor-vpn-manager" in ligne
                                               or ".config/tor-vpn-manager" in ligne):
                    continue
                restes.append(f"{rel}:{n}: {ligne.strip()}")
        self.assertEqual(restes, [], "\n".join(restes))


class LogoTest(unittest.TestCase):

    def test_icones_livrees(self):
        for f in ("katakomba.svg", "katakomba-32.png", "katakomba-48.png",
                  "katakomba-128.png"):
            self.assertTrue((ROOT / "assets" / f).is_file(), f)
        self.assertIn("assets", _liste_bash(INSTALL, "FICHIERS_CODE"))

    def test_lanceurs_utilisent_l_icone(self):
        for texte in (INSTALL, (PAQ / "org.katakomba.Katakomba.desktop").read_text()):
            self.assertIn("Icon=katakomba\n", texte)
            # Identifiant de l'application GTK : c'est lui que GNOME compare
            # (Wayland) pour rattacher la fenêtre à son lanceur et à l'icône.
            self.assertIn("StartupWMClass=org.katakomba.Katakomba", texte)
        self.assertIn('APP_ID = "org.katakomba.Katakomba"',
                      (ROOT / "gui" / "app.py").read_text())
        self.assertIn("usr/share/icons/hicolor/scalable/apps/katakomba.svg",
                      (ROOT / "packaging" / "build-deb.sh").read_text())


if __name__ == "__main__":
    unittest.main()
