"""Configuration en console (console.py), pour un serveur sans interface.

Mêmes règles que l'interface graphique : les commandes passent par
gui/modele.py et validation.py.  Chemins redirigés vers un répertoire
temporaire, état du service simulé : rien ne touche la machine."""

import contextlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
import zipfile

import console
from gui import modele

OVPN = "client\ndev tun\nproto tcp\nremote vpn.example 443\n<ca>\nX\n</ca>\n"


class Console(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self._tmp.name)
        (self.base / "etc").mkdir()
        self._sauve = {n: getattr(modele, n) for n in
                       ("CONFIG_DIR", "CONFIG_FILE", "TORRC_FILE", "PROVIDERS_DIR",
                        "SCRIPT_DIR", "etat_service")}
        modele.CONFIG_DIR = self.base / "etc"
        modele.CONFIG_FILE = self.base / "etc" / "config.json"
        modele.TORRC_FILE = self.base / "etc" / "torrc"
        modele.PROVIDERS_DIR = self.base / "providers"
        modele.PROVIDERS_DIR.mkdir()
        modele.SCRIPT_DIR = self.base
        modele.etat_service = lambda: "inactive"
        # Messages vérifiés dans la langue source, quelle que soit celle du
        # système (anglais sur la CI).  « fr » = textes tels quels, l'état
        # par défaut d'i18n : rien à restaurer.
        self._langue = os.environ.get("KATAKOMBA_LANGUE")
        os.environ["KATAKOMBA_LANGUE"] = "fr"
        self._umask = os.umask(0o022)
        self.ovpn = self.base / "ivpn.ovpn"
        self.ovpn.write_text(OVPN)

    def tearDown(self):
        for n, v in self._sauve.items():
            setattr(modele, n, v)
        if self._langue is None:
            os.environ.pop("KATAKOMBA_LANGUE", None)
        else:
            os.environ["KATAKOMBA_LANGUE"] = self._langue
        os.umask(self._umask)
        self._tmp.cleanup()

    def lancer(self, *args, entree=None):
        """(code, sortie, erreurs) de « katakomba <args> »."""
        out, err = io.StringIO(), io.StringIO()
        stdin = sys.stdin
        sys.stdin = io.StringIO(entree) if entree is not None else io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = console.main(list(args))
        finally:
            sys.stdin = stdin
        return code, out.getvalue(), err.getvalue()

    def config(self):
        return json.loads(modele.CONFIG_FILE.read_text())

    def ajouter(self, nom="ivpn", identifiants="bob\ns3cret\n"):
        return self.lancer("provider", "add", str(self.ovpn), "--name", nom, "--stdin",
                           entree=identifiants)


class FournisseurTest(Console):

    def test_ajout_complet(self):
        code, sortie, err = self.ajouter()
        self.assertEqual(code, 0, err)
        p = self.config()["providers"][0]
        self.assertEqual(p["name"], "ivpn")
        self.assertEqual(p["ovpn_file"], "providers/ivpn/ivpn.ovpn")
        self.assertEqual(modele.deobf(p["accounts"][0]["u"]), "bob")
        self.assertEqual(modele.deobf(p["accounts"][0]["p"]), "s3cret")
        self.assertTrue((modele.PROVIDERS_DIR / "ivpn" / "ivpn.ovpn").exists())
        self.assertIn("1 serveur", sortie, "résumé de l'adaptation absent")
        self.assertIn("sudo katakomba start", sortie)

    def test_fichiers_lisibles_par_le_groupe_seulement(self):
        """L'interface (groupe katakomba, sans root) doit pouvoir les relire."""
        self.ajouter()
        for f in (modele.CONFIG_FILE, modele.PROVIDERS_DIR / "ivpn" / "ivpn.ovpn"):
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o660, f.name)

    def test_mot_de_passe_jamais_en_argument(self):
        """Il serait visible de tous dans la liste des processus."""
        code, _, err = self.lancer("provider", "add", str(self.ovpn), "--password", "x")
        self.assertEqual(code, 1)
        self.assertIn("--password", err)
        self.assertFalse(modele.CONFIG_FILE.exists())

    def test_sans_terminal_ni_stdin_refuse(self):
        code, _, err = self.lancer("provider", "add", str(self.ovpn))
        self.assertEqual(code, 1)
        self.assertIn("--stdin", err)
        self.assertFalse(modele.CONFIG_FILE.exists(), "fournisseur ajouté sans identifiants")

    def test_ovpn_dangereux_neutralise(self):
        """Comme dans l'interface : la ligne est retirée (en commentaire),
        signalée dans le résumé, et le fichier écrit passe les contrôles du
        daemon."""
        self.ovpn.write_text(OVPN + "plugin /tmp/x.so\n")
        code, sortie, _ = self.ajouter()
        self.assertEqual(code, 0)
        self.assertIn("plugin /tmp/x.so", sortie)
        ecrit = (modele.PROVIDERS_DIR / "ivpn" / "ivpn.ovpn").read_text()
        self.assertFalse([l for l in ecrit.splitlines() if l.startswith("plugin")])
        self.assertEqual(modele.analyser_ovpn(ecrit)[0], [])

    def test_fichier_illisible(self):
        code, _, err = self.lancer("provider", "add", str(self.base / "absent.ovpn"),
                                   "--stdin", entree="bob\nx\n")
        self.assertEqual(code, 1)
        self.assertIn("absent.ovpn", err)
        self.assertFalse(modele.CONFIG_FILE.exists())

    def test_nom_refuse(self):
        for nom in ("../etc", ".cache", "a/b"):
            code, _, _ = self.ajouter(nom=nom)
            self.assertEqual(code, 1, nom)
        self.ajouter()
        code, _, err = self.ajouter(nom="IVPN")
        self.assertEqual(code, 1)
        self.assertIn("existe déjà", err)

    def test_liste_priorite_retrait(self):
        self.ajouter("a")
        self.ajouter("b")
        code, sortie, _ = self.lancer("provider", "list")
        self.assertLess(sortie.index("1. a"), sortie.index("2. b"))
        self.assertEqual(self.lancer("provider", "priority", "b", "1")[0], 0)
        self.assertEqual([p["name"] for p in self.config()["providers"]], ["b", "a"])
        self.assertEqual(self.lancer("provider", "priority", "b", "9")[0], 1)
        code, sortie, _ = self.lancer("provider", "remove", "A")
        self.assertEqual(code, 0)
        self.assertEqual([p["name"] for p in self.config()["providers"]], ["b"])
        self.assertTrue((modele.PROVIDERS_DIR / "a" / "ivpn.ovpn").exists(),
                        "le fichier reste sur le disque, comme dans l'interface")

    def test_inconnu(self):
        code, _, err = self.lancer("provider", "remove", "nope")
        self.assertEqual(code, 1)
        self.assertIn("nope", err)

    def test_equivalents_francais(self):
        code, _, err = self.lancer("fournisseur", "ajouter", str(self.ovpn), "--stdin",
                                   entree="bob\nx\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.lancer("fournisseur", "liste")[0], 0)

    def test_sans_droit_d_ecriture(self):
        """Message clair AVANT de demander un mot de passe."""
        os.chmod(modele.CONFIG_DIR, 0o500)
        try:
            if os.access(modele.CONFIG_DIR, os.W_OK):
                self.skipTest("lancé en root : les droits ne s'appliquent pas")
            code, _, err = self.ajouter()
        finally:
            os.chmod(modele.CONFIG_DIR, 0o700)
        self.assertEqual(code, 1)
        self.assertIn("katakomba autoriser", err)


class CompteTest(Console):

    def test_ajout_et_retrait(self):
        self.ajouter()
        code, _, err = self.lancer("account", "add", "ivpn", "--stdin", entree="alice\npw\n")
        self.assertEqual(code, 0, err)
        code, sortie, _ = self.lancer("account", "list", "ivpn")
        self.assertIn("1. bob", sortie)
        self.assertIn("2. alice", sortie)
        self.assertNotIn("pw", sortie, "mot de passe affiché")
        self.assertEqual(self.lancer("account", "remove", "ivpn", "3")[0], 1)
        self.assertEqual(self.lancer("account", "remove", "ivpn", "1")[0], 0)
        comptes = self.config()["providers"][0]["accounts"]
        self.assertEqual([modele.deobf(c["u"]) for c in comptes], ["alice"])

    def test_stdin_incomplet(self):
        self.ajouter()
        code, _, err = self.lancer("account", "add", "ivpn", "--stdin", entree="seul\n")
        self.assertEqual(code, 1)
        self.assertEqual(len(self.config()["providers"][0]["accounts"]), 1)


class ExclusionTest(Console):

    def test_reseau_et_domaine(self):
        self.assertEqual(self.lancer("exclude", "add", "192.168.50.10")[0], 0)
        self.assertEqual(self.lancer("exclude", "add", "Intranet.Example.org")[0], 0)
        cfg = self.config()
        self.assertEqual(cfg["excluded_ips"], ["192.168.50.10/32"])
        self.assertEqual(cfg["excluded_domains"], [".intranet.example.org"])
        code, sortie, _ = self.lancer("exclude", "list")
        self.assertIn("192.168.50.10/32", sortie)
        self.assertEqual(self.lancer("exclude", "remove", "192.168.50.10")[0], 0)
        self.assertEqual(self.config()["excluded_ips"], [])

    def test_memes_refus_que_l_interface(self):
        for valeur, motif in (("8.0.0.0/8", "trop large"), ("2001:db8::/32", "IPv6"),
                              ("pas un domaine!", "valide")):
            code, _, err = self.lancer("exclude", "add", valeur)
            self.assertEqual(code, 1, valeur)
            self.assertIn(motif, err, valeur)
        self.assertFalse(modele.CONFIG_FILE.exists())

    def test_exclusion_publique_signalee(self):
        _, sortie, _ = self.lancer("exclude", "add", "203.0.113.7")
        self.assertIn("adresse réelle", sortie)
        _, sortie, _ = self.lancer("exclude", "add", "10.1.2.3")
        self.assertNotIn("adresse réelle", sortie)


class ReglageTest(Console):

    def test_liste_et_modification(self):
        code, sortie, _ = self.lancer("set")
        self.assertIn("kill-switch       on", sortie)
        self.assertEqual(self.lancer("set", "kill-switch", "off")[0], 0)
        self.assertIs(self.config()["kill_switch"], False)
        self.assertEqual(self.lancer("set", "local-dns", "192.168.1.1")[0], 0)
        self.assertEqual(self.config()["local_dns"], "192.168.1.1")
        self.assertEqual(self.lancer("set", "local-dns", "none")[0], 0)
        self.assertEqual(self.config()["local_dns"], "")

    def test_valeurs_refusees(self):
        for args in (("kill-switch", "peut-etre"), ("circuit-retries", "50"),
                     ("circuit-min-kbs", "x"), ("local-dns", "pas-une-ip"),
                     ("inconnu", "1")):
            code, _, _ = self.lancer("set", *args)
            self.assertEqual(code, 1, args)
        self.assertFalse(modele.CONFIG_FILE.exists())

    def test_desactiver_le_blocage_avertit(self):
        _, sortie, _ = self.lancer("set", "kill-switch", "off")
        self.assertIn("à découvert", sortie)


class SauvegardeTest(Console):

    def test_aller_retour(self):
        self.ajouter()
        self.lancer("exclude", "add", "10.1.2.3")
        zip_ = self.base / "sauvegarde.zip"
        code, sortie, _ = self.lancer("backup", "export", str(zip_))
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(zip_.stat().st_mode), 0o600,
                         "identifiants lisibles par d'autres")
        self.assertIn("identifiants", sortie)
        with zipfile.ZipFile(zip_) as zf:
            self.assertIn("providers/ivpn/ivpn.ovpn", zf.namelist())
        modele.CONFIG_FILE.unlink()
        code, sortie, err = self.lancer("sauvegarde", "restaurer", str(zip_))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["providers"][0]["name"], "ivpn")
        self.assertEqual(self.config()["excluded_ips"], ["10.1.2.3/32"])

    def test_export_n_ecrase_rien(self):
        cible = self.base / "existant.zip"
        cible.write_text("x")
        self.assertEqual(self.lancer("backup", "export", str(cible))[0], 1)
        self.assertEqual(cible.read_text(), "x")

    def test_fichier_qui_n_est_pas_une_sauvegarde(self):
        faux = self.base / "faux.zip"
        faux.write_text("pas un zip")
        code, _, err = self.lancer("backup", "restore", str(faux))
        self.assertEqual(code, 1)
        self.assertIn("sauvegarde", err)


class AideTest(Console):

    def test_aide_traduite_jusqu_aux_parametres(self):
        """Commandes identiques, paramètres dans la langue de l'utilisateur."""
        import i18n
        os.environ["KATAKOMBA_LANGUE"] = "en"
        try:
            _, sortie, _ = self.lancer("help")
            _, _, err = self.lancer("provider", "remove")
        finally:
            i18n.activer("fr")
        self.assertIn("provider remove <name>", sortie)
        self.assertIn("start [--trial [MIN]]", sortie)
        self.assertNotIn("fichier", sortie.split("French equivalents")[0])
        self.assertIn("Usage: katakomba provider remove <name>", err)

    def test_aide_complete(self):
        code, sortie, _ = self.lancer("help")
        self.assertEqual(code, 0)
        for commande in ("start", "--essai", "confirm", "provider", "account", "exclude",
                         "set", "backup", "doctor", "status", "logs"):
            self.assertIn(commande, sortie)

    def test_commande_inconnue(self):
        self.assertEqual(self.lancer("nimporte")[0], 2)


# ── WireGuard (v4.0.0) ───────────────────────────────────────────────────────

import base64 as _b64                                          # noqa: E402

CLE = _b64.b64encode(bytes(32)).decode()
CONF = (f"[Interface]\nPrivateKey = {CLE}\n"
        "Address = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n"
        f"PublicKey = {_b64.b64encode(bytes(range(32))).decode()}\n"
        "AllowedIPs = 0.0.0.0/0\nEndpoint = 185.107.56.211:51820\n")


class WireGuardConsoleTest(Console):

    def setUp(self):
        super().setUp()
        self.conf = self.base / "nl-153.conf"
        self.conf.write_text(CONF)

    def ajouter_wg(self, nom="proton"):
        return self.lancer("provider", "add", str(self.conf), "--name", nom)

    def test_fournisseur_wireguard_sans_identifiants(self):
        code, sortie, err = self.ajouter_wg()
        self.assertEqual(code, 0, err)
        p = self.config()["providers"][0]
        self.assertEqual(p["wireguard"], [{"conf": "providers/proton/nl-153.conf"}])
        self.assertEqual(p["accounts"], [])
        self.assertIn("Proton (TLS) · 185.107.56.211:443", sortie, "résumé absent")
        self.assertNotIn(CLE, sortie + err, "clé affichée")

    def test_conf_refuse_avant_toute_ecriture(self):
        self.conf.write_text(CONF.replace("185.107.56.211", "vpn.example"))
        code, _, err = self.ajouter_wg()
        self.assertEqual(code, 1)
        self.assertIn("Endpoint", err)
        self.assertFalse((modele.PROVIDERS_DIR / "proton").exists())

    def test_types_meles_refuses(self):
        code, _, err = self.lancer("provider", "add", str(self.conf), str(self.ovpn))
        self.assertEqual(code, 1)
        self.assertIn("Un seul type", err)

    def test_openvpn_en_conf_reste_openvpn(self):
        ovpn_conf = self.base / "ivpn.conf"
        ovpn_conf.write_text(OVPN)
        code, _, err = self.lancer("provider", "add", str(ovpn_conf), "--name", "ivpn",
                                   "--stdin", entree="bob\ns3cret\n")
        self.assertEqual(code, 0, err)
        p = self.config()["providers"][0]
        self.assertTrue(p["ovpn_file"])
        self.assertNotIn("wireguard", p)

    def test_wireguard_ajoute_a_un_fournisseur_openvpn(self):
        self.ajouter()                                  # OpenVPN, « ivpn »
        code, sortie, err = self.lancer("account", "add", "ivpn", str(self.conf))
        self.assertEqual(code, 0, err)
        self.assertIn("1 fichier WireGuard ajouté", sortie)
        code, sortie, _ = self.lancer("account", "list", "ivpn")
        self.assertIn("1. bob", sortie)
        self.assertIn("wg1. nl-153.conf", sortie)
        self.assertNotIn(CLE, sortie)
        code, sortie, _ = self.lancer("provider", "list")
        self.assertIn("1 compte OpenVPN · 1 fichier WireGuard", sortie)

    def test_retrait_d_un_conf(self):
        self.ajouter_wg()
        second = self.base / "ch-12.conf"
        second.write_text(CONF.replace("185.107.56.211", "185.1.2.3"))
        self.lancer("account", "add", "proton", str(second))
        self.assertEqual(self.lancer("account", "remove", "proton", "wg3")[0], 1)
        code, _, err = self.lancer("account", "remove", "proton", "wg1")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["providers"][0]["wireguard"],
                         [{"conf": "providers/proton/ch-12.conf"}])

    def test_reglage_des_transports(self):
        code, sortie, err = self.lancer("set", "transports", "openvpn,wireguard")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["transports"], ["openvpn", "wireguard"])
        self.assertEqual(self.lancer("set", "transports", "ssh")[0], 1)
        self.assertEqual(self.lancer("set", "transports", "wireguard,wireguard")[0], 1)
        _, sortie, _ = self.lancer("set")
        self.assertIn("openvpn,wireguard", sortie)

    def test_ordre_d_un_fournisseur(self):
        self.ajouter()                                  # OpenVPN, « ivpn »
        self.lancer("account", "add", "ivpn", str(self.conf))
        code, sortie, err = self.lancer("provider", "transports", "IVPN", "openvpn,wireguard")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["providers"][0]["transports"], ["openvpn", "wireguard"])
        self.assertNotIn("qu'un transport", sortie)
        _, sortie, _ = self.lancer("provider", "list")
        self.assertIn("[openvpn,wireguard]", sortie)
        self.assertEqual(self.lancer("provider", "transports", "ivpn", "ssh")[0], 1)
        self.assertEqual(self.config()["providers"][0]["transports"], ["openvpn", "wireguard"])
        code, sortie, err = self.lancer("fournisseur", "transports", "ivpn", "default")
        self.assertEqual(code, 0, err)
        self.assertNotIn("transports", self.config()["providers"][0])
        self.assertIn("suit le réglage général (wireguard,openvpn)", sortie)

    def test_ordre_d_un_fournisseur_a_un_seul_transport(self):
        self.ajouter_wg()
        code, sortie, err = self.lancer("provider", "transports", "proton", "openvpn")
        self.assertEqual(code, 0, err)
        self.assertIn("qu'un transport", sortie)

    def test_wireguard_gere(self):
        self.ajouter()                                  # « ivpn », un compte
        code, sortie, err = self.lancer("provider", "wg-auto", "ivpn", "on")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["providers"][0]["wg_auto"]["service"], "ivpn")
        code, sortie, err = self.lancer("provider", "wg-auto", "ivpn", "countries", "nl,ch")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config()["providers"][0]["wg_auto"]["countries"], ["NL", "CH"])
        self.assertEqual(self.lancer("provider", "wg-auto", "ivpn", "countries", "NLD")[0], 1)
        code, sortie, _ = self.lancer("provider", "wg-auto", "ivpn", "reserved", "on")
        self.assertIn("remis à zéro", sortie)
        self.assertTrue(self.config()["providers"][0]["wg_auto"]["reserved_accounts"])
        _, sortie, _ = self.lancer("provider", "list")
        self.assertIn("WireGuard géré", sortie)
        self.lancer("provider", "wg-auto", "ivpn", "countries", "all")
        self.assertEqual(self.config()["providers"][0]["wg_auto"]["countries"], [])
        self.assertEqual(self.lancer("provider", "wg-auto", "ivpn", "off")[0], 0)
        self.assertNotIn("wg_auto", self.config()["providers"][0])

    def test_wireguard_gere_refuse(self):
        self.ajouter("proton")
        code, _, err = self.lancer("provider", "wg-auto", "proton", "on")
        self.assertEqual(code, 1)
        self.assertIn("ne ressemble pas à IVPN", err)
        code, _, err = self.lancer("provider", "wg-auto", "proton", "reserved", "on")
        self.assertIn("Activez d'abord", err)
        self.ajouter_wg("ivpn-wg")                     # sans compte
        code, _, err = self.lancer("provider", "wg-auto", "ivpn-wg", "on")
        self.assertIn("numéros de compte", err)

    def test_sauvegarde_emporte_les_conf(self):
        self.ajouter_wg()
        zip_ = self.base / "s.zip"
        self.assertEqual(self.lancer("backup", "export", str(zip_))[0], 0)
        with zipfile.ZipFile(zip_) as zf:
            self.assertIn("providers/proton/nl-153.conf", zf.namelist())


if __name__ == "__main__":
    unittest.main()
