"""Logique de l'interface (gui/modele.py) : saisies, torrc, sauvegardes,
fournisseurs, état affiché.  Aucune bibliothèque graphique n'est chargée."""

import copy
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

from constants import DEFAULT_CONFIG, OBSOLETE_CONFIG_KEYS
from gui import modele


class Bac(unittest.TestCase):
    """Chemins du modèle redirigés vers un répertoire temporaire."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self._tmp.name)
        self.base = base
        self._sauve = {n: getattr(modele, n) for n in
                       ("CONFIG_FILE", "TORRC_FILE", "PROVIDERS_DIR", "SCRIPT_DIR")}
        modele.CONFIG_FILE = base / "config.json"
        modele.TORRC_FILE = base / "torrc"
        modele.PROVIDERS_DIR = base / "providers"
        modele.SCRIPT_DIR = base

    def tearDown(self):
        for n, v in self._sauve.items():
            setattr(modele, n, v)
        self._tmp.cleanup()


class GuiSansGtkTest(unittest.TestCase):

    def test_modele_n_importe_aucune_bibliotheque_graphique(self):
        self.assertNotIn("gi.repository.Gtk", sys.modules.get("gui.modele").__dict__)
        src = pathlib.Path(modele.__file__).read_text()
        for interdit in ("import gi", "from gi", "tkinter"):
            self.assertNotIn(interdit, src)


class ObfuscationTest(unittest.TestCase):

    def test_aller_retour(self):
        for clair in ("bob", "p@ssw0rd!", "üñïçødé", "", "x" * 500, "a b\tc"):
            self.assertEqual(modele.deobf(modele.obf(clair)), clair)

    def test_deobf_tolere_une_valeur_en_clair(self):
        self.assertEqual(modele.deobf("!!!pas-base64!!!"), "!!!pas-base64!!!")

    def test_obfuscation_n_est_pas_du_chiffrement(self):
        """Documenté comme tel : le test fige cette limite connue."""
        import base64
        self.assertEqual(base64.b64decode(modele.obf("secret")).decode(), "secret")


class ExclusionIpTest(unittest.TestCase):
    """L'interface doit refuser l'IPv6, qu'OpenVPN ignorerait."""

    def test_ipv4_simple_normalisee_en_32(self):
        self.assertEqual(modele.normaliser_ip("10.0.0.5"), ("10.0.0.5/32", ""))

    def test_cidr_accepte(self):
        self.assertEqual(modele.normaliser_ip("10.0.20.0/24")[0], "10.0.20.0/24")

    def test_cidr_avec_bits_hote_normalise(self):
        self.assertEqual(modele.normaliser_ip("10.0.20.7/24")[0], "10.0.20.0/24")

    def test_ipv6_refusee(self):
        net, err = modele.normaliser_ip("2001:db8::/32")
        self.assertEqual(net, "", "une entrée IPv6 a été acceptée")
        self.assertIn("IPv6", err)

    def test_ipv6_simple_refusee(self):
        self.assertEqual(modele.normaliser_ip("fe80::1")[0], "")

    def test_saisie_invalide_refusee(self):
        net, err = modele.normaliser_ip("pas-une-ip")
        self.assertEqual(net, "")
        self.assertIn("valide", err)

    def test_saisie_vide_ignoree_sans_erreur(self):
        self.assertEqual(modele.normaliser_ip("   "), ("", ""))

    def test_masque_hors_bornes_refuse(self):
        self.assertEqual(modele.normaliser_ip("10.0.0.0/33")[0], "")

    def test_domaine_normalise(self):
        self.assertEqual(modele.normaliser_domaine("Internal"), ".internal")
        self.assertEqual(modele.normaliser_domaine("..lan"), ".lan")
        self.assertEqual(modele.normaliser_domaine("  "), "")


class SaisieTest(unittest.TestCase):
    """Les réglages invalides sont signalés au lieu d'être ignorés."""

    def _cfg(self, **v):
        return {**copy.deepcopy(DEFAULT_CONFIG), **v}

    def test_valeurs_par_defaut_valides(self):
        self.assertEqual(modele.erreurs_config(self._cfg()), [])

    def test_dns_local_invalide(self):
        self.assertTrue(modele.erreurs_config(self._cfg(local_dns="192.168.50")))

    def test_seuil_de_circuit_non_numerique(self):
        self.assertTrue(modele.erreurs_config(self._cfg(circuit_min_kbs="abc")))

    def test_essais_hors_bornes(self):
        self.assertTrue(modele.erreurs_config(self._cfg(circuit_max_retries=0)))

    def test_passerelle_hors_sous_reseau(self):
        self.assertTrue(modele.erreurs_config(
            self._cfg(lan_auto=True, lan_gateway="192.168.1.1")))

    def test_lan_non_verifie_si_partage_inactif(self):
        self.assertEqual(modele.erreurs_config(self._cfg(lan_gateway="x")), [])

    def test_erreurs_lan_directes(self):
        self.assertEqual(modele.erreurs_lan("10.0.0.1", "10.0.0.0/24"), [])
        self.assertTrue(modele.erreurs_lan("x", "10.0.0.0/24"))
        self.assertTrue(modele.erreurs_lan("10.0.0.1", "pas un réseau"))

    def test_cles_obsoletes_declarees(self):
        for cle in ("mode", "tor_min_speed_kbs", "speed_fail_count"):
            self.assertIn(cle, OBSOLETE_CONFIG_KEYS)


class ConfigFichierTest(Bac):

    def test_aller_retour(self):
        cfg = {**copy.deepcopy(DEFAULT_CONFIG), "local_dns": "10.0.0.53"}
        modele.enregistrer_config(cfg)
        self.assertEqual(modele.charger_config()["local_dns"], "10.0.0.53")
        self.assertEqual(modele.CONFIG_FILE.stat().st_mode & 0o777, 0o660)

    def test_absente_donne_les_defauts(self):
        self.assertEqual(modele.charger_config(), DEFAULT_CONFIG)

    def test_corrompue_mise_de_cote(self):
        modele.CONFIG_FILE.write_text("{pas du json")
        self.assertEqual(modele.charger_config(), DEFAULT_CONFIG)
        self.assertTrue((self.base / "config.json.bad").exists(),
                        "la config corrompue a été écrasée sans copie")

    def test_cles_obsoletes_retirees(self):
        modele.CONFIG_FILE.write_text(json.dumps({"mode": "x", "local_dns": ""}))
        self.assertNotIn("mode", modele.charger_config())

    def test_defauts_jamais_mutes(self):
        avant = copy.deepcopy(DEFAULT_CONFIG)
        cfg = modele.charger_config()
        cfg["providers"].append({"name": "x"})
        self.assertEqual(DEFAULT_CONFIG, avant)


class EcritureSansLienTest(Bac):
    """La console tourne parfois en root (serveur), dans des dossiers que le
    groupe katakomba peut modifier : aucune écriture ne suit un lien."""

    def setUp(self):
        super().setUp()
        self.victime = self.base / "victime"
        self.victime.write_text("intact")

    def test_lien_a_la_place_du_fichier_temporaire(self):
        (self.base / "config.json.tmp").symlink_to(self.victime)
        modele.enregistrer_config({"a": 1})
        self.assertEqual(self.victime.read_text(), "intact")
        self.assertEqual(json.loads(modele.CONFIG_FILE.read_text()), {"a": 1})

    def test_lien_a_la_place_du_fichier(self):
        """Remplacé par le renommage, jamais écrit à travers."""
        modele.CONFIG_FILE.symlink_to(self.victime)
        modele.enregistrer_config({"a": 1})
        self.assertEqual(self.victime.read_text(), "intact")
        self.assertFalse(modele.CONFIG_FILE.is_symlink())

    def test_lien_a_la_place_du_dossier_du_fournisseur(self):
        ailleurs = self.base / "ailleurs"
        ailleurs.mkdir()
        modele.PROVIDERS_DIR.mkdir()
        (modele.PROVIDERS_DIR / "vpn").symlink_to(ailleurs)
        f = self.base / "a.ovpn"
        f.write_text("client\ndev tun\nproto tcp\nremote a 443\n<ca>\nX\n</ca>\n")
        res, _ = modele.preparer_import([str(f)])
        with self.assertRaises(OSError):
            modele.ecrire_ovpn("vpn", res, [str(f)])
        self.assertEqual(list(ailleurs.iterdir()), [])

    def test_sauvegarde_ne_copie_pas_un_lien(self):
        """Un .ovpn remplacé par un lien vers un fichier système n'entre pas
        dans la sauvegarde."""
        (modele.PROVIDERS_DIR / "x").mkdir(parents=True)
        (modele.PROVIDERS_DIR / "x" / "x.ovpn").symlink_to(self.victime)
        modele.TORRC_FILE.symlink_to(self.victime)
        zip_ = self.base / "s.zip"
        modele.exporter({"providers": [{"name": "x", "ovpn_file": "providers/x/x.ovpn"}]}, zip_)
        with zipfile.ZipFile(zip_) as zf:
            self.assertEqual(zf.namelist(), ["config.json"])

    def test_droits_du_groupe_quel_que_soit_l_umask(self):
        import os
        ancien = os.umask(0o077)
        try:
            modele.enregistrer_config({})
        finally:
            os.umask(ancien)
        self.assertEqual(modele.CONFIG_FILE.stat().st_mode & 0o777, 0o660)


class DefaultConfigIntegrityTest(unittest.TestCase):

    def test_listes_par_defaut_vides(self):
        for cle in ("providers", "excluded_ips", "excluded_domains"):
            self.assertEqual(DEFAULT_CONFIG[cle], [])

    def test_seuil_de_circuit_par_defaut(self):
        self.assertEqual(DEFAULT_CONFIG["circuit_min_kbs"], 250)
        self.assertTrue(DEFAULT_CONFIG["circuit_check"])
        self.assertEqual(DEFAULT_CONFIG["circuit_max_retries"], 3)


    def test_blocage_hors_tunnel_actif_par_defaut(self):
        self.assertTrue(DEFAULT_CONFIG["kill_switch"])


class TuileIpv6Test(unittest.TestCase):

    def _ipv6(self, st):
        return next(t for t in modele.tuiles("active", st) if t["cle"] == "ipv6")

    def test_bloque_par_le_blocage_hors_tunnel(self):
        """Le blocage hors tunnel arrête aussi l'IPv6 : pas de fausse alerte."""
        self.assertEqual(self._ipv6({"tunnel_up": True, "kill_switch": True})["valeur"],
                         modele._("Bloqué"))

    def test_autorise_sans_aucun_blocage(self):
        self.assertEqual(self._ipv6({"tunnel_up": True})["valeur"], modele._("Autorisé"))


class ModeAvanceTest(unittest.TestCase):

    def cfg(self, **v):
        return {**copy.deepcopy(DEFAULT_CONFIG), **v}

    def test_nouvelle_installation_en_mode_simple(self):
        self.assertFalse(modele.mode_avance_initial(self.cfg()))

    def test_deduit_des_reglages_utilises(self):
        for k, v in (("excluded_ips", ["10.0.0.0/24"]), ("excluded_domains", [".lan"]),
                     ("local_dns", "10.0.0.53"), ("lan_auto", True),
                     ("lan_iface", "eth1"), ("circuit_min_kbs", 500),
                     ("circuit_check", False)):
            self.assertTrue(modele.mode_avance_initial(self.cfg(**{k: v})), k)

    def test_choix_explicite_respecte(self):
        self.assertFalse(modele.mode_avance_initial(
            self.cfg(advanced_mode=False, excluded_ips=["10.0.0.0/24"])))
        self.assertTrue(modele.mode_avance_initial(self.cfg(advanced_mode=True)))


class FournisseurTest(Bac):

    def test_noms(self):
        self.assertEqual(modele.verifier_nom("vpn-a", []), "")
        for mauvais in ("", "   ", ".", "..", "a/b", "..\\..", "/abs"):
            self.assertTrue(modele.verifier_nom(mauvais, []), f"« {mauvais} » accepté")
        self.assertTrue(modele.verifier_nom("VPN", [{"name": "vpn"}]),
                        "doublon insensible à la casse accepté")

    def test_nom_propose_depuis_le_fichier(self):
        self.assertEqual(modele.nom_depuis_fichier("/t/ivpn_config.zip"), "ivpn config")

    def test_nom_destination(self):
        self.assertEqual(modele.nom_destination("x", ["/t/fr.ovpn"]), "fr.ovpn")
        self.assertEqual(modele.nom_destination("Mon VPN", ["/t/a.zip"]), "Mon-VPN.ovpn")
        self.assertEqual(modele.nom_destination("v", ["/a.ovpn", "/b.ovpn"]), "v.ovpn")

    def test_preparation_depuis_un_fichier(self):
        f = self.base / "a.ovpn"
        f.write_text("client\ndev tun\nproto udp\nremote a 443\n"
                     "up /etc/openvpn/update-resolv-conf\n<ca>\nX\n</ca>\n")
        res, erreurs = modele.preparer_import([str(f)])
        self.assertEqual(erreurs, [])
        resume = modele.resume_adaptation(res)
        self.assertIn("1 serveur", resume)
        self.assertIn("update-resolv-conf", resume)
        self.assertIn("UDP", resume)

    def test_erreurs_de_lecture_remontees(self):
        res, erreurs = modele.preparer_import(["/inexistant/x.ovpn"])
        self.assertIsNone(res)
        self.assertTrue(erreurs)

    def test_ajout_par_l_assistant(self):
        f = self.base / "fr.ovpn"
        f.write_text("client\ndev tun\nproto tcp\nremote a 443\n<ca>\nX\n</ca>\n")
        res, _ = modele.preparer_import([str(f)])
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        modele.ajouter_fournisseur_adapte(cfg, "vpn", res, [str(f)], "bob", "s3cret")
        p = cfg["providers"][0]
        self.assertEqual(p["ovpn_file"], "providers/vpn/fr.ovpn")
        self.assertTrue((modele.PROVIDERS_DIR / "vpn" / "fr.ovpn").exists())
        self.assertEqual(modele.deobf(p["accounts"][0]["p"]), "s3cret")
        self.assertEqual(json.loads(modele.CONFIG_FILE.read_text())["providers"][0]["name"],
                         "vpn", "configuration non enregistrée")

    def test_deplacer(self):
        l = ["a", "b", "c"]
        self.assertEqual(modele.deplacer(l, 1, -1), 0)
        self.assertEqual(l, ["b", "a", "c"])
        self.assertEqual(modele.deplacer(l, 0, -1), 0, "sortie de la liste")
        self.assertEqual(modele.deplacer(l, 2, 1), 2)
        self.assertEqual(l, ["b", "a", "c"])


class TorrcTest(unittest.TestCase):
    """Les paramètres obligatoires doivent survivre à toute édition."""

    def test_defauts_contiennent_les_obligatoires(self):
        txt = modele.construire_torrc(modele.TOR_DEFAUTS)
        for cle in ("SocksPort 9050", "ControlPort 9051",
                    "CookieAuthentication 1", "DataDirectory"):
            self.assertIn(cle, txt)

    def test_valeurs_par_defaut_attendues(self):
        txt = modele.construire_torrc(modele.TOR_DEFAUTS)
        for ligne in ("AvoidDiskWrites 1", "SafeLogging 1", "ClientUseIPv6 0",
                      "TestSocks 1", "LongLivedPorts 1194,443",
                      "LearnCircuitBuildTimeout 0", "MaxCircuitDirtiness 3600",
                      "NumEntryGuards 3", "GuardLifetime 2 months"):
            self.assertIn(ligne, txt)

    def test_identique_au_torrc_d_installation(self):
        """install.sh et l'interface proposent les mêmes réglages par défaut."""
        install = (pathlib.Path(__file__).resolve().parents[1] / "install.sh").read_text()
        bloc = install[install.index("# === Paramètres personnalisés ==="):
                       install.index("TORRC_EOF", install.index("# === Paramètres personnalisés"))]
        for ligne in bloc.splitlines()[1:]:
            if ligne.strip():
                self.assertIn(ligne.strip(), modele.construire_torrc(modele.TOR_DEFAUTS))

    def test_conn_padding_desactive_par_defaut(self):
        self.assertNotIn("ConnectionPadding", modele.construire_torrc(modele.TOR_DEFAUTS))

    def test_valeur_zero_omise(self):
        txt = modele.construire_torrc({**modele.TOR_DEFAUTS, "max_dirty": 0})
        self.assertNotIn("MaxCircuitDirtiness", txt)

    def test_valeur_non_numerique_ignoree_sans_planter(self):
        txt = modele.construire_torrc({**modele.TOR_DEFAUTS, "keepalive": "abc"})
        self.assertNotIn("KeepalivePeriod", txt)

    def test_strict_nodes_seulement_avec_exclusion(self):
        self.assertNotIn("StrictNodes", modele.construire_torrc(modele.TOR_DEFAUTS))
        txt = modele.construire_torrc({**modele.TOR_DEFAUTS, "exclude_exits": "{us},{gb}",
                                       "strict_nodes": True})
        self.assertIn("ExcludeExitNodes {us},{gb}", txt)
        self.assertIn("StrictNodes 1", txt)

    def test_torrc_genere_accepte_par_le_daemon(self):
        from validation import analyser_torrc
        self.assertEqual(analyser_torrc(modele.construire_torrc(modele.TOR_DEFAUTS)), [])


class TorrcSyncTest(unittest.TestCase):
    """L'interface ne doit jamais effacer le torrc de l'utilisateur."""

    FICHIER = (modele.TORRC_OBLIGATOIRE
               + "AvoidDiskWrites 1\nNumEntryGuards 5\n"
               + "ExcludeNodes {ru}\nStrictNodes 1\nConnectionPadding 0\n"
               + "Bridge 192.0.2.1:443\n# note perso\n")

    def test_reglages_cales_sur_le_fichier(self):
        valeurs, _ = modele.lire_torrc(self.FICHIER)
        self.assertEqual(valeurs["num_guards"], 5)
        self.assertTrue(valeurs["avoid_disk"])
        self.assertNotIn("safe_logging", valeurs)
        complet = modele.completer_valeurs_tor(valeurs)
        self.assertFalse(complet["safe_logging"],
                         "absent du fichier : le réglage ne doit pas s'activer")

    def test_lignes_non_representables_conservees(self):
        _, extras = modele.lire_torrc(self.FICHIER)
        for ligne in ("ExcludeNodes {ru}", "StrictNodes 1", "ConnectionPadding 0",
                      "Bridge 192.0.2.1:443", "# note perso"):
            self.assertIn(ligne, extras, f"ligne perdue : {ligne}")

    def test_regeneration_garde_les_lignes_personnelles(self):
        valeurs, extras = modele.lire_torrc(self.FICHIER)
        txt = modele.construire_torrc(modele.completer_valeurs_tor(valeurs), extras)
        self.assertIn("ExcludeNodes {ru}", txt)
        self.assertIn("NumEntryGuards 5", txt)
        self.assertNotIn("SafeLogging", txt)

    def test_regeneration_stable(self):
        valeurs, extras = modele.lire_torrc(self.FICHIER)
        une = modele.construire_torrc(modele.completer_valeurs_tor(valeurs), extras)
        v2, e2 = modele.lire_torrc(une)
        deux = modele.construire_torrc(modele.completer_valeurs_tor(v2), e2)
        self.assertEqual(une, deux)

    def test_obligatoires_non_dupliques(self):
        _, extras = modele.lire_torrc(self.FICHIER)
        self.assertFalse(any(l.lower().startswith("socksport") for l in extras))


class ObligatoiresTest(unittest.TestCase):
    """Jamais de SocksPort/ControlPort en double (bind en conflit)."""

    def test_rien_a_reinjecter_si_tout_present(self):
        out = modele.completer_obligatoires(modele.TORRC_OBLIGATOIRE + "\nAvoidDiskWrites 1\n")
        self.assertEqual(out.count("SocksPort"), 1)
        self.assertEqual(out.count("ControlPort"), 1)

    def test_reinjecte_ce_qui_manque(self):
        out = modele.completer_obligatoires("AvoidDiskWrites 1\nSocksPort 9050\n")
        self.assertEqual(out.count("SocksPort"), 1)
        self.assertEqual(out.count("ControlPort"), 1)
        self.assertIn("CookieAuthentication 1", out)

    def test_detection_insensible_a_la_casse(self):
        out = modele.completer_obligatoires("socksport 9050\ncontrolport 9051\n"
                                            "cookieauthentication 1\ndatadirectory /x\n")
        self.assertEqual(out.lower().count("socksport"), 1)

    def test_lignes_commentees_ne_comptent_pas(self):
        out = modele.completer_obligatoires("# SocksPort 9050\nAvoidDiskWrites 1\n")
        actives = [l for l in out.splitlines() if l.strip().lower().startswith("socksport")]
        self.assertEqual(len(actives), 1)

    def test_torrc_vide(self):
        out = modele.completer_obligatoires("")
        for cle in ("SocksPort", "ControlPort", "CookieAuthentication", "DataDirectory"):
            self.assertIn(cle, out)


class TorrcFichierTest(Bac):

    def test_enregistre_si_valide(self):
        self.assertEqual(modele.enregistrer_torrc("SafeLogging 1"), [])
        txt = modele.TORRC_FILE.read_text()
        self.assertIn("SafeLogging 1", txt)
        self.assertIn("SocksPort 9050", txt, "obligatoires non réinjectés")

    def test_refuse_ce_que_le_daemon_refuserait(self):
        refus = modele.enregistrer_torrc("ClientTransportPlugin x exec /bin/sh\n")
        self.assertTrue(refus)
        self.assertFalse(modele.TORRC_FILE.exists())

    def test_reinitialisation(self):
        modele.enregistrer_torrc("SafeLogging 1")
        modele.supprimer_torrc()
        modele.supprimer_torrc()                       # déjà absent : sans erreur
        self.assertEqual(modele.lire_torrc_fichier(), "")


class SauvegardeTest(Bac):
    """Import de sauvegarde : mêmes contrôles que le daemon, .conf compris."""

    def _zip(self, fichiers):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for nom, contenu in fichiers.items():
                zf.writestr(nom, contenu)
        buf.seek(0)
        return buf

    def _importer(self, fichiers, cfg):
        with zipfile.ZipFile(self._zip(fichiers)) as zf:
            return modele.importer_fichiers(zf, cfg)

    def test_composants_de_chemin(self):
        for bon in ("vpn-a", "MonVPN", "mon-vpn_2", "a.ovpn"):
            self.assertTrue(modele.composant_sur(bon), bon)
        for mauvais in ("..", ".", "", "../etc", "a/b", "a\\b", ".ssh", "./x", "/etc/passwd"):
            self.assertFalse(modele.composant_sur(mauvais), f"« {mauvais} » accepté")

    def test_conf_restaure(self):
        cfg = {"providers": [{"name": "x", "ovpn_file": "providers/x/x.conf"}]}
        self.assertEqual(self._importer({"providers/x/x.conf": "client\n"}, cfg), [])
        self.assertTrue((modele.PROVIDERS_DIR / "x" / "x.conf").exists())

    def test_ovpn_piege_refuse(self):
        ecartes = self._importer({"providers/x/x.ovpn": "plugin /x.so\n"}, {"providers": []})
        self.assertFalse((modele.PROVIDERS_DIR / "x" / "x.ovpn").exists())
        self.assertTrue(any("plugin" in e for e in ecartes), ecartes)

    def test_chemin_absolu_neutralise(self):
        cfg = {"providers": [{"name": "x", "ovpn_file": "/etc/shadow"}]}
        self.assertTrue(self._importer({}, cfg))
        self.assertEqual(cfg["providers"][0]["ovpn_file"], "")

    def test_traversee_refusee(self):
        ecartes = self._importer({"providers/../../x.ovpn": "client\n"}, {"providers": []})
        self.assertTrue(ecartes)
        self.assertFalse((self.base.parent / "x.ovpn").exists())

    def test_torrc_restaure_si_valide(self):
        self._importer({"torrc": "SafeLogging 1\n"}, {"providers": []})
        self.assertEqual(modele.TORRC_FILE.read_text(), "SafeLogging 1\n")

    def test_torrc_piege_refuse(self):
        ecartes = self._importer({"torrc": "ClientTransportPlugin x exec /bin/sh\n"},
                                 {"providers": []})
        self.assertFalse(modele.TORRC_FILE.exists())
        self.assertTrue(ecartes)

    def test_export_puis_import(self):
        (modele.PROVIDERS_DIR / "v").mkdir(parents=True)
        (modele.PROVIDERS_DIR / "v" / "v.ovpn").write_text("client\n")
        modele.TORRC_FILE.write_text("SafeLogging 1\n")
        cfg = {**copy.deepcopy(DEFAULT_CONFIG), "local_dns": "10.0.0.53",
               "providers": [{"name": "v", "ovpn_file": "providers/v/v.ovpn", "accounts": []}]}
        chemin = self.base / "s.katakomba"
        modele.exporter(cfg, chemin)
        (modele.PROVIDERS_DIR / "v" / "v.ovpn").unlink()
        nouvelle, ecartes = modele.lire_sauvegarde(chemin)
        self.assertEqual(ecartes, [])
        self.assertEqual(nouvelle["local_dns"], "10.0.0.53")
        self.assertTrue((modele.PROVIDERS_DIR / "v" / "v.ovpn").exists())

    def test_reglages_importes_assainis(self):
        """Une sauvegarde reçue d'un tiers pourrait exclure tout Internet du
        tunnel, ou injecter des réglages dans systemd-resolved."""
        chemin = self.base / "piege.katakomba"
        cfg = {"excluded_ips": ["0.0.0.0/2", "64.0.0.0/2", "192.168.1.0/24"],
               "excluded_domains": [".lan", "x\nDNSSEC=no"],
               "local_dns": "1.1.1.1\nDNSStubListenerExtra=0.0.0.0", "lan_iface": "lo"}
        with zipfile.ZipFile(chemin, "w") as zf:
            zf.writestr("config.json", json.dumps(cfg))
        nouvelle, ecartes = modele.lire_sauvegarde(chemin)
        self.assertEqual(nouvelle["excluded_ips"], ["192.168.1.0/24"])
        self.assertEqual(nouvelle["excluded_domains"], [".lan"])
        self.assertEqual(nouvelle["local_dns"], "")
        self.assertEqual(nouvelle["lan_iface"], "")
        self.assertEqual(len(ecartes), 5, ecartes)

    def test_archive_piegee_refusee_avant_lecture(self):
        """Taille contrôlée AVANT décompression : quelques Ko annoncent des Go."""
        chemin = self.base / "bombe.katakomba"
        with zipfile.ZipFile(chemin, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", "{}")
            zf.writestr("providers/x/x.ovpn", "client\n" + " " * (modele.OVPN_MAX + 10))
        _nouvelle, ecartes = modele.lire_sauvegarde(chemin)
        self.assertTrue(any("trop volumineux" in e for e in ecartes), ecartes)
        self.assertFalse((modele.PROVIDERS_DIR / "x" / "x.ovpn").exists())

    def test_pas_une_sauvegarde(self):
        chemin = self.base / "x.zip"
        with zipfile.ZipFile(chemin, "w") as zf:
            zf.writestr("autre.txt", "x")
        with self.assertRaises(ValueError):
            modele.lire_sauvegarde(chemin)


class ResumeEtatTest(unittest.TestCase):
    """Ce que l'écran d'accueil affiche."""

    def test_sans_fournisseur_propose_l_assistant(self):
        r = modele.resume_etat("inactive", {}, 0)
        self.assertEqual((r["niveau"], r["action"]), ("arret", "configurer"))

    def test_arrete(self):
        r = modele.resume_etat("inactive", {})
        self.assertEqual((r["titre"], r["action"]), ("Déconnecté", "demarrer"))

    def test_en_echec(self):
        self.assertEqual(modele.resume_etat("failed", {})["niveau"], "erreur")

    def test_connecte(self):
        r = modele.resume_etat("active", {"tunnel_up": True, "provider": "vpn",
                                          "account_index": 1, "tunnel_uptime": 7260})
        self.assertEqual((r["niveau"], r["titre"], r["action"]), ("ok", "Connecté", "arreter"))
        self.assertIn("à travers Tor", r["detail"])

    def test_reconnexion_avec_sa_raison(self):
        r = modele.resume_etat("active", {"tunnel_up": False, "tor_ready": True,
                                          "tunnel_down_for": 4,
                                          "reconnect_reason": "circuit Tor trop lent, nouveau tirage"})
        self.assertEqual(r["titre"], "Reconnexion…")
        self.assertIn("Circuit Tor trop lent", r["detail"])

    def test_premier_demarrage(self):
        r = modele.resume_etat("active", {"tunnel_up": False, "tor_ready": False,
                                          "reconnect_reason": "démarrage du service"})
        self.assertIn("Tor", r["titre"])

    def test_durees(self):
        # Espaces insécables : « 4 s » ne se coupe jamais en fin de ligne.
        self.assertEqual(modele.duree_lisible(42), "42\u00a0s")
        self.assertEqual(modele.duree_lisible(600), "10\u00a0min")
        self.assertEqual(modele.duree_lisible(7260), "2\u00a0h\u00a001")
        self.assertEqual(modele.duree_lisible(3 * 86400 + 7200), "3\u00a0j\u00a02\u00a0h")


class EtatConnexionTest(unittest.TestCase):
    """Assistant : suivi de la première connexion."""

    def test_progression(self):
        self.assertEqual(modele.etat_connexion("activating", {})[0], "attente")
        self.assertIn("Tor", modele.etat_connexion("active", {"tor_ready": False})[1])
        self.assertIn("VPN", modele.etat_connexion("active", {"tor_ready": True})[1])

    def test_connecte_avec_debit(self):
        niveau, msg, fini = modele.etat_connexion("active", {"tunnel_up": True,
                                                             "last_circuit_kbs": 500})
        self.assertEqual((niveau, fini), ("ok", True))
        self.assertIn("4,0\u00a0Mb/s", msg)

    def test_connecte_debit_pas_encore_mesure(self):
        """L'assistant attend la mesure : décidé par un drapeau, jamais en
        cherchant « en cours » dans un texte qui peut être traduit."""
        niveau, _msg, fini = modele.etat_connexion("active", {"tunnel_up": True})
        self.assertEqual((niveau, fini), ("ok", False))

    def test_identifiants_refuses(self):
        st = {"tor_ready": True, "provider": "vpn", "accounts_cooldown": {"1": 800}}
        niveau, msg, fini = modele.etat_connexion("active", st, "vpn", 0)
        self.assertEqual((niveau, fini), ("erreur", True))
        self.assertIn("identifiant", msg)

    def test_refus_d_un_autre_fournisseur_ignore(self):
        st = {"tor_ready": True, "provider": "autre", "accounts_cooldown": {"1": 800}}
        self.assertEqual(modele.etat_connexion("active", st, "vpn", 0)[0], "attente")

    def test_service_en_echec(self):
        self.assertEqual(modele.etat_connexion("failed", {})[0], "erreur")


class EvenementsTest(unittest.TestCase):

    LIGNES = [
        "2026-09-25T15:14:17+02:00 h katakomba[1]: [2026-09-25 15:14:17] [ERROR] "
        "Watchdog : redémarrage complet (1/3) …",
        "2026-09-25T15:14:21+02:00 h katakomba[1]: [2026-09-25 15:14:21] [OK   ] Tunnel VPN actif.",
        "2026-09-25T15:14:34+02:00 h katakomba[1]: [2026-09-25 15:14:34] [OK   ] "
        "[circuit] Débit OK : 930 KB/s (~7.4 Mbps).",
        "2026-09-24T22:13:35+02:00 h katakomba[1]: [2026-09-24 22:13:35] [WARN ] "
        "[circuit] Débit faible : 5 KB/s (~0.0 Mbps) < 250 KB/s — nouveau tirage (1/3) …",
        "2026-09-24T22:00:00+02:00 h katakomba[1]: [2026-09-24 22:00:00] [WARN ] "
        "Compte 3 refusé (vpn) — mis en quarantaine 15 min",
        "2026-09-24T21:00:00+02:00 h katakomba[1]: [2026-09-24 21:00:00] [INFO ] [tor] bruit",
    ]

    def test_traduction_du_plus_recent_au_plus_ancien(self):
        ev = modele.evenements(self.LIGNES)
        self.assertEqual([e[3] for e in ev], [
            "Circuit mesuré : 7,4\u00a0Mb/s", "Connecté",
            "Connexion perdue : redémarrage complet",
            "Circuit trop lent (0,0\u00a0Mb/s) : nouveau tirage",
            "Compte 3 refusé par le fournisseur"])
        self.assertEqual(ev[0][:3], ("2026-09-25", "15:14", "ok"))

    def test_maximum(self):
        self.assertEqual(len(modele.evenements(self.LIGNES, 2)), 2)


class DiagnosticTest(unittest.TestCase):

    def test_lecture_de_la_sortie_de_doctor(self):
        sortie = ("\n  ╔═══╗\n  ║  Diagnostic Katakomba   ║\n  ╚═══╝\n\n"
                  "  [OK  ] Service                    actif\n"
                  "  [....] Tunnel                     reconnexion en cours depuis 3 s (x)\n"
                  "  [--  ] Sortie Internet            reporté — le tunnel se reconnecte\n"
                  "  [KO  ] DNS du tunnel              incomplet\n\n"
                  "  Reconnexion en cours (x) : les contrôles du tunnel sont reportés.\n")
        import subprocess
        from unittest import mock
        with mock.patch.object(modele.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 2, sortie, "")):
            resultats, conclusion, code = modele.lancer_diagnostic()
        self.assertEqual([r[0] for r in resultats], ["ok", "attente", "reporte", "erreur"])
        self.assertEqual(resultats[3][1:], ("DNS du tunnel", "incomplet"))
        self.assertIn("Reconnexion en cours", conclusion)
        self.assertEqual(code, 2)


class ServiceTest(unittest.TestCase):

    def test_systemctl_jamais_via_pkexec(self):
        """systemd consulte polkit lui-même : c'est ce qui permet à la règle
        50-katakomba.rules de dispenser le groupe de mot de passe (via
        pkexec, polkit ne verrait qu'« exécuter systemctl en root »)."""
        from unittest import mock
        with mock.patch.object(modele.os, "geteuid", return_value=1000), \
             mock.patch.object(modele.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 0, "", "")) as run:
            modele.systemctl("is-active", "katakomba")
            modele.piloter_service("restart")
        self.assertEqual(run.call_args_list[0].args[0][0], "systemctl")
        self.assertEqual(run.call_args_list[1].args[0], ["systemctl", "restart", "katakomba"])

    def test_refus_polkit_vaut_annulation(self):
        from unittest import mock
        for message in ("Failed to start katakomba.service: Access denied",
                        "Failed to stop katakomba.service: Interactive authentication required."):
            with mock.patch.object(modele.subprocess, "run", return_value=
                                   subprocess.CompletedProcess([], 1, "", message)):
                self.assertEqual(modele.piloter_service("start").returncode, modele.ANNULE)
        with mock.patch.object(modele.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 1, "", "Unit not found")):
            self.assertEqual(modele.piloter_service("start").returncode, 1)

    def test_actions_privilegiees_designent_la_politique(self):
        """pkexec + chemin + premier argument : l'invite polkit est celle
        d'org.katakomba.policy, pas l'invite générique."""
        from unittest import mock
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(modele, "SCRIPT_DIR", pathlib.Path(d)), \
             mock.patch.object(modele.os, "geteuid", return_value=1000), \
             mock.patch.object(modele, "demarrage_auto_actif", return_value=False), \
             mock.patch.object(modele.subprocess, "run") as run:
            (pathlib.Path(d) / "repair_network.sh").touch()
            modele.regler_demarrage_auto(True)
            modele.lancer_reparation()
        self.assertEqual(run.call_args_list[0].args[0],
                         ["pkexec", f"{d}/katakomba-cli.sh", "enable"])
        self.assertEqual(run.call_args_list[1].args[0], ["pkexec", f"{d}/repair_network.sh"])

    def test_root_sans_pkexec(self):
        from unittest import mock
        with mock.patch.object(modele.os, "geteuid", return_value=0), \
             mock.patch.object(modele.subprocess, "run") as run:
            modele.privilegie("katakomba-cli.sh", "disable")
        self.assertEqual(run.call_args.args[0][1:], ["disable"])
        self.assertNotIn("pkexec", run.call_args.args[0])

    def test_demarrage_auto_sans_invite_si_rien_ne_change(self):
        from unittest import mock
        with mock.patch.object(modele, "demarrage_auto_actif", return_value=True), \
             mock.patch.object(modele, "privilegie") as pr:
            modele.regler_demarrage_auto(True)
        pr.assert_not_called()


class PreferencesTest(unittest.TestCase):

    def setUp(self):
        from unittest import mock
        self._tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self._tmp.name)
        for nom, chemin in (("PREFERENCES_FILE", base / "katakomba" / "interface.json"),
                            ("LANCEMENT_SESSION_FILE", base / "autostart" / "k.desktop")):
            p = mock.patch.object(modele, nom, chemin)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_defauts_puis_aller_retour(self):
        self.assertEqual(modele.charger_preferences(), modele.PREFERENCES_DEFAUT)
        prefs = modele.charger_preferences()
        prefs["notifications"] = False
        modele.enregistrer_preferences(prefs)
        self.assertFalse(modele.charger_preferences()["notifications"])
        self.assertTrue(modele.charger_preferences()["arriere_plan"])

    def test_fichier_abime_ou_valeurs_etrangeres(self):
        modele.PREFERENCES_FILE.parent.mkdir(parents=True)
        modele.PREFERENCES_FILE.write_text("{pas du json")
        self.assertEqual(modele.charger_preferences(), modele.PREFERENCES_DEFAUT)
        modele.PREFERENCES_FILE.write_text(json.dumps(
            {"notifications": "non", "inconnue": True, "arriere_plan": False}))
        prefs = modele.charger_preferences()
        self.assertTrue(prefs["notifications"], "valeur non booléenne acceptée")
        self.assertFalse(prefs["arriere_plan"])
        self.assertNotIn("inconnue", prefs)

    def test_lancement_a_l_ouverture_de_session(self):
        self.assertFalse(modele.lancement_session_actif())
        modele.regler_lancement_session(True)
        texte = modele.LANCEMENT_SESSION_FILE.read_text()
        self.assertIn("Exec=katakomba gui --arriere-plan\n", texte)
        self.assertTrue(modele.lancement_session_actif())
        modele.regler_lancement_session(False)
        self.assertFalse(modele.LANCEMENT_SESSION_FILE.exists())

    def test_entree_de_l_utilisateur_jamais_effacee(self):
        modele.LANCEMENT_SESSION_FILE.parent.mkdir(parents=True)
        modele.LANCEMENT_SESSION_FILE.write_text("[Desktop Entry]\nExec=autre chose\n")
        modele.regler_lancement_session(False)
        self.assertTrue(modele.LANCEMENT_SESSION_FILE.exists())

    def test_hors_de_la_configuration_systeme(self):
        self.assertNotIn(str(modele.CONFIG_DIR), str(modele._config_utilisateur()))


class ReglagesRelusTest(unittest.TestCase):
    """Tout réglage exposé par l'interface doit être LU et ÉCRIT.

    Défaut classique : l'interrupteur qui enregistre sans jamais se recharger
    (valeur juste dans config.json, fausse à l'écran)."""

    GUI = pathlib.Path(__file__).resolve().parents[1] / "gui"
    OPTIONS = {"auto_reconnect": "page_reglages.py", "random_account": "page_reglages.py",
               "block_ipv6": "page_reglages.py", "circuit_check": "page_reglages.py",
               "circuit_min_kbs": "page_reglages.py", "circuit_max_retries": "page_reglages.py",
               "autostart": "page_reglages.py", "lan_auto": "page_lan.py",
               "lan_dhcp": "page_lan.py", "lan_iface": "page_lan.py",
               "lan_gateway": "page_lan.py", "lan_subnet": "page_lan.py",
               "local_dns": "page_exclusions.py", "excluded_ips": "page_exclusions.py",
               "excluded_domains": "page_exclusions.py"}

    def test_chaque_reglage_est_lu_et_ecrit(self):
        for cle, fichier in self.OPTIONS.items():
            src = (self.GUI / fichier).read_text()
            lu = f'c.get("{cle}"' in src or f'config.get("{cle}"' in src
            self.assertTrue(lu, f"{cle} : jamais rechargé à l'écran")
            # Écriture directe, ou interrupteur générique qui reçoit la clé.
            ecrit = (f'config["{cle}"]' in src or f'setdefault("{cle}"' in src
                     or re.search(r'_interrupteur\(\s*[\w.]+,\s*"%s"' % cle, src))
            self.assertTrue(ecrit, f"{cle} : jamais écrit dans la configuration")
            self.assertIn(cle, DEFAULT_CONFIG)


# ── WireGuard (v4.0.0) ───────────────────────────────────────────────────────

import base64 as _b64                                          # noqa: E402

CONF = (f"[Interface]\nPrivateKey = {_b64.b64encode(bytes(32)).decode()}\n"
        "Address = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n"
        f"PublicKey = {_b64.b64encode(bytes(range(32))).decode()}\n"
        "AllowedIPs = 0.0.0.0/0\nEndpoint = 185.107.56.211:51820\n")


class WireGuardImportTest(Bac):

    def test_resume_et_avertissement(self):
        f = self.base / "nl.conf"
        f.write_text(CONF.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nPostUp = x"))
        prets, erreurs = modele.preparer_import_wg([str(f)])
        self.assertEqual(erreurs, [])
        resume = modele.resume_import(prets)
        self.assertIn("nl.conf — Proton (TLS) · 185.107.56.211:443", resume)
        self.assertIn("wg-quick", resume, "avertissement absent du résumé")

    def test_fichier_illisible(self):
        prets, erreurs = modele.preparer_import_wg(["/inexistant/x.conf"])
        self.assertEqual(prets, [])
        self.assertTrue(erreurs)

    def test_conf_refuse_jamais_pret(self):
        f = self.base / "x.conf"
        f.write_text(CONF.replace("Endpoint = 185.107.56.211:51820", "Endpoint = a.b:1"))
        prets, erreurs = modele.preparer_import_wg([str(f)])
        self.assertEqual(prets, [])
        self.assertTrue(any(e.startswith("x.conf : ") for e in erreurs), erreurs)

    def test_ajout_cree_le_fournisseur_sans_doublon(self):
        f = self.base / "nl.conf"
        f.write_text(CONF)
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        self.assertEqual(modele.ajouter_confs_wg(cfg, "vpn", [str(f)]), 1)
        p = cfg["providers"][0]
        self.assertEqual(p["wireguard"], [{"conf": "providers/vpn/nl.conf"}])
        self.assertEqual((modele.PROVIDERS_DIR / "vpn" / "nl.conf").read_text(), CONF)
        self.assertEqual(modele.ajouter_confs_wg(cfg, "VPN", [str(f)]), 0,
                         "doublon ajouté, ou second fournisseur créé")
        self.assertEqual(len(cfg["providers"]), 1)

    def test_ajout_a_un_fournisseur_openvpn(self):
        """Les deux transports chez le même fournisseur : rien d'OpenVPN ne
        doit se perdre."""
        f = self.base / "nl.conf"
        f.write_text(CONF)
        cfg = {"providers": [{"name": "ivpn", "ovpn_file": "providers/ivpn/a.ovpn",
                              "accounts": [{"u": "dQ==", "p": "cA=="}]}]}
        modele.ajouter_confs_wg(cfg, "ivpn", [str(f)])
        p = cfg["providers"][0]
        self.assertEqual(p["ovpn_file"], "providers/ivpn/a.ovpn")
        self.assertEqual(len(p["accounts"]), 1)
        self.assertEqual(len(p["wireguard"]), 1)
        self.assertEqual(modele.resume_comptes(p), "1 compte OpenVPN · 1 fichier WireGuard")

    def test_meme_nom_contenu_different(self):
        """Un .conf du même nom ne remplace jamais l'autre (autre serveur)."""
        a, b = self.base / "a", self.base / "b"
        a.mkdir()
        b.mkdir()
        (a / "nl.conf").write_text(CONF)
        (b / "nl.conf").write_text(CONF.replace("10.2.0.2", "10.2.0.3"))
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        modele.ajouter_confs_wg(cfg, "vpn", [str(a / "nl.conf"), str(b / "nl.conf")])
        self.assertEqual([c["conf"] for c in cfg["providers"][0]["wireguard"]],
                         ["providers/vpn/nl.conf", "providers/vpn/nl-2.conf"])

    def test_description(self):
        f = self.base / "nl.conf"
        f.write_text(CONF)
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        modele.ajouter_confs_wg(cfg, "vpn", [str(f)])
        entree = cfg["providers"][0]["wireguard"][0]
        self.assertEqual(modele.decrire_conf(entree),
                         ("nl.conf", "Proton (TLS) · 185.107.56.211:443"))
        self.assertEqual(modele.decrire_conf({"conf": "/etc/shadow"})[1], "chemin refusé")
        self.assertEqual(modele.decrire_conf({"u": "x"})[1], "aucun fichier WireGuard")

    def test_genre_reconnu_au_contenu(self):
        wg, ovpn_conf, ovpn = (self.base / n for n in ("wg.conf", "o.conf", "o.ovpn"))
        wg.write_text(CONF)
        ovpn_conf.write_text("client\nremote 1.2.3.4 443 tcp\n")
        ovpn.write_text("client\n")
        self.assertEqual(modele.genre_fichiers([wg]), "wireguard")
        self.assertEqual(modele.genre_fichiers([ovpn_conf]), "openvpn",
                         "configuration OpenVPN livrée en .conf prise pour WireGuard")
        self.assertEqual(modele.genre_fichiers([ovpn]), "openvpn")
        self.assertEqual(modele.genre_fichiers([wg, ovpn]), "")
        self.assertEqual(modele.genre_fichiers([self.base / "absent.conf"]), "wireguard")


class WireGuardSauvegardeTest(Bac):

    def _sauver_puis_lire(self, cfg):
        zip_ = self.base / "s.zip"
        modele.exporter(cfg, zip_)
        return modele.lire_sauvegarde(zip_)

    def test_aller_retour(self):
        (modele.PROVIDERS_DIR / "v").mkdir(parents=True)
        (modele.PROVIDERS_DIR / "v" / "v.conf").write_text(CONF)
        cfg = {**copy.deepcopy(DEFAULT_CONFIG),
               "providers": [{"name": "v", "wireguard": [{"conf": "providers/v/v.conf"}]}]}
        zip_ = self.base / "s.zip"
        modele.exporter(cfg, zip_)
        (modele.PROVIDERS_DIR / "v" / "v.conf").unlink()
        nouvelle, ecartes = modele.lire_sauvegarde(zip_)
        self.assertEqual(ecartes, [])
        self.assertEqual(nouvelle["providers"][0]["wireguard"], [{"conf": "providers/v/v.conf"}])
        self.assertEqual((modele.PROVIDERS_DIR / "v" / "v.conf").read_text(), CONF)

    def test_chemin_refuse_ecarte(self):
        zip_ = self.base / "s.zip"
        with zipfile.ZipFile(zip_, "w") as zf:
            zf.writestr("config.json", json.dumps({"providers": [{"name": "x", "wireguard": [
                {"conf": "/etc/shadow"}, {"conf": "providers/x/ok.conf"}]}]}))
        nouvelle, ecartes = modele.lire_sauvegarde(zip_)
        self.assertEqual(nouvelle["providers"][0]["wireguard"], [{"conf": "providers/x/ok.conf"}])
        self.assertTrue(any("chemin refusé" in e for e in ecartes), ecartes)

    def test_conf_piege_refuse(self):
        zip_ = self.base / "s.zip"
        with zipfile.ZipFile(zip_, "w") as zf:
            zf.writestr("config.json", "{}")
            zf.writestr("providers/x/x.conf", "[Interface]\nPostUp = sh\n")
        _nouvelle, ecartes = modele.lire_sauvegarde(zip_)
        self.assertFalse((modele.PROVIDERS_DIR / "x" / "x.conf").exists())
        self.assertTrue(ecartes)

    def test_lien_jamais_exporte(self):
        victime = self.base / "secret"
        victime.write_text("SECRET")
        (modele.PROVIDERS_DIR / "x").mkdir(parents=True)
        (modele.PROVIDERS_DIR / "x" / "x.conf").symlink_to(victime)
        zip_ = self.base / "s.zip"
        modele.exporter({"providers": [{"name": "x", "wireguard": [
            {"conf": "providers/x/x.conf"}, {"conf": "/etc/shadow"}]}]}, zip_)
        with zipfile.ZipFile(zip_) as zf:
            self.assertEqual([n for n in zf.namelist() if n.endswith(".conf")], [])

    def test_transports_illisibles_remplaces(self):
        zip_ = self.base / "s.zip"
        with zipfile.ZipFile(zip_, "w") as zf:
            zf.writestr("config.json", json.dumps({"transports": ["ssh"]}))
        nouvelle, ecartes = modele.lire_sauvegarde(zip_)
        self.assertEqual(nouvelle["transports"], ["wireguard", "openvpn"])
        self.assertTrue(any("Transports" in e for e in ecartes))


class TransportsReglageTest(unittest.TestCase):

    def test_ordres_admis(self):
        for ordre in modele.ORDRES_TRANSPORTS:
            self.assertEqual(modele.erreurs_config({"transports": list(ordre)}), [], ordre)

    def test_ordres_refuses(self):
        for valeur in ([], ["ssh"], ["wireguard", "wireguard"], "wireguard"):
            self.assertTrue(modele.erreurs_config({"transports": valeur}), valeur)

    def test_defaut(self):
        self.assertEqual(DEFAULT_CONFIG["transports"], ["wireguard", "openvpn"])


class WireGuardEtatTest(unittest.TestCase):

    def test_assistant_attend_que_tous_les_conf_soient_ecartes(self):
        st = {"tor_ready": True, "provider": "vpn", "transport": "wireguard",
              "accounts_cooldown": {"1": 800}}
        self.assertEqual(modele.etat_connexion("active", st, "vpn", 0, 2)[0], "attente",
                         "échec annoncé alors qu'un autre .conf reste à essayer")
        st["accounts_cooldown"]["2"] = 800
        niveau, msg, fini = modele.etat_connexion("active", st, "vpn", 0, 2)
        self.assertEqual((niveau, fini), ("erreur", True))
        self.assertIn("poignée de main", msg)

    def test_transport_affiche(self):
        st = {"tunnel_up": True, "tor_ready": True, "provider": "vpn",
              "transport": "wireguard", "account_index": 1}
        vpn = next(e for e in modele.trajet("active", st) if e["cle"] == "vpn")
        self.assertEqual(vpn["detail"], "WireGuard · fichier 2")
        st["transport"] = "openvpn"
        vpn = next(e for e in modele.trajet("active", st) if e["cle"] == "vpn")
        self.assertEqual(vpn["detail"], "OpenVPN · compte 2")

    def test_evenements(self):
        lignes = [
            "2026-09-24T22:00:00+02:00 h katakomba[1]: [2026-09-24 22:00:00] [WARN ] "
            ".conf 3 (vpn) sans poignée de main — mis en quarantaine 15 min.",
            "2026-09-24T22:00:05+02:00 h katakomba[1]: [2026-09-24 22:00:05] [WARN ] "
            "vpn : WireGuard épuisé → OpenVPN",
        ]
        self.assertEqual([e[3] for e in modele.evenements(lignes)],
                         ["Bascule vers OpenVPN", "Fichier WireGuard 3 : aucune réponse du serveur"])


if __name__ == "__main__":
    unittest.main()


class ProgressionTorTest(unittest.TestCase):

    def tor(self, st, service="active"):
        return modele.trajet(service, st, 1)[1]

    def test_demarrage_de_tor(self):
        t = self.tor({"tor_ready": False, "tor_bootstrap": 45})
        self.assertEqual((t["niveau"], t["progression"]), ("attente", 0.45))
        self.assertEqual(t["detail"], "Démarrage : 45 %")

    def test_progression_inconnue(self):
        t = self.tor({"tor_ready": False})            # daemon antérieur au champ
        self.assertEqual((t["detail"], t["progression"]), ("Connexion…", 0))

    def test_pas_de_progression_hors_attente(self):
        self.assertIsNone(self.tor({"tor_ready": True, "tor_bootstrap": 100})["progression"])
        self.assertIsNone(self.tor({}, "inactive")["progression"])
