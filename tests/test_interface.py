"""Interface GTK réelle : la fenêtre est construite (jamais affichée) sur un
faux système.  Ignoré sans GTK 4 / libadwaita ou sans écran."""

import copy
import json
import warnings
import pathlib
import tempfile
import unittest

from constants import DEFAULT_CONFIG
from gui import modele

# PyGObject signale une API asyncio dépréciée à chaque boucle : sans rapport
# avec Katakomba.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="gi.events")

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, Gtk
    DISPONIBLE = Gtk.init_check()
    if DISPONIBLE:
        Adw.init()
except (ImportError, ValueError):
    DISPONIBLE = False


def pomper(ms=300):
    """Laisse tourner la boucle GTK : rappels des tâches de fond compris."""
    fin = GLib.get_monotonic_time() + ms * 1000
    ctx = GLib.MainContext.default()
    while GLib.get_monotonic_time() < fin:
        ctx.iteration(False)


@unittest.skipUnless(DISPONIBLE, "GTK 4 / libadwaita ou écran indisponible")
class FenetreTest(unittest.TestCase):

    STATUT = {"version": "3.7.0", "tor_ready": True, "tunnel_up": True,
              "tunnel_iface": "tun0", "tunnel_uptime": 3600, "provider": "vpn-a",
              "account_index": 0, "last_circuit_kbs": 654.0, "light_restarts": 2,
              "full_restarts": 0, "ipv6_blocked": True}

    @classmethod
    def setUpClass(cls):
        # Une seule application pour toute la classe : chaque enregistrement
        # exporte un objet sur le bus de session.
        cls.app = Adw.Application(application_id="org.katakomba.Test",
                                  flags=Gio.ApplicationFlags.NON_UNIQUE)
        cls.app.register(None)
        # Notifications du bureau : relevées, jamais envoyées.
        cls.app.notifier_bureau = lambda avis: cls.avis.append(avis)

    def setUp(self):
        # Une exception dans un rappel GTK (signal, tâche de fond) ne fait
        # pas échouer le test par elle-même : PyGObject l'imprime via
        # sys.excepthook.  Elle est relevée ici, et le test échoue.
        import sys
        self._exceptions = []
        self._excepthook = sys.excepthook
        sys.excepthook = lambda t, v, tb: self._exceptions.append(f"{t.__name__}: {v}")
        self._tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self._tmp.name)
        self.sauve = {n: getattr(modele, n) for n in (
            "CONFIG_FILE", "TORRC_FILE", "PROVIDERS_DIR", "SCRIPT_DIR", "etat_service",
            "lire_statut", "lire_evenements", "interfaces_lan", "demarrage_auto_actif",
            "systemctl", "privilegie", "PREFERENCES_FILE", "LANCEMENT_SESSION_FILE")}
        type(self).avis = []
        modele.PREFERENCES_FILE = base / "prefs" / "interface.json"
        modele.LANCEMENT_SESSION_FILE = base / "autostart" / "org.katakomba.Katakomba.desktop"
        modele.privilegie = lambda *a: self.fail(f"commande privilégiée lancée : {a}")
        modele.CONFIG_FILE, modele.TORRC_FILE = base / "config.json", base / "torrc"
        modele.PROVIDERS_DIR, modele.SCRIPT_DIR = base / "providers", base
        modele.etat_service = lambda: "active"
        modele.lire_statut = lambda: dict(self.STATUT)
        modele.lire_evenements = lambda n=8: [("2026-09-25", "15:22", "ok", "Connecté")]
        modele.interfaces_lan = lambda: ["eth1"]
        modele.demarrage_auto_actif = lambda: False
        modele.systemctl = lambda *a: self.fail(f"commande système lancée : {a}")
        cfg = {**copy.deepcopy(DEFAULT_CONFIG), "advanced_mode": False, "providers": [
            {"name": "vpn-a", "ovpn_file": "providers/vpn-a/a.ovpn",
             "accounts": [{"u": modele.obf("alice"), "p": modele.obf("x")}]},
            {"name": "vpn-b", "ovpn_file": "", "accounts": []}]}
        modele.CONFIG_FILE.write_text(json.dumps(cfg))
        modele.TORRC_FILE.write_text(modele.construire_torrc(modele.TOR_DEFAUTS,
                                                             ["ExcludeNodes {ru}"]))
        from gui.fenetre import Fenetre
        self.fen = Fenetre(self.app)
        pomper()

    def tearDown(self):
        import sys
        self.fen.arreter_suivi()
        self.fen.destroy()
        pomper(50)
        sys.excepthook = self._excepthook
        self.assertEqual(self._exceptions, [], "exception dans un rappel GTK")
        for n, v in self.sauve.items():
            setattr(modele, n, v)
        self._tmp.cleanup()

    def config_disque(self):
        return json.loads(modele.CONFIG_FILE.read_text())

    def test_toutes_les_pages(self):
        self.assertEqual(set(self.fen.pages), {"connexion", "fournisseurs", "reglages",
                                               "diagnostic", "journal", "exclusions",
                                               "lan", "tor"})

    def test_mode_simple_cache_les_pages_avancees(self):
        self.assertFalse(self.fen.nav_avancee.get_visible())
        self.assertFalse(self.fen.pages["reglages"].circuit.get_visible())
        self.fen.lookup_action("avance").change_state(GLib.Variant.new_boolean(True))
        self.assertTrue(self.fen.nav_avancee.get_visible())
        self.assertTrue(self.fen.pages["reglages"].circuit.get_visible())
        self.assertTrue(self.config_disque()["advanced_mode"])

    def test_accueil_affiche_l_etat(self):
        self.fen._lire_etat()
        pomper(500)
        page = self.fen.pages["connexion"]
        self.assertEqual(page.titre.get_label(), "Connecté")
        self.assertEqual(page.libelle.get_label(), "Se déconnecter")
        self.assertTrue(self.fen.point.has_css_class("etat-ok"))
        # Trajet : les quatre étapes au vert, le VPN nommé.
        self.assertTrue(all(n.pastille.has_css_class("etat-ok") for n in page.noeuds))
        self.assertEqual(page.noeuds[2].titre.get_label(), "vpn-a")
        circuit = page.tuiles[1]
        self.assertEqual(circuit.valeur.get_label(), "5,2\u00a0Mb/s")

    def test_accueil_pendant_une_connexion(self):
        """Tor à 45 % : son anneau montre la progression, lui seul travaille
        et le trait qui y mène s'anime ; une fois connecté, les étapes qui
        s'établissent s'illuminent et les paquets prennent le relais."""
        self.STATUT = {"version": "3.7.0", "tor_ready": False, "tor_bootstrap": 45,
                       "tunnel_up": False, "provider": "vpn-a", "account_index": 0,
                       "reconnect_reason": "démarrage du service"}
        page = self.fen.pages["connexion"]
        self.fen._lire_etat()
        pomper(500)
        tor = page.noeuds[1].pastille
        self.assertEqual(tor.progression, 0.45)
        self.assertEqual(page._attentes, [tor])
        self.assertIs(page._flux, page.liens[0])

        eclats = []
        for n in page.noeuds:
            n.pastille.illuminer = lambda p=n.pastille: eclats.append(p)
        self.STATUT = dict(type(self).STATUT)
        self.fen._lire_etat()
        pomper(500)
        # Tor, le VPN et Internet viennent de s'établir : ils s'illuminent ;
        # l'ordinateur, déjà établi, non.
        self.assertEqual(eclats, [n.pastille for n in page.noeuds[1:]])
        self.assertTrue(page._connecte)
        self.assertEqual(page._attentes, [])
        self.assertIsNone(tor.progression)

    def test_ordre_des_fournisseurs(self):
        page = self.fen.pages["fournisseurs"]
        self.assertEqual(len(page.liste.rangees), 2)
        page._deplacer(1, -1)
        self.assertEqual([p["name"] for p in self.config_disque()["providers"]],
                         ["vpn-b", "vpn-a"])

    def test_interrupteur_enregistre(self):
        page = self.fen.pages["reglages"]
        page.ipv6.set_active(True)
        self.assertTrue(self.config_disque()["block_ipv6"])
        self.assertTrue(self.fen.bandeau.get_revealed(),
                        "le redémarrage nécessaire n'est pas proposé")

    def test_exclusion_normalisee_et_ipv6_refusee(self):
        page = self.fen.pages["exclusions"]
        page.nouveau_reseau.set_text("10.0.20.7/24")
        page._reseau_ajoute(None)
        page.nouveau_reseau.set_text("2001:db8::/32")
        page._reseau_ajoute(None)
        self.assertEqual(self.config_disque()["excluded_ips"], ["10.0.20.0/24"])
        self.assertTrue(page.nouveau_reseau.has_css_class("error"))

    def test_tor_garde_les_lignes_personnelles(self):
        page = self.fen.pages["tor"]
        page.champs["conn_padding"].set_active(True)
        texte = page._texte()
        self.assertIn("ConnectionPadding 1", texte)
        self.assertIn("ExcludeNodes {ru}", texte, "ligne personnelle perdue")

    # ── Arrière-plan et notifications ────────────────────────────────────────

    def test_fermer_cache_seulement_et_explique_une_fois(self):
        self.fen.present()
        pomper()
        self.fen.close()
        pomper()
        self.assertFalse(self.fen.get_visible())
        self.assertIn(self.fen, self.app.get_windows(), "fenêtre détruite")
        self.assertIsNone(self.fen.page_visible(), "les pages relisent encore le journal")
        self.assertEqual([a.ident for a in self.avis], ["arriere-plan"])
        self.assertTrue(modele.charger_preferences()["avis_arriere_plan_vu"])
        self.fen.present()
        pomper()
        self.fen.close()
        pomper()
        self.assertEqual(len(self.avis), 1, "explication répétée")

    def test_coupure_notifiee_fenetre_cachee(self):
        self.fen._lire_etat()
        pomper(400)
        self.STATUT = {**self.STATUT, "tunnel_up": False, "tunnel_down_for": 45,
                       "reconnect_reason": "perte de connectivité, relance d'OpenVPN"}
        self.fen._lire_etat()
        pomper(400)
        self.assertEqual([a.titre for a in self.avis], ["Connexion perdue"])

    def test_notifications_desactivables(self):
        page = self.fen.pages["reglages"]
        page.notifications.set_active(False)
        self.assertFalse(modele.charger_preferences()["notifications"])
        self.fen._lire_etat()
        pomper(400)
        self.STATUT = {**self.STATUT, "tunnel_up": False, "tunnel_down_for": 45}
        self.fen._lire_etat()
        pomper(400)
        self.assertEqual(self.avis, [])

    def test_reglages_d_interface(self):
        page = self.fen.pages["reglages"]
        page.session.set_active(True)
        self.assertTrue(modele.lancement_session_actif())
        page.arriere_plan.set_active(False)
        self.assertFalse(self.fen.get_hide_on_close())
        self.assertFalse(page.session.get_sensitive())
        self.assertFalse(modele.lancement_session_actif(),
                         "lancement caché sans arrière-plan")
        self.assertFalse(modele.charger_preferences()["arriere_plan"])

    # ── Langues ──────────────────────────────────────────────────────────────

    def test_chaque_langue_construit_la_fenetre(self):
        import i18n
        from gui.fenetre import Fenetre
        try:
            for code in i18n.LANGUES:
                i18n.activer(code)
                f = Fenetre(self.app)
                pomper(200)
                self.assertEqual(f.page_contenu.get_title(), i18n._("Connexion"))
                if code != "fr":
                    self.assertNotEqual(f.page_contenu.get_title(), "Connexion", code)
                f.arreter_suivi()
                f.destroy()
        finally:
            i18n.activer("fr")

    def test_changer_de_langue_reconstruit_la_fenetre(self):
        """Même page, nouvelle langue, sans relancer l'application."""
        import os
        from unittest import mock
        import i18n
        from gui.app import KatakombaApp
        self.fen.aller("reglages")
        ancienne = self.fen
        try:
            with mock.patch.dict(os.environ, {}):
                KatakombaApp.changer_langue(self.app, "de")
                pomper()
                self.assertEqual(os.environ.get("LANGUAGE"), "de", "textes de GTK")
            nouvelles = [w for w in self.app.get_windows() if w is not ancienne]
            self.assertEqual(len(nouvelles), 1)
            self.fen = nouvelles[0]                      # détruite par tearDown
            self.assertEqual(self.fen.page_visible() or self.fen.pile.get_visible_child_name(),
                             "reglages")
            self.assertEqual(self.fen.page_contenu.get_title(), "Einstellungen")
            self.assertIs(self.fen.veilleur, ancienne.veilleur, "coupure en cours oubliée")
            self.assertNotIn(ancienne, self.app.get_windows())
        finally:
            i18n.activer("fr")

    def test_assistant_se_construit(self):
        from gui.assistant import Assistant
        a = Assistant(self.fen)
        self.assertIsNotNone(a.vue.get_visible_page())
        a._valider_fournisseur()
        self.assertIn("nom", a.info_fichier.get_label().lower())


if __name__ == "__main__":
    unittest.main()
