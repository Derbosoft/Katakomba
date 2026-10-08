"""
Fenêtre principale : barre latérale (Connexion, Fournisseurs, Réglages,
Diagnostic, Journal, puis les pages avancées) et zone de contenu.

La fenêtre porte l'état partagé par les pages : la configuration, son
enregistrement, les notifications, et le suivi du service (toutes les 3 s,
hors du fil de l'interface).

Fermée, elle est seulement cachée (préférence « arriere_plan ») : le suivi
continue et le veilleur prévient d'une coupure par une notification.
"""

from gi.repository import Adw, Gio, GLib, Gtk

from constants import SCRIPT_DIR, VERSION
from gui import modele
from gui.outils import alerte, en_fond
from gui.veilleur import Avis, Veilleur
from i18n import N_, _

ASSETS = SCRIPT_DIR / "assets"
PERIODE_ETAT = 3           # s

# (identifiant, titre, icône, avancée) — titres traduits à la construction.
PAGES = (
    ("connexion", N_("Connexion"), "network-vpn-symbolic", False),
    ("fournisseurs", N_("Fournisseurs"), "network-server-symbolic", False),
    ("reglages", N_("Réglages"), "preferences-system-symbolic", False),
    ("diagnostic", N_("Diagnostic"), "katakomba-diagnostic-symbolic", False),
    ("journal", N_("Journal"), "view-list-symbolic", False),
    ("exclusions", N_("Exclusions"), "katakomba-exclusions-symbolic", True),
    ("lan", N_("Partage LAN"), "network-wired-symbolic", True),
    ("tor", N_("Tor"), "katakomba-tor-symbolic", True),
)


def titre_page(ident: str) -> str:
    return _(next(t for i, t, _ic, _a in PAGES if i == ident))


class Fenetre(Adw.ApplicationWindow):

    def __init__(self, app, veilleur=None):
        super().__init__(application=app, title="Katakomba",
                         default_width=1040, default_height=720)
        self.set_size_request(360, 480)
        self.config = modele.charger_config()
        self.prefs = modele.charger_preferences()
        self.mode_avance = modele.mode_avance_initial(self.config)
        self.service, self.statut = "unknown", {}
        self._lecture_en_cours = False
        # Repris d'une fenêtre précédente (changement de langue) : une
        # coupure en cours reste suivie.
        self.veilleur = veilleur or Veilleur()
        self._assistant_en_attente = False
        self.set_hide_on_close(self.prefs["arriere_plan"])
        self.connect("close-request", self._fermeture)
        self.connect("notify::visible", self._visibilite)

        # Import tardif : les pages ont besoin de la fenêtre déjà construite.
        from gui.page_connexion import PageConnexion
        from gui.page_diagnostic import PageDiagnostic
        from gui.page_exclusions import PageExclusions
        from gui.page_fournisseurs import PageFournisseurs
        from gui.page_journal import PageJournal
        from gui.page_lan import PageLan
        from gui.page_reglages import PageReglages
        from gui.page_tor import PageTor
        self._classes = {"connexion": PageConnexion, "fournisseurs": PageFournisseurs,
                         "reglages": PageReglages, "diagnostic": PageDiagnostic,
                         "journal": PageJournal, "exclusions": PageExclusions,
                         "lan": PageLan, "tor": PageTor}
        self.pages = {}

        self._construire()
        self._actions()
        self.appliquer_mode(self.mode_avance)
        self.aller("connexion")
        self._lire_etat()
        self._minuteur = GLib.timeout_add_seconds(PERIODE_ETAT, self._lire_etat)
        # Première utilisation : aucun fournisseur, l'assistant guide pas à
        # pas — dès que la fenêtre s'affiche (elle peut démarrer cachée).
        self._assistant_en_attente = not self.config.get("providers")

    def arreter_suivi(self):
        """Fenêtre remplacée (changement de langue) : plus de lecture d'état."""
        if self._minuteur:
            GLib.source_remove(self._minuteur)
            self._minuteur = 0

    # ── Construction ─────────────────────────────────────────────────────────

    def _construire(self):
        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        self.split = Adw.NavigationSplitView(min_sidebar_width=220,
                                             max_sidebar_width=280)
        self.toasts.set_child(self.split)

        # Barre latérale
        lat = Adw.ToolbarView()
        entete = Adw.HeaderBar()
        # Logo aux couleurs de l'interface (graphite) ; katakomba-nom.png reste la
        # version de marque, en cyan.
        nom = Gtk.Picture.new_for_filename(str(ASSETS / "katakomba-nom-graphite.png"))
        nom.set_content_fit(Gtk.ContentFit.CONTAIN)
        nom.set_can_shrink(True)
        nom.set_alternative_text("Katakomba")
        entete.set_title_widget(Adw.Clamp(maximum_size=128, child=nom))
        lat.add_top_bar(entete)

        boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.nav = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.nav.add_css_class("navigation-sidebar")
        self.nav_avancee = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.nav_avancee.add_css_class("navigation-sidebar")
        self.titre_avance = Gtk.Label(label=_("Avancé").upper(), xalign=0)
        self.titre_avance.add_css_class("section-laterale")
        boite.append(self.nav)
        boite.append(self.titre_avance)
        boite.append(self.nav_avancee)
        defil = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        defil.set_child(boite)
        lat.set_content(defil)
        self.split.set_sidebar(Adw.NavigationPage(title="Katakomba", child=lat))

        # Contenu
        # Non homogène : chaque page n'impose que SA largeur minimale, sinon
        # la plus large empêcherait la fenêtre de se rétrécir.
        self.pile = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE,
                              transition_duration=120, hhomogeneous=False,
                              vhomogeneous=False)
        self._rangees = {}
        for ident, titre, icone, avancee in PAGES:
            page = self._classes[ident](self)
            self.pages[ident] = page
            self.pile.add_named(page, ident)
            rangee = self._rangee_nav(ident, _(titre), icone)
            (self.nav_avancee if avancee else self.nav).append(rangee)
        self.nav.connect("row-activated", self._choisie)
        self.nav_avancee.connect("row-activated", self._choisie)

        contenu = Adw.ToolbarView()
        self.entete = Adw.HeaderBar()
        menu = Gio.Menu()
        menu.append(_("Mode avancé"), "win.avance")
        menu.append(_("Assistant de configuration"), "win.assistant")
        aide = Gio.Menu()
        aide.append(_("À propos de Katakomba"), "win.apropos")
        menu.append_section(None, aide)
        fin = Gio.Menu()
        fin.append(_("Quitter"), "app.quitter")
        menu.append_section(None, fin)
        self.entete.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic",
                                            menu_model=menu, primary=True,
                                            tooltip_text=_("Menu principal")))
        contenu.add_top_bar(self.entete)
        self.bandeau = Adw.Banner(
            title=_("Réglage enregistré : il sera appliqué au prochain démarrage "
                    "du service."), button_label=_("Redémarrer maintenant"))
        self.bandeau.connect("button-clicked", lambda _b: self.redemarrer_service())
        contenu.add_top_bar(self.bandeau)
        contenu.set_content(self.pile)
        self.page_contenu = Adw.NavigationPage(title=titre_page("connexion"), child=contenu)
        self.split.set_content(self.page_contenu)

        point_de_rupture = Adw.Breakpoint.new(
            Adw.BreakpointCondition.parse("max-width: 720sp"))
        point_de_rupture.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(point_de_rupture)

    def _rangee_nav(self, ident, titre, icone):
        ligne = Gtk.Box(spacing=12, margin_top=2, margin_bottom=2)
        image = Gtk.Image(icon_name=icone)
        image.add_css_class(f"nav-{ident}")
        ligne.append(image)
        ligne.append(Gtk.Label(label=titre, xalign=0, hexpand=True))
        if ident == "connexion":
            self.point = Gtk.Image(icon_name="media-record-symbolic", pixel_size=10)
            self.point.add_css_class("etat-arret")
            ligne.append(self.point)
        rangee = Gtk.ListBoxRow(child=ligne)
        rangee.ident = ident
        rangee.update_property([Gtk.AccessibleProperty.LABEL], [titre])
        self._rangees[ident] = rangee
        return rangee

    def _actions(self):
        avance = Gio.SimpleAction.new_stateful(
            "avance", None, GLib.Variant.new_boolean(self.mode_avance))
        avance.connect("change-state", self._basculer_mode)
        self.add_action(avance)
        for nom, rappel in (("assistant", self.ouvrir_assistant),
                            ("apropos", self._a_propos)):
            a = Gio.SimpleAction.new(nom, None)
            a.connect("activate", lambda _a, _p, r=rappel: r())
            self.add_action(a)

    # ── Navigation ───────────────────────────────────────────────────────────

    def _choisie(self, liste, rangee):
        autre = self.nav_avancee if liste is self.nav else self.nav
        autre.unselect_all()
        self.aller(rangee.ident, depuis_liste=True)

    def aller(self, ident, depuis_liste=False):
        if ident not in self.pages:
            return
        avancee = next(a for i, _t, _ic, a in PAGES if i == ident)
        if avancee and not self.mode_avance:
            return
        self.pile.set_visible_child_name(ident)
        self.page_contenu.set_title(titre_page(ident))
        if not depuis_liste:
            rangee = self._rangees[ident]
            liste = rangee.get_parent()
            (self.nav_avancee if liste is self.nav else self.nav).unselect_all()
            liste.select_row(rangee)
        self.split.set_show_content(True)
        montree = getattr(self.pages[ident], "montree", None)
        if montree:
            montree()

    def page_visible(self):
        """Page affichée ; None si la fenêtre est cachée (les pages cessent
        alors de relire le journal)."""
        return self.pile.get_visible_child_name() if self.get_visible() else None

    # ── Fenêtre cachée ───────────────────────────────────────────────────────

    def _visibilite(self, *_a):
        if not self.get_visible():
            return
        # De retour à l'écran : la page affichée se remet à jour.
        montree = getattr(self.pages[self.pile.get_visible_child_name()], "montree", None)
        if montree:
            montree()
        if self._assistant_en_attente:
            self._assistant_en_attente = False
            GLib.timeout_add(400, lambda: (self.ouvrir_assistant(), False)[1])

    def _fermeture(self, _fen):
        """Fermer ne fait que cacher : la première fois, dire où est passé
        Katakomba et comment le quitter vraiment."""
        if self.get_hide_on_close() and not self.prefs["avis_arriere_plan_vu"]:
            self.prefs["avis_arriere_plan_vu"] = True
            self.enregistrer_preferences()
            self.get_application().notifier_bureau(Avis(
                _("Katakomba veille en arrière-plan"),
                _("Il vous préviendra si la connexion tombe. Pour le quitter : "
                  "menu principal, Quitter."), ident="arriere-plan"))
        return False

    def enregistrer_preferences(self):
        try:
            modele.enregistrer_preferences(self.prefs)
        except OSError as e:
            self.notifier(_("Préférence non enregistrée : {erreur}").format(erreur=e))

    # ── Mode simple / avancé ─────────────────────────────────────────────────

    def _basculer_mode(self, action, valeur):
        action.set_state(valeur)
        self.mode_avance = valeur.get_boolean()
        self.config["advanced_mode"] = self.mode_avance
        self.enregistrer()
        self.appliquer_mode(self.mode_avance)
        self.notifier(_("Mode avancé activé") if self.mode_avance else _("Mode simple"))

    def appliquer_mode(self, avance: bool):
        self.titre_avance.set_visible(avance)
        self.nav_avancee.set_visible(avance)
        if not avance and self.pile.get_visible_child_name() in ("exclusions", "lan", "tor"):
            self.aller("reglages")
        for page in self.pages.values():
            if hasattr(page, "mode"):
                page.mode(avance)

    # ── Configuration ────────────────────────────────────────────────────────

    def enregistrer(self) -> bool:
        try:
            modele.enregistrer_config(self.config)
            return True
        except PermissionError:
            alerte(self, _("Enregistrement impossible"), modele.message_droits())
        except OSError as e:
            alerte(self, _("Enregistrement impossible"), str(e))
        return False

    def reglage_modifie(self):
        """Réglage lu par le daemon au démarrage : proposer de redémarrer."""
        if self.enregistrer() and self.service == "active":
            self.bandeau.set_revealed(True)

    def recharger(self, config: dict):
        """Configuration remplacée (import de sauvegarde) : tout est relu."""
        self.config = config
        for page in self.pages.values():
            if hasattr(page, "recharger"):
                page.recharger()

    def notifier(self, texte: str):
        self.toasts.add_toast(Adw.Toast(title=texte, timeout=3))

    # ── Service ──────────────────────────────────────────────────────────────

    def _lire_etat(self):
        if not self._lecture_en_cours:
            self._lecture_en_cours = True
            en_fond(lambda: (modele.etat_service(), modele.lire_statut()),
                    self._etat_lu)
        return True                                     # timer permanent

    def _etat_lu(self, resultat):
        self._lecture_en_cours = False
        # Fenêtre remplacée ou détruite entre-temps : plus rien à afficher.
        if isinstance(resultat, Exception) or not self._minuteur \
                or self.get_application() is None:
            return
        self.service, self.statut = resultat
        resume = modele.resume_etat(self.service, self.statut,
                                    len(self.config.get("providers", [])))
        for c in ("etat-ok", "etat-attente", "etat-erreur", "etat-arret"):
            self.point.remove_css_class(c)
        self.point.add_css_class(f"etat-{resume['niveau']}")
        self.point.set_tooltip_text(resume["titre"])
        self._rangees["connexion"].update_property(
            [Gtk.AccessibleProperty.DESCRIPTION], [resume["titre"]])
        if self.service != "active":
            self.bandeau.set_revealed(False)
        avis = self.veilleur.observer(self.service, self.statut, modele.maintenant(),
                                      discret=self.is_active())
        if self.prefs["notifications"]:
            for a in avis:
                self.get_application().notifier_bureau(a)
        for page in self.pages.values():
            if hasattr(page, "etat"):
                page.etat(self.service, self.statut, resume)

    def rafraichir_etat(self, delai_ms=800):
        GLib.timeout_add(delai_ms, lambda: (self._lire_etat(), False)[1])

    def piloter(self, action: str, fini=None):
        """start / stop / restart, hors de l'interface (sans mot de passe pour
        le groupe katakomba, sinon invite polkit du bureau)."""
        self.veilleur.action_utilisateur(modele.maintenant())

        def resultat(r):
            self.veilleur.action_utilisateur(modele.maintenant())
            if isinstance(r, Exception):
                alerte(self, _("Action impossible"), str(r))
            elif r.returncode == modele.ANNULE:
                self.notifier(_("Action annulée"))
            elif r.returncode != 0:
                alerte(self, _("Le service n'a pas répondu comme prévu"),
                       (r.stderr or "").strip() or _("Erreur inconnue."))
            elif action in ("start", "restart"):
                self.bandeau.set_revealed(False)
            self.rafraichir_etat()
            if fini:
                fini(r)
        en_fond(modele.piloter_service, resultat, action)

    def redemarrer_service(self):
        self.bandeau.set_revealed(False)
        self.piloter("restart")

    # ── Dialogues ────────────────────────────────────────────────────────────

    def ouvrir_assistant(self):
        from gui.assistant import Assistant
        Assistant(self).present(self)

    def _a_propos(self):
        d = Adw.AboutDialog(
            application_name="Katakomba", application_icon="katakomba",
            version=VERSION, developer_name="Katakomba",
            comments=_("Tout le trafic de la machine passe par un VPN, "
                       "lui-même encapsulé dans Tor.") + "\n\nSVB TERRA LIBERI",
            license_type=Gtk.License.MIT_X11)
        d.present(self)

