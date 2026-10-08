"""
Katakomba — interface graphique (GTK 4 + libadwaita).

Le daemon (katakomba.service) gère Tor + OpenVPN de façon autonome ; cette
interface écrit la configuration et pilote le service.  Elle tourne sans
root : la configuration est accessible via le groupe « katakomba », les
actions privilégiées passent par polkit.

Fermer la fenêtre la cache seulement (réglable) : l'interface continue de
veiller sur la connexion et prévient par une notification du bureau.

Usage : katakomba gui [--arriere-plan]   (ou : python3 main.py)
        --arriere-plan : démarre sans ouvrir la fenêtre (ouverture de session)
"""

import grp
import os
import pwd
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, Gtk  # noqa: E402

import i18n  # noqa: E402
from constants import CONFIG_DIR, SCRIPT_DIR  # noqa: E402
from i18n import _  # noqa: E402

APP_ID = "org.katakomba.Katakomba"
ADW_MINIMUM = (1, 5)


def message_acces() -> str:
    """Pourquoi ce compte ne peut pas écrire la configuration, en clair.

    Deux cas très différents pour l'utilisateur : inscrit dans le groupe
    katakomba mais session ouverte AVANT l'installation (il suffit de la
    rouvrir), ou pas inscrit du tout (un administrateur doit l'autoriser)."""
    moi = pwd.getpwuid(os.getuid()).pw_name
    try:
        inscrit = moi in grp.getgrnam("katakomba").gr_mem
    except KeyError:
        inscrit = False
    if inscrit:
        return _("Dernière étape de l'installation : fermez votre session puis "
                 "rouvrez-la (ou redémarrez l'ordinateur). Votre compte vient de "
                 "recevoir l'accès à Katakomba, mais la session en cours a été "
                 "ouverte avant.")
    return _("Ce compte n'a pas accès à la configuration ({dossier}). Un "
             "administrateur de la machine peut vous l'accorder :\n\n"
             "sudo katakomba autoriser {compte}\n\n"
             "puis fermez et rouvrez votre session.").format(dossier=CONFIG_DIR, compte=moi)


def acces_refuse() -> bool:
    return os.geteuid() != 0 and CONFIG_DIR.exists() and not os.access(CONFIG_DIR, os.W_OK)


class KatakombaApp(Adw.Application):

    def __init__(self, arriere_plan=False):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._cache_au_lancement = arriere_plan

    def do_startup(self):
        Adw.Application.do_startup(self)
        # Identité visuelle : toujours sombre, quel que soit le thème du bureau.
        Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        affichage = Gdk.Display.get_default()
        css = Gtk.CssProvider()
        css.load_from_path(str(SCRIPT_DIR / "gui" / "style.css"))
        Gtk.StyleContext.add_provider_for_display(
            affichage, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        # Icône : installée dans hicolor ; en développement, lue dans assets/.
        theme = Gtk.IconTheme.get_for_display(affichage)
        theme.add_search_path(str(SCRIPT_DIR / "assets"))
        theme.add_search_path(str(SCRIPT_DIR / "assets" / "icones"))   # icônes symboliques
        Gtk.Window.set_default_icon_name("katakomba")
        # Actions aussi déclenchées depuis les notifications du bureau.
        for nom, rappel in (("quitter", self.quit),
                            ("afficher", self.activate),
                            ("reconnecter", self._reconnecter)):
            a = Gio.SimpleAction.new(nom, None)
            a.connect("activate", lambda _a, _p, r=rappel: r())
            self.add_action(a)

    def do_activate(self):
        # get_windows et non get_active_window : la fenêtre cachée compte.
        fenetres = self.get_windows()
        fen = fenetres[0] if fenetres else None
        if fen is None:
            if acces_refuse():
                fen = self._fenetre_acces()
            else:
                from gui.fenetre import Fenetre
                fen = Fenetre(self)
                if getattr(self, "_cache_au_lancement", False):
                    # Ouverture de session : la fenêtre existe (et veille),
                    # elle s'affichera au premier lancement suivant.
                    self._cache_au_lancement = False
                    return
        fen.present()

    def _reconnecter(self):
        from gui.fenetre import Fenetre
        fen = next((f for f in self.get_windows() if isinstance(f, Fenetre)), None)
        if fen is not None:
            fen.piloter("start")

    def notifier_bureau(self, avis):
        """Notification GNOME (ou freedesktop).  GNOME ne l'affiche que si un
        lanceur porte le nom de l'application : org.katakomba.Katakomba.desktop."""
        if avis.retirer:
            self.withdraw_notification(avis.ident)
            return
        n = Gio.Notification.new(avis.titre)
        if avis.corps:
            n.set_body(avis.corps)
        n.set_icon(Gio.ThemedIcon.new("katakomba"))
        n.set_priority(Gio.NotificationPriority.HIGH if avis.urgent
                       else Gio.NotificationPriority.NORMAL)
        n.set_default_action("app.afficher")
        if avis.bouton == "reconnecter":
            n.add_button(_("Se connecter"), "app.reconnecter")
        self.send_notification(avis.ident, n)

    def changer_langue(self, code: str):
        """Nouvelle langue ("" : celle du système) : la fenêtre est
        reconstruite dans cette langue, à la même page et à la même taille.
        Les textes propres à GTK suivront au prochain lancement."""
        from gui.fenetre import Fenetre
        choisir_langue_gtk(code)            # avant : activer("") relit LANGUAGE
        i18n.activer(code)
        ancienne = next((f for f in self.get_windows() if isinstance(f, Fenetre)), None)
        if ancienne is None:
            return
        page = ancienne.pile.get_visible_child_name()
        nouvelle = Fenetre(self, veilleur=ancienne.veilleur)
        nouvelle.set_default_size(ancienne.get_width(), ancienne.get_height())
        if ancienne.is_maximized():
            nouvelle.maximize()
        nouvelle.aller(page)
        nouvelle.present()
        ancienne.arreter_suivi()
        ancienne.destroy()
        nouvelle.notifier(_("Langue : {langue}").format(langue=i18n.LANGUES[i18n.langue()]))

    def _fenetre_acces(self):
        fen = Adw.ApplicationWindow(application=self, title="Katakomba",
                                    default_width=560, default_height=440)
        vue = Adw.ToolbarView()
        vue.add_top_bar(Adw.HeaderBar())
        page = Adw.StatusPage(icon_name="system-lock-screen-symbolic",
                              title=_("Accès à Katakomba"), description=message_acces())
        fermer = Gtk.Button(label=_("Fermer"), halign=Gtk.Align.CENTER)
        fermer.add_css_class("pill")
        fermer.connect("clicked", lambda _b: fen.close())
        page.set_child(fermer)
        vue.set_content(page)
        fen.set_content(vue)
        return fen


def choisir_langue_gtk(code: str):
    """Textes propres à GTK et libadwaita (boîtes de fichiers, « Annuler »…)
    dans la langue choisie : gettext les lit dans LANGUAGE."""
    if code:
        os.environ["LANGUAGE"] = code
    elif "KATAKOMBA_LANGUAGE_SYSTEME" in os.environ:
        os.environ["LANGUAGE"] = os.environ["KATAKOMBA_LANGUAGE_SYSTEME"]


def main() -> int:
    from gui import modele
    # LANGUAGE d'origine, pour revenir à « langue du système » sans relancer.
    os.environ.setdefault("KATAKOMBA_LANGUAGE_SYSTEME", os.environ.get("LANGUAGE", ""))
    langue = modele.charger_preferences()["langue"]
    choisir_langue_gtk(langue)
    i18n.activer(langue)
    if (Adw.get_major_version(), Adw.get_minor_version()) < ADW_MINIMUM:
        print(_("Katakomba requiert libadwaita {version} ou plus récent "
                "(Ubuntu 24.04+, Debian 13+).").format(version="%d.%d" % ADW_MINIMUM),
              file=sys.stderr)
        return 1
    arriere_plan = "--arriere-plan" in sys.argv[1:]
    argv = [a for a in sys.argv if a != "--arriere-plan"]
    return KatakombaApp(arriere_plan).run(argv)
