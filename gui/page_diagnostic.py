"""
Diagnostic : « katakomba doctor » en un clic, en lecture seule, présenté
comme une liste de contrôles avec un verdict.  Trois états : accueil (rien
de lancé), diagnostic en cours, résultats.
"""

from gi.repository import Adw, Gdk, Gtk

import i18n
from gui import modele
from gui.outils import GroupeListe, en_fond
from i18n import _, ngettext

ICONES = {"ok": ("object-select-symbolic", "etat-ok"),
          "attention": ("dialog-warning-symbolic", "warning"),
          "erreur": ("dialog-error-symbolic", "etat-erreur"),
          "attente": ("view-refresh-symbolic", "etat-attente"),
          "reporte": ("content-loading-symbolic", "dim-label")}
# Verdict selon le code de sortie de doctor : 0 conforme, 1 problème,
# 2 reconnexion en cours.
VERDICTS = {0: ("object-select-symbolic", "etat-ok"),
            1: ("dialog-error-symbolic", "etat-erreur"),
            2: ("view-refresh-symbolic", "etat-attente")}
SYMBOLES = {"ok": "OK", "attention": "WARN", "erreur": "KO", "attente": "…", "reporte": "--"}


class PageDiagnostic(Gtk.Stack):

    def __init__(self, fen):
        super().__init__(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.fen = fen
        self._rapport = ""

        accueil = Adw.StatusPage(
            icon_name="katakomba-diagnostic-symbolic",
            title=_("Vérifier la protection"),
            description=_("Routage, DNS, fuites possibles, relais Tor protégés, sortie "
                          "réelle vers Internet. Rien n'est modifié, aucun mot de "
                          "passe n'est demandé."))
        lancer = Gtk.Button(label=_("Lancer le diagnostic"), halign=Gtk.Align.CENTER)
        lancer.add_css_class("pill")
        lancer.add_css_class("suggested-action")
        lancer.connect("clicked", lambda _b: self.lancer())
        accueil.set_child(lancer)
        self.add_named(accueil, "accueil")

        attente = Adw.StatusPage(title=_("Diagnostic en cours…"),
                                 description=_("Une vingtaine de secondes : la sortie "
                                               "vers Internet est testée pour de vrai."))
        spinner = Gtk.Spinner(width_request=32, height_request=32, halign=Gtk.Align.CENTER)
        spinner.start()
        attente.set_child(spinner)
        self.add_named(attente, "attente")

        page = Adw.PreferencesPage()
        entete = Adw.PreferencesGroup()
        carte = Gtk.Box(spacing=16)
        carte.add_css_class("card")
        carte.add_css_class("carte-etat")
        # hexpand/vexpand explicites : sinon l'expansion de l'icône remonte
        # jusqu'à la carte, qui s'étire quand il y a peu de contrôles.
        self.pastille = Gtk.Box(valign=Gtk.Align.CENTER, halign=Gtk.Align.START,
                                hexpand=False, vexpand=False)
        self.pastille.add_css_class("pastille-etat")
        self.icone = Gtk.Image(pixel_size=26, hexpand=True, vexpand=True,
                               halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.pastille.append(self.icone)
        carte.append(self.pastille)
        textes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True,
                         valign=Gtk.Align.CENTER)
        self.verdict = Gtk.Label(xalign=0, wrap=True)
        self.verdict.add_css_class("title-3")
        self.conclusion = Gtk.Label(xalign=0, wrap=True, selectable=True)
        self.conclusion.add_css_class("dim-label")
        textes.append(self.verdict)
        textes.append(self.conclusion)
        carte.append(textes)
        entete.add(carte)
        page.add(entete)

        self.groupe = Adw.PreferencesGroup(title=_("Contrôles"))
        boutons = Gtk.Box(spacing=6)
        copier = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text=_("Copier le rapport"),
                            valign=Gtk.Align.CENTER)
        copier.add_css_class("flat")
        copier.update_property([Gtk.AccessibleProperty.LABEL], [_("Copier le rapport")])
        copier.connect("clicked", lambda _b: self._copier())
        relancer = Gtk.Button(valign=Gtk.Align.CENTER)
        relancer.set_child(Adw.ButtonContent(icon_name="view-refresh-symbolic",
                                             label=_("Relancer")))
        relancer.add_css_class("flat")
        relancer.connect("clicked", lambda _b: self.lancer())
        boutons.append(copier)
        boutons.append(relancer)
        self.groupe.set_header_suffix(boutons)
        self.resultats = GroupeListe(self.groupe)
        page.add(self.groupe)
        self.add_named(page, "resultats")
        self.set_visible_child_name("accueil")

    def lancer(self):
        self.set_visible_child_name("attente")
        en_fond(modele.lancer_diagnostic, self._fini, i18n.langue())

    def _fini(self, r):
        if isinstance(r, Exception):
            resultats, conclusion, code = [], _("Diagnostic impossible : {erreur}").format(
                erreur=r), 1
        else:
            resultats, conclusion, code = r
        n_ko = sum(1 for n, _t, _d in resultats if n == "erreur")
        n_warn = sum(1 for n, _t, _d in resultats if n == "attention")
        if code == 2:
            verdict = _("Reconnexion en cours")
        elif n_ko:
            verdict = ngettext("{n} problème à corriger", "{n} problèmes à corriger",
                               n_ko).format(n=n_ko)
        elif not resultats:
            verdict = _("Diagnostic impossible")
        elif n_warn:
            verdict = ngettext("Protégé, {n} point à surveiller",
                               "Protégé, {n} points à surveiller", n_warn).format(n=n_warn)
        else:
            verdict = _("Tout est conforme")
        icone, classe = VERDICTS.get(code, VERDICTS[1])
        self.icone.set_from_icon_name(icone)
        for w in (self.pastille, self.verdict):
            for c in ("etat-ok", "etat-erreur", "etat-attente"):
                w.remove_css_class(c)
            w.add_css_class(classe)
        self.verdict.set_label(verdict)
        self.conclusion.set_label(conclusion)
        self.conclusion.set_visible(bool(conclusion))

        rangees = []
        for niveau, titre, detail in resultats:
            r = Adw.ActionRow(title=titre, subtitle=detail)
            r.set_subtitle_selectable(True)
            icone, classe = ICONES.get(niveau, ICONES["reporte"])
            img = Gtk.Image(icon_name=icone)
            img.add_css_class(classe)
            r.add_prefix(img)
            rangees.append(r)
        self.groupe.set_visible(bool(rangees))
        self.resultats.remplacer(rangees)
        self._rapport = "\n".join([f"Katakomba — {verdict}", ""]
                                  + [f"[{SYMBOLES.get(n, '?')}] {t} — {d}"
                                     for n, t, d in resultats]
                                  + ["", conclusion])
        self.set_visible_child_name("resultats")

    def _copier(self):
        Gdk.Display.get_default().get_clipboard().set(self._rapport)
        self.fen.notifier(_("Rapport copié"))
