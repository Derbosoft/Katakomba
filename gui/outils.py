"""
Outils partagés par les pages : tâches en arrière-plan, boîtes de dialogue,
choix de fichiers, rangées de préférences.
"""

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from i18n import _  # noqa: E402


def en_fond(travail, rappel=None, *args):
    """Exécute travail(*args) hors du fil de l'interface (pkexec, journalctl,
    adaptation d'un fichier…), puis rappel(résultat) dans l'interface.
    Une exception devient le résultat : le rappel la reçoit et l'affiche."""
    def fil():
        try:
            resultat = travail(*args)
        except Exception as e:           # remonté à l'interface, pas perdu
            resultat = e
        if rappel is not None:
            GLib.idle_add(lambda: (rappel(resultat), False)[1])
    threading.Thread(target=fil, daemon=True).start()


def alerte(parent, titre, texte, reponses=None, defaut="ok",
           destructive=None, suggeree=None, rappel=None, extra=None):
    """Boîte de dialogue ; rappel(réponse) à la fermeture."""
    reponses = reponses or (("ok", _("OK")),)
    d = Adw.AlertDialog(heading=titre, body=texte)
    for rid, libelle in reponses:
        d.add_response(rid, libelle)
    if destructive:
        d.set_response_appearance(destructive, Adw.ResponseAppearance.DESTRUCTIVE)
    if suggeree:
        d.set_response_appearance(suggeree, Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response(defaut)
    d.set_close_response(reponses[0][0])
    if extra is not None:
        d.set_extra_child(extra)
    if rappel:
        d.connect("response", lambda _d, r: rappel(r))
    d.present(parent)
    return d


def confirmer(parent, titre, texte, libelle, rappel, destructif=True):
    """Confirmation à deux boutons ; rappel() seulement si l'utilisateur valide."""
    alerte(parent, titre, texte,
           reponses=(("annuler", _("Annuler")), ("oui", libelle)), defaut="annuler",
           destructive="oui" if destructif else None,
           suggeree=None if destructif else "oui",
           rappel=lambda r: r == "oui" and rappel())


def _filtre(nom, motifs):
    f = Gtk.FileFilter()
    f.set_name(nom)
    for m in motifs:
        f.add_pattern(m)
    return f


def _filtres(nom, motifs):
    liste = Gio.ListStore.new(Gtk.FileFilter)
    liste.append(_filtre(nom, motifs))
    liste.append(_filtre(_("Tous les fichiers"), ["*"]))
    return liste


def choisir_fichiers(parent, titre, nom, motifs, rappel, plusieurs=True):
    """rappel([chemins]) ; rien si l'utilisateur annule."""
    dlg = Gtk.FileDialog(title=titre, modal=True, filters=_filtres(nom, motifs))

    def fini(d, res):
        try:
            if plusieurs:
                modele = d.open_multiple_finish(res)
                chemins = [modele.get_item(i).get_path()
                           for i in range(modele.get_n_items())]
            else:
                chemins = [d.open_finish(res).get_path()]
        except GLib.Error:
            return                          # annulé
        chemins = [c for c in chemins if c]
        if chemins:
            rappel(chemins)

    if plusieurs:
        dlg.open_multiple(parent, None, fini)
    else:
        dlg.open(parent, None, fini)


def choisir_destination(parent, titre, nom_initial, nom, motifs, rappel):
    dlg = Gtk.FileDialog(title=titre, modal=True, initial_name=nom_initial,
                         filters=_filtres(nom, motifs))

    def fini(d, res):
        try:
            fichier = d.save_finish(res)
        except GLib.Error:
            return
        if fichier and fichier.get_path():
            rappel(fichier.get_path())

    dlg.save(parent, None, fini)


def bouton_icone(icone, info, rappel, *classes):
    b = Gtk.Button(icon_name=icone, tooltip_text=info, valign=Gtk.Align.CENTER)
    b.update_property([Gtk.AccessibleProperty.LABEL], [info])
    b.add_css_class("flat")
    for c in classes:
        b.add_css_class(c)
    b.connect("clicked", lambda _b: rappel())
    return b


def menu_actions(actions, info=None):
    """Bouton « ⋯ » ouvrant une liste d'actions [(libellé, rappel, actif,
    destructif)].  Évite une rangée de flèches qu'on confond avec celle qui
    déplie la ligne."""
    bouton = Gtk.MenuButton(icon_name="view-more-symbolic",
                            tooltip_text=info or _("Plus d'actions"),
                            valign=Gtk.Align.CENTER)
    bouton.add_css_class("flat")
    pop = Gtk.Popover()
    boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    for libelle, rappel, actif, destructif in actions:
        b = Gtk.Button(label=libelle, sensitive=actif)
        b.add_css_class("flat")
        if destructif:
            b.add_css_class("error")
        b.get_child().set_xalign(0)

        def clic(_b, r=rappel):
            pop.popdown()
            GLib.idle_add(lambda: (r(), False)[1])
        b.connect("clicked", clic)
        boite.append(b)
    pop.set_child(boite)
    bouton.set_popover(pop)
    return bouton


def numero(n):
    """Pastille de priorité (1, 2, 3…)."""
    l = Gtk.Label(label=str(n), valign=Gtk.Align.CENTER, width_chars=2)
    l.add_css_class("numero")
    return l


def rangee_bouton(titre, libelle, rappel, sous_titre="", *classes):
    """Rangée de préférences avec un bouton à droite."""
    r = Adw.ActionRow(title=titre, subtitle=sous_titre)
    b = Gtk.Button(label=libelle, valign=Gtk.Align.CENTER)
    for c in classes:
        b.add_css_class(c)
    b.connect("clicked", lambda _b: rappel())
    r.add_suffix(b)
    return r


def vider(conteneur):
    """Retire tous les enfants d'un Gtk.Box ou d'un Adw.PreferencesGroup."""
    enfants = []
    enfant = conteneur.get_first_child()
    while enfant is not None:
        enfants.append(enfant)
        enfant = enfant.get_next_sibling()
    for e in enfants:
        conteneur.remove(e)


class GroupeListe:
    """Groupe de préférences dont les rangées sont reconstruites à volonté.
    (Adw.PreferencesGroup ne permet pas de vider ses rangées directement.)"""

    def __init__(self, groupe: Adw.PreferencesGroup):
        self.groupe = groupe
        self.rangees = []

    def remplacer(self, rangees):
        for r in self.rangees:
            self.groupe.remove(r)
        self.rangees = list(rangees)
        for r in self.rangees:
            self.groupe.add(r)
