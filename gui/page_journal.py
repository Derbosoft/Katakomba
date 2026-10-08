"""
Journal : les dernières lignes du service, rafraîchies tant que la page est
visible.  Recherche, filtre par gravité, messages de routine de Tor masqués
par défaut, export du texte affiché.

Les lignes restent celles du daemon (en français) : c'est un journal
technique, cité tel quel dans un rapport.
"""

import re

from gi.repository import GLib, Gtk

from gui import modele
from gui.outils import alerte, choisir_destination, en_fond
from i18n import N_, _

PERIODE = 5        # s
LIGNES = 400       # affichées au plus
# Messages qui reviennent sans rien apprendre : ouvertures de connexion de
# contrôle de Tor (toutes les 30 s), vérification de la chaîne de certificats
# à chaque connexion d'OpenVPN.
ROUTINE = ("New control connection opened", "Bootstrapped ", "VERIFY ",
           "Validating certificate", "Certificate has EKU", "Control Channel:",
           "TLS: ", "Peer Connection Initiated", "OPTIONS IMPORT", "net_route_v4",
           "DEPRECATED OPTION", "library versions", "DCO version")
# « [2026-09-25 17:13:10] [INFO ] [openvpn] 2026-09-25 17:13:10 message »
_LIGNE = re.compile(r"\[\d{4}-\d\d-\d\d (\d\d:\d\d:\d\d)\] \[(\w+)\s*\] (.*)$")
# Horodatages recopiés par OpenVPN et par Tor dans leurs propres messages.
_HORODATAGE_INTERNE = re.compile(
    r"^(\[(openvpn|tor)\] )(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d |"
    r"\w{3} \d\d \d\d:\d\d:\d\d\.\d+ \[\w+\] )")
COULEURS = {"WARN": "#e6bd62", "ERROR": "#ec7383", "OK": "#62cf97"}
# (libellé, niveaux gardés) — None : tout.
GRAVITES = ((N_("Tous les messages"), None),
            (N_("Avertissements et erreurs"), ("WARN", "ERROR")),
            (N_("Erreurs seulement"), ("ERROR",)))


def filtrer(lignes, routine=True, gravite=None, recherche=""):
    """Lignes à afficher : [(heure, niveau, message)] ; les lignes que le
    format du daemon n'explique pas passent avec un niveau vide."""
    sortie = []
    recherche = recherche.strip().lower()
    for l in lignes:
        if routine and any(r in l for r in ROUTINE):
            continue
        m = _LIGNE.search(l)
        heure, niveau, message = m.groups() if m else ("", "", l)
        message = _HORODATAGE_INTERNE.sub(r"\1", message)
        if gravite and niveau not in gravite:
            continue
        if recherche and recherche not in message.lower():
            continue
        sortie.append((heure, niveau, message))
    return sortie[-LIGNES:]


class PageJournal(Gtk.Box):

    def __init__(self, fen):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.fen = fen
        self._lecture = False
        self._lignes = []
        self._affichees = []

        barre = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                        margin_top=10, margin_bottom=10, margin_start=14, margin_end=14)
        self.recherche = Gtk.SearchEntry(placeholder_text=_("Rechercher dans le journal"),
                                         hexpand=True)
        self.recherche.connect("search-changed", lambda _e: self._afficher())
        barre.append(self.recherche)

        filtres = Gtk.Box(spacing=8)
        self.gravite = Gtk.DropDown.new_from_strings([_(g) for g, _n in GRAVITES])
        self.gravite.set_tooltip_text(_("Gravité"))
        self.gravite.connect("notify::selected", lambda *_a: self._afficher())
        filtres.append(self.gravite)
        self.routine = Gtk.ToggleButton(icon_name="view-conceal-symbolic", active=True,
                                        tooltip_text=_("Masquer la routine (connexions de "
                                                       "contrôle de Tor, certificats…)"))
        self.routine.update_property([Gtk.AccessibleProperty.LABEL], [_("Masquer la routine")])
        self.routine.connect("toggled", lambda _b: self._afficher())
        filtres.append(self.routine)
        filtres.append(Gtk.Box(hexpand=True))
        self.suivi = Gtk.ToggleButton(active=True, tooltip_text=_("Suivi en direct"))
        self.suivi.update_property([Gtk.AccessibleProperty.LABEL], [_("Suivi en direct")])
        self.suivi.connect("toggled", self._suivi_change)
        self._icone_suivi()
        filtres.append(self.suivi)
        exporter = Gtk.Button(icon_name="document-save-symbolic",
                              tooltip_text=_("Exporter les lignes affichées"))
        exporter.update_property([Gtk.AccessibleProperty.LABEL],
                                 [_("Exporter les lignes affichées")])
        exporter.connect("clicked", lambda _b: self._exporter())
        filtres.append(exporter)
        for b in (self.routine, self.suivi, exporter):
            b.add_css_class("flat")
        barre.append(filtres)
        self.append(barre)

        self.defil = Gtk.ScrolledWindow(vexpand=True)
        self.texte = Gtk.TextView(editable=False, cursor_visible=False,
                                  monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                                  top_margin=8, bottom_margin=8,
                                  left_margin=14, right_margin=14)
        self.texte.add_css_class("technique")
        self.defil.set_child(self.texte)
        self.append(self.defil)
        GLib.timeout_add_seconds(PERIODE, self._periodique)

    def _icone_suivi(self):
        # L'icône montre l'action possible, comme un lecteur : pause pendant le suivi.
        self.suivi.set_icon_name("media-playback-pause-symbolic" if self.suivi.get_active()
                                 else "media-playback-start-symbolic")

    def _suivi_change(self, bouton):
        self._icone_suivi()
        if bouton.get_active():
            self.actualiser()

    def montree(self):
        self.actualiser()

    def _periodique(self):
        if self.fen.page_visible() == "journal" and self.suivi.get_active():
            self.actualiser()
        return True

    def actualiser(self):
        if not self._lecture:
            self._lecture = True
            # Lecture large puis filtrage : les messages de routine peuvent
            # occuper des centaines de lignes d'affilée.
            en_fond(modele.lire_journal, self._lu, 4000)

    def _lu(self, lignes):
        self._lecture = False
        self._lignes = [] if isinstance(lignes, Exception) else lignes
        self._afficher()

    def _afficher(self):
        tampon = self.texte.get_buffer()
        table = tampon.get_tag_table()
        for niveau, couleur in COULEURS.items():
            if table.lookup(niveau) is None:
                tampon.create_tag(niveau, foreground=couleur)
        if table.lookup("heure") is None:
            tampon.create_tag("heure", foreground="#8c8c94")
        tampon.set_text("")
        if not self._lignes:
            tampon.insert(tampon.get_end_iter(),
                          _("Journal vide ou illisible pour ce compte (groupes adm ou "
                            "systemd-journal requis)."))
            self._affichees = []
            return
        self._affichees = filtrer(self._lignes, self.routine.get_active(),
                                  GRAVITES[self.gravite.get_selected()][1],
                                  self.recherche.get_text())
        if not self._affichees:
            tampon.insert(tampon.get_end_iter(), _("Aucune ligne ne correspond aux filtres."))
            return
        for heure, niveau, message in self._affichees:
            if heure:
                tampon.insert_with_tags_by_name(tampon.get_end_iter(), heure + "  ", "heure")
            if niveau in COULEURS:
                tampon.insert_with_tags_by_name(tampon.get_end_iter(), message + "\n", niveau)
            else:
                tampon.insert(tampon.get_end_iter(), message + "\n")
        GLib.idle_add(self._en_bas)

    def _en_bas(self):
        adj = self.defil.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())
        return False

    def _exporter(self):
        texte = "\n".join(f"{h}  [{n}] {m}" if h else m for h, n, m in self._affichees)

        def vers(chemin):
            try:
                with open(chemin, "w", encoding="utf-8") as f:
                    f.write(texte + "\n")
            except OSError as e:
                alerte(self.fen, _("Export impossible"), str(e))
                return
            self.fen.notifier(_("Journal exporté : {fichier}").format(
                fichier=GLib.path_get_basename(chemin)))
        choisir_destination(self.fen, _("Exporter le journal"), "katakomba-journal.txt",
                            _("Texte"), ["*.txt", "*.log"], vers)
