"""
Accueil : l'état de la connexion, le trajet du trafic (cet ordinateur →
Tor → VPN → Internet), un seul bouton pour se connecter ou se déconnecter,
les chiffres utiles et ce qui s'est passé récemment.

Fenêtre étroite : le trajet passe à la verticale et le bouton sous l'état
(Adw.BreakpointBin, selon la largeur de la page et non de la fenêtre).

Mouvement : il ne montre que ce qui se passe vraiment.  Connecté, un paquet
parcourt le trajet de temps en temps et les étapes établies brillent ;
pendant une connexion, l'étape en cours tourne et respire (Tor : anneau de
progression de son démarrage), le trait qui y mène s'anime, et chaque étape
s'illumine d'un éclat au moment où elle s'établit.
Les animations libadwaita s'arrêtent d'elles-mêmes quand la page n'est pas
affichée ou quand GNOME demande de réduire les animations.
"""

import math

import cairo
from gi.repository import Adw, GLib, Graphene, Gtk, Pango

from gui import modele
from gui.outils import GroupeListe, en_fond
from i18n import _

NIVEAUX = ("etat-ok", "etat-attente", "etat-erreur", "etat-arret", "etat-info")
ICONES = {"ok": "object-select-symbolic", "attente": "view-refresh-symbolic",
          "erreur": "dialog-error-symbolic", "arret": "system-shutdown-symbolic",
          "info": "media-playback-start-symbolic"}
ICONES_ETAT = {"ok": "network-vpn-symbolic", "attente": "network-vpn-acquiring-symbolic",
               "erreur": "dialog-error-symbolic", "arret": "network-vpn-disabled-symbolic"}
PERIODE_EVENEMENTS = 20    # s
DUREE_PAQUET = 1800        # ms : traversée du trajet par un paquet
PAUSE_PAQUET = 2600        # ms entre deux paquets
DUREE_TOUR = 1400          # ms : un tour de l'anneau d'attente
DUREE_ECLAT = 900          # ms : une étape qui s'établit s'illumine
LARGEUR_MOYENNE = 700      # px : en dessous, chiffres sur deux lignes
LARGEUR_ETROITE = 520      # px : en dessous, trajet vertical


def _niveau(widget, niveau):
    for c in NIVEAUX:
        widget.remove_css_class(c)
    widget.add_css_class(f"etat-{niveau}")


def _rgba(widget, alpha=1.0):
    c = widget.get_color()
    return c.red, c.green, c.blue, c.alpha * alpha


class _Pastille(Gtk.Box):
    """Cercle d'icône d'une étape.  En attente : un arc tourne autour
    (rotation, 0-1) et un halo respire ; avec une progression connue (Tor),
    l'arc la montre.  Quand l'étape s'établit : un éclat (0-1) s'étend."""

    HALO = 12           # px au-delà du cercle

    def __init__(self):
        super().__init__(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.rotation = None
        self.progression = None
        self.eclat = None
        cible = Adw.CallbackAnimationTarget.new(self._eclat)
        self.animation_eclat = Adw.TimedAnimation.new(self, 0, 1, DUREE_ECLAT, cible)
        self.animation_eclat.set_easing(Adw.Easing.EASE_OUT_CUBIC)
        self.animation_eclat.connect("done", lambda _a: self._eclat(None))

    def _eclat(self, v):
        self.eclat = v
        self.queue_draw()

    def illuminer(self):
        self.animation_eclat.reset()
        self.animation_eclat.play()

    def _halo(self, cr, cx, cy, rayon, etendue, alpha):
        couleur = _rgba(self)
        halo = cairo.RadialGradient(cx, cy, rayon, cx, cy, rayon + etendue)
        halo.add_color_stop_rgba(0, *couleur[:3], alpha * couleur[3])
        halo.add_color_stop_rgba(1, *couleur[:3], 0)
        cr.set_source(halo)
        cr.arc(cx, cy, rayon + etendue, 0, 2 * math.pi)
        cr.fill()

    def do_snapshot(self, snap):
        w, h = self.get_width(), self.get_height()
        cx, cy, rayon = w / 2, h / 2, min(w, h) / 2 - 0.5
        marge = self.HALO + 4
        if self.rotation is not None or self.eclat is not None:
            # Sous l'icône : le halo ne doit pas la voiler.
            fond = snap.append_cairo(Graphene.Rect().init(-marge, -marge, w + 2 * marge,
                                                           h + 2 * marge))
            if self.rotation is not None:           # respiration : deux par tour
                souffle = 0.5 - 0.5 * math.cos(4 * math.pi * self.rotation)
                self._halo(fond, cx, cy, rayon, self.HALO * (0.6 + 0.4 * souffle),
                           0.18 + 0.30 * souffle)
            if self.eclat is not None:
                self._halo(fond, cx, cy, rayon, self.HALO * (0.5 + 1.2 * self.eclat),
                           0.75 * (1 - self.eclat))
        Gtk.Box.do_snapshot(self, snap)
        if self.eclat is not None:                  # anneau qui s'éloigne
            cr = snap.append_cairo(Graphene.Rect().init(-marge * 2, -marge * 2,
                                                         w + 4 * marge, h + 4 * marge))
            couleur = _rgba(self)
            cr.set_source_rgba(*couleur[:3], 0.8 * (1 - self.eclat) * couleur[3])
            cr.set_line_width(1.5)
            cr.arc(cx, cy, rayon + 2 + 16 * self.eclat, 0, 2 * math.pi)
            cr.stroke()
        if self.rotation is None and self.progression is None:
            return
        cr = snap.append_cairo(Graphene.Rect().init(-2, -2, w + 4, h + 4))
        cr.set_line_width(2.5)
        cr.set_line_cap(1)                                  # cairo.LINE_CAP_ROUND
        if self.progression is not None:
            debut = -math.pi / 2
            fin = debut + 2 * math.pi * max(self.progression, 0.02)
        else:
            debut = 2 * math.pi * self.rotation - math.pi / 2
            fin = debut + math.pi / 2
        cr.set_source_rgba(*_rgba(self))
        cr.arc(cx, cy, rayon, debut, fin)
        cr.stroke()


class _Noeud(Gtk.Box):
    """Une étape du trajet : pastille d'icône, nom, état."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                         halign=Gtk.Align.CENTER, width_request=96)
        self.pastille = _Pastille()
        self.pastille.add_css_class("noeud-icone")
        self.icone = Gtk.Image(pixel_size=20, hexpand=True, vexpand=True,
                               halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.pastille.append(self.icone)
        self.append(self.pastille)
        self.textes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                              halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.titre = Gtk.Label(justify=Gtk.Justification.CENTER, xalign=0.5,
                               ellipsize=Pango.EllipsizeMode.END, max_width_chars=16)
        self.titre.add_css_class("noeud-titre")
        self.detail = Gtk.Label(justify=Gtk.Justification.CENTER, xalign=0.5,
                                ellipsize=Pango.EllipsizeMode.END, max_width_chars=18)
        self.detail.add_css_class("caption")
        self.detail.add_css_class("dim-label")
        self.textes.append(self.titre)
        self.textes.append(self.detail)
        self.append(self.textes)
        self._niveau = None

    def poser(self, etape):
        self.icone.set_from_icon_name(etape["icone"])
        self.titre.set_label(etape["titre"])
        self.detail.set_label(etape["detail"])
        self.set_tooltip_text(f"{etape['titre']} — {etape['detail']}")
        _niveau(self.pastille, etape["niveau"])
        self.pastille.add_css_class(f"etape-{etape['cle']}")    # teinte propre
        self.pastille.progression = etape.get("progression") or None
        self.pastille.queue_draw()
        # L'étape vient de s'établir (pas à l'ouverture de la fenêtre).
        if etape["niveau"] == "ok" and self._niveau in ("attente", "arret", "erreur"):
            self.pastille.illuminer()
        self._niveau = etape["niveau"]

    def etroit(self, bp):
        """Réglages du mode vertical : icône à gauche, textes alignés à gauche."""
        bp.add_setter(self, "orientation", Gtk.Orientation.HORIZONTAL)
        bp.add_setter(self, "halign", Gtk.Align.START)
        bp.add_setter(self, "spacing", 14)
        bp.add_setter(self.textes, "halign", Gtk.Align.START)
        for l in (self.titre, self.detail):
            bp.add_setter(l, "xalign", 0.0)
            bp.add_setter(l, "justify", Gtk.Justification.LEFT)
            bp.add_setter(l, "max-width-chars", 40)


class _Lien(Gtk.Box):
    """Trait entre deux étapes, coloré selon l'état de celle qu'il atteint.

    position (0-1, None = rien) : tête d'une trace lumineuse qui le parcourt,
    queue comprise ; un paquet (blanc cassé) ou l'attente (couleur du trait)."""

    QUEUE = 36          # px

    def __init__(self):
        # Aligné sur le centre des pastilles (44 px) : 21 px sous le haut.
        super().__init__(hexpand=True, valign=Gtk.Align.START, margin_top=21,
                         height_request=2)
        self.add_css_class("lien")
        self.position = None
        self.paquet = False

    def placer(self, position, paquet=False):
        if position != self.position:
            self.position, self.paquet = position, paquet
            self.queue_draw()

    def do_snapshot(self, snap):
        if self.position is None:
            return
        w, h = self.get_width(), self.get_height()
        horizontal = w >= h
        longueur = w if horizontal else h
        tete = self.position * longueur
        if tete - self.QUEUE > longueur or tete < 0:
            return
        cr = snap.append_cairo(Graphene.Rect().init(-6, -6, w + 12, h + 12))
        if not horizontal:                      # trajet vertical : on pivote
            cr.translate(w, 0)
            cr.rotate(math.pi / 2)
        epaisseur = h if horizontal else w
        couleur = (0.93, 0.95, 0.94, 1.0) if self.paquet else _rgba(self)
        cr.rectangle(0, -6, longueur, epaisseur + 12)
        cr.clip()
        trace = cairo.LinearGradient(tete - self.QUEUE, 0, tete, 0)
        trace.add_color_stop_rgba(0, *couleur[:3], 0)
        trace.add_color_stop_rgba(1, *couleur[:3], 0.95 * couleur[3])
        cr.set_source(trace)
        cr.rectangle(tete - self.QUEUE, 0, self.QUEUE, epaisseur)
        cr.fill()
        if tete <= longueur:
            halo = cairo.RadialGradient(tete, epaisseur / 2, 0, tete, epaisseur / 2, 6)
            halo.add_color_stop_rgba(0, *couleur[:3], 0.9 * couleur[3])
            halo.add_color_stop_rgba(1, *couleur[:3], 0)
            cr.set_source(halo)
            cr.arc(tete, epaisseur / 2, 6, 0, 2 * math.pi)
            cr.fill()

    def etroit(self, bp):
        bp.add_setter(self, "hexpand", False)
        bp.add_setter(self, "halign", Gtk.Align.START)
        bp.add_setter(self, "valign", Gtk.Align.FILL)
        bp.add_setter(self, "margin-top", 0)
        bp.add_setter(self, "margin-start", 21)
        bp.add_setter(self, "width-request", 2)
        bp.add_setter(self, "height-request", 18)


class _Tuile(Gtk.Box):

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("card")
        self.add_css_class("tuile")
        self.titre = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END,
                               max_width_chars=18)
        self.titre.add_css_class("tuile-titre")
        self.valeur = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END,
                                max_width_chars=12)
        self.valeur.add_css_class("tuile-valeur")
        self.detail = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END,
                                max_width_chars=20)
        self.detail.add_css_class("caption")
        self.detail.add_css_class("dim-label")
        for w in (self.titre, self.valeur, self.detail):
            self.append(w)

    def poser(self, t):
        self.titre.set_label(t["titre"].upper())
        self.valeur.set_label(t["valeur"])
        self.detail.set_label(t["detail"])
        self.set_tooltip_text(t["detail"])
        self.add_css_class(f"tuile-{t['cle']}")


class PageConnexion(Adw.BreakpointBin):

    def __init__(self, fen):
        # BreakpointBin : la taille minimale doit être donnée explicitement.
        # Il enveloppe le défilement (et non l'inverse) : dedans, il imposait
        # sa hauteur et écrasait le contenu au lieu de le laisser défiler.
        # Deux seuils ; quand les deux s'appliquent, le dernier ajouté
        # l'emporte : l'étroit reprend donc aussi les réglages du moyen.
        super().__init__(width_request=300, height_request=400)
        self.fen = fen
        self._action = None
        self._occupe = False
        self._derniers = None

        moyen = Adw.Breakpoint.new(Adw.BreakpointCondition.parse(
            f"max-width: {LARGEUR_MOYENNE}px"))
        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse(
            f"max-width: {LARGEUR_ETROITE}px"))
        self.add_breakpoint(moyen)
        self.add_breakpoint(bp)
        clamp = Adw.Clamp(maximum_size=760, margin_top=24, margin_bottom=24,
                          margin_start=16, margin_end=16)
        defilement = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        defilement.set_child(clamp)
        self.set_child(defilement)
        boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        clamp.set_child(boite)

        # ── Carte d'état ─────────────────────────────────────────────────────
        carte = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=26)
        carte.add_css_class("card")
        carte.add_css_class("carte-etat")
        boite.append(carte)

        entete = Gtk.Box(spacing=16)
        self.pastille = Gtk.Box(valign=Gtk.Align.CENTER, halign=Gtk.Align.START)
        self.pastille.add_css_class("pastille-etat")
        self.icone_etat = Gtk.Image(pixel_size=26, hexpand=True, vexpand=True,
                                    halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        self.pastille.append(self.icone_etat)
        entete.append(self.pastille)
        textes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4,
                         hexpand=True, valign=Gtk.Align.CENTER)
        self.titre = Gtk.Label(label="…", xalign=0, wrap=True)
        self.titre.add_css_class("titre-etat")
        self.detail = Gtk.Label(xalign=0, wrap=True)
        self.detail.add_css_class("dim-label")
        textes.append(self.titre)
        textes.append(self.detail)
        entete.append(textes)

        actions = Gtk.Box(spacing=8, valign=Gtk.Align.CENTER)
        self.relancer = Gtk.Button(icon_name="view-refresh-symbolic",
                                   tooltip_text=_("Redémarrer la connexion"),
                                   valign=Gtk.Align.CENTER, visible=False)
        self.relancer.add_css_class("circular")
        self.relancer.add_css_class("flat")
        self.relancer.update_property([Gtk.AccessibleProperty.LABEL],
                                      [_("Redémarrer la connexion")])
        self.relancer.connect("clicked", lambda _b: self._lancer("restart"))
        actions.append(self.relancer)
        self.bouton = Gtk.Button()
        self.bouton.add_css_class("connexion")
        self.bouton.connect("clicked", lambda _b: self._agir())
        contenu_bouton = Gtk.Box(spacing=10, halign=Gtk.Align.CENTER)
        self.attente = Gtk.Spinner(visible=False)
        self.libelle = Gtk.Label()
        contenu_bouton.append(self.attente)
        contenu_bouton.append(self.libelle)
        self.bouton.set_child(contenu_bouton)
        actions.append(self.bouton)
        entete.append(actions)
        carte.append(entete)

        # Fenêtre étroite : le bouton passe sous l'état, sur toute la largeur.
        bp.add_setter(entete, "orientation", Gtk.Orientation.VERTICAL)
        bp.add_setter(entete, "spacing", 14)
        bp.add_setter(actions, "halign", Gtk.Align.FILL)
        bp.add_setter(self.bouton, "hexpand", True)

        self.trajet = Gtk.Box()
        self.noeuds, self.liens = [], []
        for i in range(4):
            if i:
                lien = _Lien()
                lien.etroit(bp)
                self.liens.append(lien)
                self.trajet.append(lien)
            noeud = _Noeud()
            noeud.etroit(bp)
            self.noeuds.append(noeud)
            self.trajet.append(noeud)
        bp.add_setter(self.trajet, "orientation", Gtk.Orientation.VERTICAL)
        carte.append(self.trajet)

        # ── Chiffres ─────────────────────────────────────────────────────────
        # Quatre tuiles sur une ligne, ou deux lignes de deux : jamais 3 + 1.
        self.grille = Gtk.Box(spacing=12, homogeneous=True)
        self.tuiles = []
        for _i in range(2):
            paire = Gtk.Box(spacing=12, homogeneous=True)
            for _j in range(2):
                t = _Tuile()
                self.tuiles.append(t)
                paire.append(t)
            self.grille.append(paire)
        for point in (moyen, bp):
            point.add_setter(self.grille, "orientation", Gtk.Orientation.VERTICAL)
        boite.append(self.grille)

        # ── Événements ───────────────────────────────────────────────────────
        groupe = Adw.PreferencesGroup(
            title=_("Derniers événements"),
            description=_("Ce que Katakomba a fait récemment pour garder la connexion."))
        tout = Gtk.Button(label=_("Journal complet"), valign=Gtk.Align.CENTER)
        tout.add_css_class("flat")
        tout.connect("clicked", lambda _b: self.fen.aller("journal"))
        groupe.set_header_suffix(tout)
        self.evenements = GroupeListe(groupe)
        boite.append(groupe)

        GLib.timeout_add_seconds(PERIODE_EVENEMENTS, self._evenements_periodiques)
        self._lire_evenements()
        self._animations()

    # ── État ─────────────────────────────────────────────────────────────────

    def etat(self, service, st, resume):
        niveau = resume["niveau"]
        self.titre.set_label(resume["titre"])
        self.detail.set_label(resume["detail"])
        _niveau(self.titre, niveau)
        _niveau(self.pastille, niveau)
        self.icone_etat.set_from_icon_name(ICONES_ETAT.get(niveau, ICONES_ETAT["arret"]))

        nb = len(self.fen.config.get("providers", []))
        etapes = modele.trajet(service, st, nb)
        for noeud, etape in zip(self.noeuds, etapes):
            noeud.poser(etape)
        for lien, etape in zip(self.liens, etapes[1:]):
            _niveau(lien, etape["niveau"])
            lien.add_css_class(f"vers-{etape['cle']}")
        self._mouvement(etapes)
        for tuile, t in zip(self.tuiles, modele.tuiles(service, st)):
            tuile.poser(t)
        self.grille.set_visible(nb > 0)

        self._action = resume["action"]
        if not self._occupe:
            self._montrer_bouton()
        self.relancer.set_visible(service == "active" and not self._occupe)

        # Un changement d'état vaut un nouvel événement probable.
        cle = (niveau, resume["titre"])
        if cle != self._derniers:
            self._derniers = cle
            self._lire_evenements()

    # ── Mouvement ────────────────────────────────────────────────────────────

    def _animations(self):
        self._connecte = False
        self._attentes = []           # étapes en attente : leur anneau tourne
        self._flux = None             # trait qui mène à la première d'entre elles
        cible = Adw.CallbackAnimationTarget.new(self._paquet_avance)
        self.paquet = Adw.TimedAnimation.new(self, 0, len(self.liens), DUREE_PAQUET, cible)
        self.paquet.set_easing(Adw.Easing.EASE_IN_OUT_SINE)
        self.paquet.connect("done", self._paquet_fini)
        self._pause = None
        cible = Adw.CallbackAnimationTarget.new(self._tour)
        self.horloge = Adw.TimedAnimation.new(self, 0, 1, DUREE_TOUR, cible)
        self.horloge.set_easing(Adw.Easing.LINEAR)
        self.horloge.set_repeat_count(0)                    # sans fin
        self.horloge.connect("done", lambda _a: self._tour(None))
        # Page cachée (autre page, fenêtre fermée) : tout s'arrête ; au retour,
        # on repart de l'état connu.
        self.connect("unmap", lambda _w: self._tout_arreter())
        self.connect("map", lambda _w: self._reprendre())

    def _mouvement(self, etapes):
        self._connecte = all(e["niveau"] == "ok" for e in etapes)
        # Seule la première étape en attente travaille : les suivantes
        # attendent leur tour, et s'allumeront l'une après l'autre.
        attente = [i for i, e in enumerate(etapes) if e["niveau"] == "attente"][:1]
        self._attentes = [self.noeuds[i].pastille for i in attente]
        self._flux = self.liens[attente[0] - 1] if attente and attente[0] else None
        self._reprendre()

    def _reprendre(self):
        if not self.get_mapped():
            return
        if self._connecte:
            if self.paquet.get_state() != Adw.AnimationState.PLAYING and self._pause is None:
                self.paquet.play()
        else:
            self._arreter_paquet()
        for n in self.noeuds:
            if n.pastille not in self._attentes and n.pastille.rotation is not None:
                n.pastille.rotation = None
                n.pastille.queue_draw()
        for l in self.liens:
            if l is not self._flux and not self._connecte:
                l.placer(None)
        if self._attentes:
            if self.horloge.get_state() != Adw.AnimationState.PLAYING:
                self.horloge.play()
        else:
            self.horloge.reset()

    def _arreter_paquet(self):
        if self._pause is not None:
            GLib.source_remove(self._pause)
            self._pause = None
        self.paquet.reset()
        for l in self.liens:
            l.placer(None)

    def _tout_arreter(self):
        self._arreter_paquet()
        self.horloge.reset()

    def _paquet_avance(self, v):
        for i, lien in enumerate(self.liens):
            u = v - i
            visible = 0 <= u <= 1 + lien.QUEUE / max(lien.get_width(), lien.get_height(), 1)
            lien.placer(u if visible else None, paquet=True)

    def _paquet_fini(self, _a):
        for l in self.liens:
            l.placer(None)
        if self._connecte and self.get_mapped() and self._pause is None:
            self._pause = GLib.timeout_add(PAUSE_PAQUET, self._paquet_relance)

    def _paquet_relance(self):
        self._pause = None
        if self._connecte and self.get_mapped():
            self.paquet.reset()
            self.paquet.play()
        return False

    def _tour(self, v):
        for p in self._attentes:
            p.rotation = v
            p.queue_draw()
        if self._flux is not None:
            # Deux passages par tour : le trait « travaille ».
            self._flux.placer(None if v is None else (2 * v) % 1 * 1.4, paquet=False)

    def _montrer_bouton(self):
        for c in ("suggested-action", "destructive-action"):
            self.bouton.remove_css_class(c)
        libelle, classe = {
            "demarrer": (_("Se connecter"), "suggested-action"),
            "arreter": (_("Se déconnecter"), None),
            "configurer": (_("Ajouter mon fournisseur"), "suggested-action"),
        }.get(self._action, (_("Se connecter"), "suggested-action"))
        self.libelle.set_label(libelle)
        if classe:
            self.bouton.add_css_class(classe)
        self.attente.set_visible(False)
        self.attente.stop()
        self.bouton.set_sensitive(True)

    def _agir(self):
        if self._action == "configurer":
            self.fen.ouvrir_assistant()
        elif self._action == "arreter":
            self._lancer("stop")
        else:
            self._lancer("start")

    def _lancer(self, action):
        self._occupe = True
        self.bouton.set_sensitive(False)
        self.relancer.set_visible(False)
        self.attente.set_visible(True)
        self.attente.start()
        self.libelle.set_label({"start": _("Connexion…"), "stop": _("Déconnexion…"),
                                "restart": _("Redémarrage…")}[action])

        def fini(_r):
            self._occupe = False
            self._montrer_bouton()
        self.fen.piloter(action, fini)

    # ── Événements ───────────────────────────────────────────────────────────

    def _evenements_periodiques(self):
        if self.fen.page_visible() == "connexion":
            self._lire_evenements()
        return True

    def _lire_evenements(self):
        en_fond(modele.lire_evenements, self._afficher_evenements, 8)

    def _afficher_evenements(self, liste):
        if isinstance(liste, Exception):
            liste = []
        rangees = []
        aujourdhui = GLib.DateTime.new_now_local().format("%Y-%m-%d")
        for date, heure, niveau, texte in liste:
            r = Adw.ActionRow(title=texte)
            icone = Gtk.Image(icon_name=ICONES.get(niveau, "dialog-information-symbolic"))
            icone.add_css_class(f"etat-{niveau}")
            r.add_prefix(icone)
            if date == aujourdhui:
                quand = heure
            else:
                quand = _("{jour}/{mois} {heure}").format(jour=date[8:10], mois=date[5:7],
                                                          heure=heure)
            h = Gtk.Label(label=quand)
            h.add_css_class("heure")
            r.add_suffix(h)
            rangees.append(r)
        if not rangees:
            rangees = [Adw.ActionRow(title=_("Aucun événement récent"),
                                     subtitle=_("Le journal du service est vide ou "
                                                "illisible pour ce compte."))]
        self.evenements.remplacer(rangees)
