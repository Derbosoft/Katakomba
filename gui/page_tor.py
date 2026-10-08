"""
Tor (mode avancé) : réglages du torrc, avec le fichier complet en mode
expert.  Les réglages et le texte restent synchronisés : une ligne que les
réglages ne savent pas représenter est conservée telle quelle.
"""

from gi.repository import Adw, Gtk

from gui import modele
from gui.outils import alerte, confirmer
from i18n import N_, _

# Titres et explications traduits à la construction de la page ; les noms
# d'options du torrc (LongLivedPorts…) ne se traduisent pas.
DRAPEAUX_CIRCUIT = (
    ("long_lived", N_("Relais stables pour OpenVPN"), "LongLivedPorts 1194,443", ""),
    ("learn_timeout", N_("Délai de construction fixe"), "LearnCircuitBuildTimeout 0",
     N_("plus prévisible")),
)
ENTIERS = (
    ("max_dirty", N_("Durée de vie d'un circuit (s)"), "MaxCircuitDirtiness",
     N_("0 : défaut de Tor"), 0, 7200, 60),
    ("build_timeout", N_("Délai de construction (s)"), "CircuitBuildTimeout",
     N_("0 : désactivé"), 0, 300, 5),
    ("new_circuit", N_("Préparation d'un nouveau circuit (s)"), "NewCircuitPeriod",
     N_("0 : défaut de Tor"), 0, 600, 10),
    ("keepalive", N_("Maintien de connexion (s)"), "KeepalivePeriod",
     N_("0 : désactivé"), 0, 300, 10),
    ("num_guards", N_("Nombre de relais d'entrée"), "NumEntryGuards",
     N_("0 : défaut de Tor"), 0, 10, 1),
)
DRAPEAUX_VIE_PRIVEE = (
    ("avoid_disk", N_("Limiter les écritures sur le disque"), "AvoidDiskWrites 1", ""),
    ("safe_logging", N_("Masquer les adresses dans le journal de Tor"), "SafeLogging 1", ""),
    ("no_ipv6", N_("Tor sans IPv6"), "ClientUseIPv6 0", ""),
    ("test_socks", N_("Signaler les requêtes DNS locales"), "TestSocks 1", ""),
    ("conn_padding", N_("Rembourrage du trafic"), "ConnectionPadding 1",
     N_("résiste à l'analyse de trafic, consomme plus")),
)
DUREES = (N_("Défaut de Tor"), N_("1 mois"), N_("2 mois"), N_("3 mois"), N_("6 mois"))


def _sous_titre(option, note):
    return f"{option} — {_(note)}" if note else option


class PageTor(Gtk.Box):

    def __init__(self, fen):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.fen = fen
        self._sync = False
        self.champs = {}

        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        g = Adw.PreferencesGroup(
            title=_("Circuits"),
            description=_("Les valeurs par défaut privilégient des circuits longs "
                          "et stables, adaptés à un tunnel VPN permanent."))
        for cle, titre, option, note in DRAPEAUX_CIRCUIT:
            g.add(self._drapeau(cle, _(titre), _sous_titre(option, note)))
        for cle, titre, option, note, bas, haut, pas in ENTIERS:
            r = Adw.SpinRow.new_with_range(bas, haut, pas)
            r.set_title(_(titre))
            r.set_subtitle(_sous_titre(option, note))
            r.connect("notify::value", self._change)
            self.champs[cle] = r
            g.add(r)
        self.duree = Adw.ComboRow(title=_("Durée de vie des relais d'entrée"),
                                  subtitle="GuardLifetime",
                                  model=Gtk.StringList.new([_(d) for d in DUREES]))
        self.duree.connect("notify::selected", self._change)
        g.add(self.duree)
        page.add(g)

        g = Adw.PreferencesGroup(title=_("Confidentialité"))
        for cle, titre, option, note in DRAPEAUX_VIE_PRIVEE:
            g.add(self._drapeau(cle, _(titre), _sous_titre(option, note)))
        page.add(g)

        g = Adw.PreferencesGroup(
            title=_("Pays de sortie exclus"),
            description=_("Codes ISO entre accolades, séparés par des virgules : "
                          "{exemple}. Vide : aucun.").format(exemple="{us},{gb},{ca}"))
        self.sorties = Adw.EntryRow(title="ExcludeExitNodes")
        self.sorties.connect("changed", self._change)
        g.add(self.sorties)
        g.add(self._drapeau("strict_nodes", _("Exclusion stricte"),
                            _sous_titre("StrictNodes 1", N_("peut empêcher toute "
                                                            "connexion si aucun relais "
                                                            "ne convient"))))
        page.add(g)

        g = Adw.PreferencesGroup(
            title=_("Mode expert"),
            description=_("Le torrc complet. Les lignes que les réglages ci-dessus "
                          "ne représentent pas sont conservées. Les paramètres "
                          "obligatoires sont toujours garantis."))
        cadre = Gtk.Frame()
        defil = Gtk.ScrolledWindow(min_content_height=220, max_content_height=420,
                                   propagate_natural_height=True)
        self.texte = Gtk.TextView(monospace=True, top_margin=10, bottom_margin=10,
                                  left_margin=12, right_margin=12,
                                  wrap_mode=Gtk.WrapMode.NONE)
        self.texte.add_css_class("technique")
        focus = Gtk.EventControllerFocus()
        # Quitter le texte recale les réglages : l'édition manuelle n'est pas perdue.
        focus.connect("leave", lambda _c: self._reglages_depuis_texte())
        self.texte.add_controller(focus)
        defil.set_child(self.texte)
        cadre.set_child(defil)
        g.add(cadre)
        page.add(g)

        barre = Gtk.ActionBar()
        reinit = Gtk.Button(label=_("Réinitialiser"))
        reinit.connect("clicked", lambda _b: self._reinitialiser())
        barre.pack_start(reinit)
        appliquer = Gtk.Button(label=_("Appliquer et redémarrer"))
        appliquer.add_css_class("suggested-action")
        appliquer.connect("clicked", lambda _b: self._appliquer())
        barre.pack_end(appliquer)
        self.append(barre)
        self.recharger()

    def _drapeau(self, cle, titre, detail):
        r = Adw.SwitchRow(title=titre, subtitle=detail)
        r.connect("notify::active", self._change)
        self.champs[cle] = r
        return r

    # ── Réglages ⇄ texte ─────────────────────────────────────────────────────

    def _poser(self, valeurs):
        self._sync = True
        try:
            for cle, w in self.champs.items():
                v = valeurs[cle]
                if isinstance(w, Adw.SwitchRow):
                    w.set_active(bool(v))
                else:
                    w.set_value(int(v))
            d = valeurs["guard_lifetime"]
            self.duree.set_selected(modele.TOR_DUREES_GARDE.index(d)
                                    if d in modele.TOR_DUREES_GARDE else 0)
            self.sorties.set_text(valeurs["exclude_exits"])
        finally:
            self._sync = False

    def _lire(self) -> dict:
        v = {}
        for cle, w in self.champs.items():
            v[cle] = (w.get_active() if isinstance(w, Adw.SwitchRow)
                      else int(w.get_value()))
        v["guard_lifetime"] = modele.TOR_DUREES_GARDE[self.duree.get_selected()]
        v["exclude_exits"] = self.sorties.get_text().strip()
        return v

    def _texte(self) -> str:
        b = self.texte.get_buffer()
        return b.get_text(b.get_start_iter(), b.get_end_iter(), False)

    def _ecrire_texte(self, contenu):
        self.texte.get_buffer().set_text(contenu)

    def _change(self, *_args):
        """Un réglage a changé : le texte est régénéré, ses lignes
        personnelles comprises."""
        if self._sync:
            return
        _valeurs, extras = modele.lire_torrc(self._texte())
        self._ecrire_texte(modele.construire_torrc(self._lire(), extras))

    def _reglages_depuis_texte(self):
        valeurs, _extras = modele.lire_torrc(self._texte())
        self._poser(modele.completer_valeurs_tor(valeurs))

    def recharger(self):
        contenu = modele.lire_torrc_fichier()
        if contenu:
            valeurs, _extras = modele.lire_torrc(contenu)
            self._poser(modele.completer_valeurs_tor(valeurs))
            self._ecrire_texte(contenu)
        else:
            self._poser(modele.TOR_DEFAUTS)
            self._ecrire_texte(modele.construire_torrc(modele.TOR_DEFAUTS))

    # ── Actions ──────────────────────────────────────────────────────────────

    def _appliquer(self):
        try:
            refus = modele.enregistrer_torrc(self._texte())
        except PermissionError:
            alerte(self.fen, _("Enregistrement impossible"), modele.message_droits())
            return
        except OSError as e:
            alerte(self.fen, _("Enregistrement impossible"), str(e))
            return
        if refus:
            alerte(self.fen, _("Ce torrc serait refusé"),
                   _("Tor le lit en root au démarrage : le daemon refuserait "
                     "ces lignes.") + "\n\n" + "\n".join(refus[:10])
                   + "\n\n" + _("Retirez-les puis réessayez."))
            return
        self.recharger()
        self.fen.notifier(_("Réglages de Tor enregistrés — redémarrage…"))
        self.fen.redemarrer_service()

    def _reinitialiser(self):
        def faire():
            try:
                modele.supprimer_torrc()
            except OSError as e:
                alerte(self.fen, _("Réinitialisation impossible"), str(e))
                return
            self.recharger()
            self.fen.notifier(_("Réglages de Tor réinitialisés — redémarrage…"))
            self.fen.redemarrer_service()
        confirmer(self.fen, _("Réinitialiser les réglages de Tor ?"),
                  _("Le torrc personnalisé est supprimé : Tor redémarre avec la "
                    "configuration de base de Katakomba."), _("Réinitialiser"), faire)
