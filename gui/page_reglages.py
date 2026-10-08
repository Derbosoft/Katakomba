"""
Réglages : comportement de la connexion, démarrage, sécurité, qualité du
circuit (mode avancé), interface (propre au compte), sauvegarde et
dépannage.  Enregistrés aussitôt.
"""

from gi.repository import Adw, GLib, Gtk

import i18n
from gui import modele, veilleur
from gui.outils import (alerte, choisir_destination, choisir_fichiers,
                        confirmer, en_fond, rangee_bouton)
from i18n import _

# Ordre du sélecteur : langue du système, puis chaque langue sous son nom.
CODES_LANGUE = ("", *i18n.LANGUES)


class PageReglages(Adw.PreferencesPage):

    def __init__(self, fen):
        super().__init__()
        self.fen = fen
        self._charge = False

        g = Adw.PreferencesGroup(title=_("Connexion"))
        self.auto = self._interrupteur(
            g, "auto_reconnect", _("Reconnexion automatique"),
            _("Rétablir la connexion dès qu'elle tombe."))
        self.hasard = self._interrupteur(
            g, "random_account", _("Choisir un compte au hasard"),
            _("Parmi les comptes du fournisseur. L'ordre des fournisseurs, lui, "
              "reste celui de la liste."))
        self.add(g)

        g = Adw.PreferencesGroup(title=_("Démarrage"))
        self.demarrage = Adw.SwitchRow(
            title=_("Se connecter au démarrage de l'ordinateur"),
            subtitle=_("Le mot de passe administrateur est demandé pour changer "
                       "ce réglage."))
        self.demarrage.connect("notify::active", self._demarrage_change)
        g.add(self.demarrage)
        self.add(g)

        g = Adw.PreferencesGroup(
            title=_("Interface"),
            description=_("Propres à votre compte, sans mot de passe."))
        noms = [_("Langue du système")] + list(i18n.LANGUES.values())
        self.langue = Adw.ComboRow(title=_("Langue"), model=Gtk.StringList.new(noms))
        self.langue.connect("notify::selected", self._langue_change)
        g.add(self.langue)
        self.arriere_plan = Adw.SwitchRow(
            title=_("Continuer en arrière-plan"),
            subtitle=_("Fermer la fenêtre laisse Katakomba veiller sur la connexion. "
                       "Pour le quitter : menu principal, Quitter."))
        self.arriere_plan.connect("notify::active", self._arriere_plan_change)
        g.add(self.arriere_plan)
        self.notifications = Adw.SwitchRow(
            title=_("Prévenir en cas de coupure"),
            subtitle=_("Notification si la connexion tombe plus de {n} s, puis quand "
                       "elle revient, ou si le service s'arrête.").format(
                           n=veilleur.SEUIL_COUPURE))
        self.notifications.connect("notify::active", self._notifications_change)
        g.add(self.notifications)
        self.session = Adw.SwitchRow(
            title=_("Lancer à l'ouverture de session"),
            subtitle=_("Discrètement, sans ouvrir la fenêtre."))
        self.session.connect("notify::active", self._session_change)
        g.add(self.session)
        self.add(g)

        g = Adw.PreferencesGroup(title=_("Sécurité"))
        self.ipv6 = self._interrupteur(
            g, "block_ipv6", _("Bloquer IPv6 pendant la connexion"),
            _("Le tunnel ne transporte que l'IPv4 : sans ce blocage, le trafic "
              "IPv6 sortirait à découvert."))
        self.add(g)

        self.circuit = Adw.PreferencesGroup(
            title=_("Qualité du circuit Tor"),
            description=_("Une seule mesure de 2 Mo juste après la connexion : un "
                          "circuit trop lent est aussitôt remplacé. Aucune "
                          "surveillance continue."))
        self.mesure = self._interrupteur(
            self.circuit, "circuit_check", _("Mesurer le débit à la connexion"), "")
        self.seuil = Adw.SpinRow.new_with_range(0, 10000, 50)
        self.seuil.set_title(_("Débit minimum (Ko/s)"))
        self.seuil.connect("notify::value", self._seuil_change)
        self.circuit.add(self.seuil)
        self.essais = Adw.SpinRow.new_with_range(1, 10, 1)
        self.essais.set_title(_("Nouveaux tirages au plus"))
        self.essais.set_subtitle(_("Avant de garder le circuit tel quel : mieux "
                                   "vaut un tunnel lent qu'une boucle de reconnexions."))
        self.essais.connect("notify::value", self._essais_change)
        self.circuit.add(self.essais)
        self.add(self.circuit)

        g = Adw.PreferencesGroup(
            title=_("Sauvegarde"),
            description=_("Fournisseurs, comptes, fichiers de configuration et "
                          "réglages de Tor, dans un seul fichier .katakomba. Les "
                          "identifiants n'y sont pas chiffrés : gardez-le en lieu sûr."))
        g.add(rangee_bouton(_("Exporter la configuration"), _("Exporter…"), self._exporter))
        g.add(rangee_bouton(_("Importer une sauvegarde"), _("Importer…"), self._importer,
                            _("Remplace la configuration actuelle.")))
        self.add(g)

        g = Adw.PreferencesGroup(title=_("Dépannage"))
        g.add(rangee_bouton(
            _("Réparer le réseau"), _("Réparer…"), self._reparer,
            _("Retire les règles de pare-feu, routes et DNS laissés par une coupure, "
              "puis arrête le service."), "destructive-action"))
        self.add(g)

        self.recharger()

    # ── Liaison avec la configuration ────────────────────────────────────────

    def _interrupteur(self, groupe, cle, titre, sous_titre):
        r = Adw.SwitchRow(title=titre, subtitle=sous_titre)
        r.connect("notify::active", self._bascule, cle)
        groupe.add(r)
        return r

    def recharger(self):
        c = self.fen.config
        self._charge = True
        try:
            self.auto.set_active(c.get("auto_reconnect", True))
            self.hasard.set_active(c.get("random_account", True))
            self.ipv6.set_active(c.get("block_ipv6", False))
            self.mesure.set_active(c.get("circuit_check", True))
            self.seuil.set_value(int(c.get("circuit_min_kbs", 250)))
            self.essais.set_value(int(c.get("circuit_max_retries", 3)))
            self.demarrage.set_active(c.get("autostart", False))
            p = self.fen.prefs
            self.langue.set_selected(CODES_LANGUE.index(p["langue"]))
            self.arriere_plan.set_active(p["arriere_plan"])
            self.notifications.set_active(p["notifications"])
            self.session.set_active(modele.lancement_session_actif())
            self.session.set_sensitive(p["arriere_plan"])
        finally:
            self._charge = False
        self._maj_seuil()
        # L'état réel de systemd fait foi (modifiable hors de l'interface).
        en_fond(modele.demarrage_auto_actif, self._demarrage_lu)

    def _demarrage_lu(self, actif):
        if isinstance(actif, bool) and actif != self.demarrage.get_active():
            self._charge = True
            self.demarrage.set_active(actif)
            self._charge = False

    def mode(self, avance):
        self.circuit.set_visible(avance)

    def _bascule(self, rangee, _p, cle):
        if self._charge:
            return
        self.fen.config[cle] = rangee.get_active()
        self.fen.reglage_modifie()

    def _maj_seuil(self):
        self.seuil.set_subtitle(_("≈ {debit} sur un test de débit").format(
            debit=modele.kbs_en_mbps(self.seuil.get_value())))

    def _seuil_change(self, *_args):
        self._maj_seuil()
        if not self._charge:
            self.fen.config["circuit_min_kbs"] = int(self.seuil.get_value())
            self.fen.reglage_modifie()

    def _essais_change(self, *_args):
        if not self._charge:
            self.fen.config["circuit_max_retries"] = int(self.essais.get_value())
            self.fen.reglage_modifie()

    def _demarrage_change(self, *_args):
        if self._charge:
            return
        voulu = self.demarrage.get_active()

        def fini(r):
            if isinstance(r, Exception) or r.returncode != 0:
                self._charge = True
                self.demarrage.set_active(not voulu)      # rien n'a changé
                self._charge = False
                if not isinstance(r, Exception) and r.returncode == modele.ANNULE:
                    self.fen.notifier(_("Action annulée"))
                else:
                    alerte(self.fen, _("Réglage impossible"),
                           str(r) if isinstance(r, Exception) else
                           (r.stderr or "").strip() or _("Erreur inconnue."))
                return
            self.fen.config["autostart"] = voulu
            self.fen.enregistrer()
            self.fen.notifier(_("Connexion au démarrage activée") if voulu
                              else _("Connexion au démarrage désactivée"))
        en_fond(modele.regler_demarrage_auto, fini, voulu)

    # ── Interface ────────────────────────────────────────────────────────────

    def _langue_change(self, *_a):
        if self._charge:
            return
        code = CODES_LANGUE[self.langue.get_selected()]
        self.fen.prefs["langue"] = code
        self.fen.enregistrer_preferences()
        # La fenêtre est reconstruite dans la nouvelle langue : après ce
        # rappel, pas pendant (le sélecteur appartient à l'ancienne fenêtre).
        GLib.idle_add(lambda: (self.fen.get_application().changer_langue(code), False)[1])

    def _arriere_plan_change(self, *_args):
        if self._charge:
            return
        actif = self.arriere_plan.get_active()
        self.fen.prefs["arriere_plan"] = actif
        self.fen.set_hide_on_close(actif)
        self.fen.enregistrer_preferences()
        # Lancé caché à l'ouverture de session, sans arrière-plan : absurde.
        self.session.set_sensitive(actif)
        if not actif and self.session.get_active():
            self.session.set_active(False)

    def _notifications_change(self, *_args):
        if not self._charge:
            self.fen.prefs["notifications"] = self.notifications.get_active()
            self.fen.enregistrer_preferences()

    def _session_change(self, *_args):
        if self._charge:
            return
        actif = self.session.get_active()
        try:
            modele.regler_lancement_session(actif)
        except OSError as e:
            self._charge = True
            self.session.set_active(not actif)
            self._charge = False
            alerte(self.fen, _("Réglage impossible"), str(e))
            return
        self.fen.notifier(_("Katakomba se lancera à l'ouverture de session") if actif
                          else _("Plus de lancement à l'ouverture de session"))

    # ── Sauvegarde ───────────────────────────────────────────────────────────

    def _exporter(self):
        def vers(chemin):
            if not chemin.endswith(".katakomba"):
                chemin += ".katakomba"
            try:
                modele.exporter(self.fen.config, chemin)
            except OSError as e:
                alerte(self.fen, _("Export impossible"), str(e))
                return
            self.fen.notifier(_("Configuration exportée : {fichier}").format(
                fichier=GLib.path_get_basename(chemin)))
        choisir_destination(self.fen, _("Exporter la configuration"),
                            _("sauvegarde") + ".katakomba", _("Sauvegarde Katakomba"),
                            ["*.katakomba"], vers)

    def _importer(self):
        # .tvpn : sauvegardes d'avant le changement de nom, même format.
        choisir_fichiers(self.fen, _("Importer une sauvegarde"), _("Sauvegarde Katakomba"),
                         ["*.katakomba", "*.tvpn"],
                         lambda chemins: confirmer(
                             self.fen, _("Remplacer la configuration ?"),
                             _("Fournisseurs, comptes et réglages actuels seront "
                               "remplacés par ceux de la sauvegarde."), _("Remplacer"),
                             lambda: self._importer_depuis(chemins[0])),
                         plusieurs=False)

    def _importer_depuis(self, chemin):
        try:
            nouvelle, ecartes = modele.lire_sauvegarde(chemin)
        except Exception as e:
            alerte(self.fen, _("Import impossible"), str(e))
            return
        self.fen.recharger(nouvelle)
        self.fen.reglage_modifie()
        if ecartes:
            alerte(self.fen, _("Import partiel"),
                   _("Configuration importée, sauf :") + "\n\n" + "\n".join(ecartes))
        else:
            self.fen.notifier(_("Configuration importée"))

    # ── Dépannage ────────────────────────────────────────────────────────────

    def _reparer(self):
        def lancer():
            def fini(r):
                if isinstance(r, Exception):
                    alerte(self.fen, _("Réparation impossible"), str(r))
                elif r.returncode == modele.ANNULE:
                    self.fen.notifier(_("Action annulée"))
                else:
                    alerte(self.fen, _("Réseau réparé"),
                           _("Le service est arrêté. Reconnectez-vous depuis "
                             "l'écran Connexion."))
                self.fen.rafraichir_etat()
            self.fen.veilleur.action_utilisateur(modele.maintenant(), 120)
            en_fond(modele.lancer_reparation, fini)
        confirmer(self.fen, _("Réparer le réseau ?"),
                  _("Le service va s'arrêter et toutes les règles réseau de "
                    "Katakomba seront nettoyées. Le mot de passe administrateur "
                    "sera demandé."),
                  _("Réparer"), lancer)
