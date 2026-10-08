"""
Assistant de configuration : du fichier du fournisseur au tunnel actif, en
trois étapes, sans connaître le vocabulaire (torrc, CIDR, split DNS…).

  1. Fournisseur   nom + fichier(s) téléchargé(s) — adaptés automatiquement
  2. Identifiants  identifiant et mot de passe OpenVPN
  3. Connexion     enregistrement, démarrage du service, suivi en direct

Ouvert d'office au premier lancement (aucun fournisseur), et à la demande.
La logique (contrôles, lecture de l'état) est dans gui/modele.py.
"""

import time

from gi.repository import Adw, GLib, Gtk

from gui import modele
from gui.outils import choisir_fichiers, en_fond
from i18n import _, ngettext

DELAI_MAX = 300      # s : au-delà, la connexion « prend trop de temps »


def _page(titre, contenu, bouton):
    """Étape : en-tête (avec retour automatique), contenu, bouton d'action."""
    vue = Adw.ToolbarView()
    vue.add_top_bar(Adw.HeaderBar())
    defil = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
    clamp = Adw.Clamp(maximum_size=480, margin_top=12, margin_bottom=12,
                      margin_start=18, margin_end=18)
    clamp.set_child(contenu)
    defil.set_child(clamp)
    vue.set_content(defil)
    bas = Gtk.Box(margin_top=12, margin_bottom=18, margin_start=18, margin_end=18,
                  halign=Gtk.Align.END)
    bouton.add_css_class("suggested-action")
    bouton.add_css_class("pill")
    bas.append(bouton)
    vue.add_bottom_bar(bas)
    return Adw.NavigationPage(title=titre, child=vue)


def _intro(boite, titre, texte):
    t = Gtk.Label(label=titre, xalign=0, wrap=True)
    t.add_css_class("title-2")
    boite.append(t)
    a = Gtk.Label(label=texte, xalign=0, wrap=True, margin_bottom=6)
    a.add_css_class("dim-label")
    boite.append(a)


class Assistant(Adw.Dialog):

    def __init__(self, fen):
        super().__init__(title=_("Assistant de configuration"),
                         content_width=560, content_height=600)
        self.fen = fen
        self.resultat = None
        self.chemins = ()
        self._debut = 0.0
        self._termine = False
        self.vue = Adw.NavigationView()
        self.set_child(self.vue)
        self.vue.add(self._etape_fournisseur())

    # ── 1. Fournisseur ───────────────────────────────────────────────────────

    def _etape_fournisseur(self):
        boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        _intro(boite, _("Votre fournisseur VPN"),
               _("Téléchargez sur le site de votre fournisseur sa configuration "
                 "OpenVPN (un fichier .ovpn, ou une archive .zip), de préférence "
                 "en TCP. Gardez seulement les serveurs voulus : Katakomba adapte "
                 "le reste automatiquement."))
        liste = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        liste.add_css_class("boxed-list")
        self.fichier = Adw.ActionRow(title=_("Fichier de configuration"),
                                     subtitle=_("Aucun fichier choisi"))
        self.fichier.add_prefix(Gtk.Image(icon_name="text-x-generic-symbolic"))
        choisir = Gtk.Button(label=_("Choisir…"), valign=Gtk.Align.CENTER)
        choisir.connect("clicked", lambda _b: choisir_fichiers(
            self.fen, _("Fichiers de votre fournisseur"), _("Configuration OpenVPN"),
            ["*.ovpn", "*.conf", "*.zip"], self._choisi))
        self.fichier.add_suffix(choisir)
        self.fichier.set_activatable_widget(choisir)
        liste.append(self.fichier)
        self.nom = Adw.EntryRow(title=_("Nom du fournisseur"))
        liste.append(self.nom)
        boite.append(liste)
        self.info_fichier = Gtk.Label(xalign=0, wrap=True, visible=False)
        boite.append(self.info_fichier)
        suivant = Gtk.Button(label=_("Suivant"))
        suivant.connect("clicked", lambda _b: self._valider_fournisseur())
        return _page(_("Fournisseur"), boite, suivant)

    def _choisi(self, chemins):
        self.fichier.set_subtitle(_("Lecture…"))
        en_fond(modele.preparer_import, lambda r: self._pret(r, chemins), chemins)

    def _pret(self, r, chemins):
        if isinstance(r, Exception):
            r = (None, [str(r)])
        res, erreurs = r
        self.info_fichier.set_visible(True)
        for c in ("etat-ok", "etat-erreur", "warning"):
            self.info_fichier.remove_css_class(c)
        if erreurs:
            self.resultat, self.chemins = None, ()
            self.fichier.set_subtitle(_("Aucun fichier utilisable"))
            self.info_fichier.set_label(_("Ce fichier ne peut pas être utilisé :") + "\n\n"
                                        + "\n".join(f"• {e}" for e in erreurs[:6]))
            self.info_fichier.add_css_class("etat-erreur")
            return
        self.resultat, self.chemins = res, tuple(chemins)
        self.fichier.set_subtitle(", ".join(GLib.path_get_basename(c) for c in chemins))
        if not self.nom.get_text().strip():
            self.nom.set_text(modele.nom_depuis_fichier(chemins[0]))
        texte = "✓ " + ngettext("Fichier prêt : {n} serveur.", "Fichier prêt : {n} serveurs.",
                                res.serveurs).format(n=res.serveurs)
        if res.modifications:
            n = len(res.modifications)
            texte += "\n" + ngettext(
                "{n} adaptation faite automatiquement pour fonctionner à travers Tor.",
                "{n} adaptations faites automatiquement pour fonctionner à travers Tor.",
                n).format(n=n)
        if res.avertissements:
            texte += "\n\n" + "\n".join(f"⚠ {a}" for a in res.avertissements)
        self.info_fichier.set_label(texte)
        self.info_fichier.add_css_class("warning" if res.avertissements else "etat-ok")

    def _valider_fournisseur(self):
        erreur = modele.verifier_nom(self.nom.get_text(),
                                     self.fen.config.get("providers", []))
        if not erreur and not self.resultat:
            erreur = _("Choisissez d'abord le fichier de votre fournisseur.")
        if erreur:
            self.info_fichier.set_visible(True)
            self.info_fichier.set_label(erreur)
            self.info_fichier.add_css_class("etat-erreur")
            return
        self.vue.push(self._etape_identifiants())

    # ── 2. Identifiants ──────────────────────────────────────────────────────

    def _etape_identifiants(self):
        boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        _intro(boite, _("Vos identifiants"),
               _("Les identifiants OpenVPN fournis par votre fournisseur. Chez "
                 "beaucoup d'entre eux, ils sont différents de l'e-mail et du mot "
                 "de passe de votre compte sur leur site."))
        liste = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        liste.add_css_class("boxed-list")
        self.ident = Adw.EntryRow(title=_("Identifiant"))
        self.secret = Adw.PasswordEntryRow(title=_("Mot de passe"))
        liste.append(self.ident)
        liste.append(self.secret)
        boite.append(liste)
        self.info_ident = Gtk.Label(xalign=0, wrap=True, visible=False)
        self.info_ident.add_css_class("etat-erreur")
        boite.append(self.info_ident)
        suivant = Gtk.Button(label=_("Suivant"))
        suivant.connect("clicked", lambda _b: self._valider_identifiants())
        return _page(_("Identifiants"), boite, suivant)

    def _valider_identifiants(self):
        if not self.ident.get_text().strip() or not self.secret.get_text():
            self.info_ident.set_label(_("Identifiant et mot de passe sont nécessaires."))
            self.info_ident.set_visible(True)
            return
        self.vue.push(self._etape_connexion())

    # ── 3. Connexion ─────────────────────────────────────────────────────────

    def _etape_connexion(self):
        boite = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        _intro(boite, _("Connexion"),
               _("Fournisseur « {fournisseur} », identifiant « {identifiant} ». "
                 "Katakomba enregistre la configuration puis se connecte.").format(
                   fournisseur=self.nom.get_text().strip(),
                   identifiant=self.ident.get_text().strip()))
        liste = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        liste.add_css_class("boxed-list")
        self.auto = Adw.SwitchRow(title=_("Se connecter au démarrage de l'ordinateur"),
                                  subtitle=_("Le mot de passe administrateur est "
                                             "demandé pour ce réglage."),
                                  active=True)
        liste.append(self.auto)
        boite.append(liste)
        etat = Gtk.Box(spacing=12, margin_top=18)
        self.attente = Gtk.Spinner(visible=False, valign=Gtk.Align.START)
        self.etat = Gtk.Label(xalign=0, wrap=True, hexpand=True)
        self.etat.add_css_class("title-4")
        etat.append(self.attente)
        etat.append(self.etat)
        boite.append(etat)
        self.action = Gtk.Button(label=_("Enregistrer et se connecter"))
        self.action.connect("clicked", lambda _b: self._agir())
        return _page(_("Connexion"), boite, self.action)

    def _agir(self):
        if self._termine:
            self.close()
            return
        nom = self.nom.get_text().strip()
        try:
            modele.ajouter_fournisseur_adapte(
                self.fen.config, nom, self.resultat, self.chemins,
                self.ident.get_text().strip(), self.secret.get_text())
        except PermissionError:
            self._montrer("erreur", modele.message_droits())
            return
        except OSError as e:
            self._montrer("erreur", _("Enregistrement impossible : {erreur}").format(erreur=e))
            return
        self.fen.pages["fournisseurs"].recharger()
        # Enregistré : revenir en arrière créerait un doublon du fournisseur.
        self.vue.get_visible_page().set_can_pop(False)
        self.action.set_sensitive(False)
        self._montrer("attente", _("Démarrage du service…"))
        self._fournisseur = nom
        self._compte = len(self.fen.config["providers"][-1]["accounts"]) - 1
        auto = self.auto.get_active()

        def demarrer():
            r_auto = modele.regler_demarrage_auto(auto)
            return r_auto, modele.piloter_service("restart")
        self.fen.veilleur.action_utilisateur(modele.maintenant())
        en_fond(demarrer, self._demarre)

    def _demarre(self, r):
        if isinstance(r, Exception):
            self._montrer("erreur", _("Le service n'a pas pu démarrer : {erreur}").format(
                erreur=r))
            self._terminer()
            return
        r_auto, r_service = r
        if r_auto.returncode == 0:
            self.fen.config["autostart"] = self.auto.get_active()
            self.fen.enregistrer()
            self.fen.pages["reglages"].recharger()
        if r_service.returncode != 0:
            cause = (r_service.stderr or "").strip() or _("autorisation refusée")
            self._montrer("erreur", _("Le service n'a pas pu démarrer ({cause}). "
                                      "Réessayez depuis l'écran Connexion.").format(cause=cause))
            self._terminer()
            return
        self._debut = time.time()
        GLib.timeout_add(1500, self._suivre)

    def _suivre(self):
        en_fond(lambda: (modele.etat_service(), modele.lire_statut()), self._lu)
        return False

    def _lu(self, r):
        if isinstance(r, Exception) or not self.get_root():
            return
        service, st = r
        niveau, message, fini = modele.etat_connexion(service, st, self._fournisseur,
                                                      self._compte)
        self._montrer(niveau, message)
        self.fen.rafraichir_etat(0)
        ecoule = time.time() - self._debut
        if fini:
            self._terminer()
        elif ecoule > DELAI_MAX:
            self._montrer("attente", _("La connexion prend plus de temps que prévu. "
                                       "Elle continue en arrière-plan ; son état reste "
                                       "visible sur l'écran Connexion."))
            self._terminer()
        else:
            GLib.timeout_add(3000 if niveau == "ok" else 2000, self._suivre)

    def _montrer(self, niveau, message):
        prefixe = {"ok": "✓ ", "erreur": "✗ "}.get(niveau, "")
        self.etat.set_label(prefixe + message)
        for c in ("etat-ok", "etat-erreur", "etat-attente"):
            self.etat.remove_css_class(c)
        self.etat.add_css_class(f"etat-{niveau}")
        en_cours = niveau == "attente"
        self.attente.set_visible(en_cours)
        (self.attente.start if en_cours else self.attente.stop)()

    def _terminer(self):
        self._termine = True
        self.attente.stop()
        self.attente.set_visible(False)
        self.action.set_label(_("Terminer"))
        self.action.set_sensitive(True)
