"""
Fournisseurs : ordre de priorité, fichier de configuration et comptes.
Chaque modification est enregistrée aussitôt.
"""

from gi.repository import Adw, Gtk

from gui import modele
from i18n import _, ngettext
from gui.outils import (GroupeListe, alerte, choisir_fichiers, confirmer,
                        en_fond, menu_actions, numero)


class PageFournisseurs(Gtk.Stack):

    def __init__(self, fen):
        super().__init__()
        self.fen = fen
        self._ouverts = set()        # fournisseurs dépliés, gardés au rafraîchissement

        vide = Adw.StatusPage(
            icon_name="network-server-symbolic", title=_("Aucun fournisseur"),
            description=_("Ajoutez votre fournisseur VPN : il suffit du fichier "
                          "de configuration téléchargé sur son site."))
        b = Gtk.Button(label=_("Ajouter un fournisseur"), halign=Gtk.Align.CENTER)
        b.add_css_class("pill")
        b.add_css_class("suggested-action")
        b.connect("clicked", lambda _b: fen.ouvrir_assistant())
        vide.set_child(b)
        self.add_named(vide, "vide")

        page = Adw.PreferencesPage()
        self.groupe = Adw.PreferencesGroup(
            title=_("Fournisseurs"),
            description=_("Le premier est utilisé en priorité. En cas d'échec, "
                          "Katakomba passe au compte suivant, puis au fournisseur "
                          "suivant."))
        ajouter = Gtk.Button(valign=Gtk.Align.CENTER)
        ajouter.set_child(Adw.ButtonContent(icon_name="list-add-symbolic",
                                            label=_("Ajouter")))
        ajouter.add_css_class("flat")
        ajouter.connect("clicked", lambda _b: fen.ouvrir_assistant())
        self.groupe.set_header_suffix(ajouter)
        self.liste = GroupeListe(self.groupe)
        page.add(self.groupe)
        self.add_named(page, "liste")
        self.recharger()

    @property
    def fournisseurs(self):
        return self.fen.config.setdefault("providers", [])

    def recharger(self):
        provs = self.fournisseurs
        self.set_visible_child_name("liste" if provs else "vide")
        self.liste.remplacer(self._rangee(i, p) for i, p in enumerate(provs))

    def _modifie(self):
        self.fen.reglage_modifie()
        self.recharger()

    # ── Rangées ──────────────────────────────────────────────────────────────

    def _rangee(self, i, p):
        comptes = p.get("accounts", [])
        fichier = p.get("ovpn_file", "")
        morceaux = [_("Prioritaire") if i == 0 else _("Priorité {n}").format(n=i + 1),
                    ngettext("{n} compte", "{n} comptes", len(comptes)).format(n=len(comptes))]
        if not fichier:
            morceaux.append(_("aucun fichier de configuration"))
        r = Adw.ExpanderRow(title=p["name"], subtitle=" · ".join(morceaux))
        r.set_expanded(p["name"] in self._ouverts)
        r.connect("notify::expanded", self._depliage, p["name"])
        r.add_prefix(numero(i + 1))
        if not fichier or not comptes:
            alerte_icone = Gtk.Image(icon_name="dialog-warning-symbolic",
                                     tooltip_text=_("Fichier ou compte manquant"))
            alerte_icone.add_css_class("warning")
            r.add_suffix(alerte_icone)
        dernier = len(self.fournisseurs) - 1
        r.add_suffix(menu_actions((
            (_("Monter en priorité"), lambda: self._deplacer(i, -1), i > 0, False),
            (_("Descendre en priorité"), lambda: self._deplacer(i, 1), i < dernier, False),
            (_("Supprimer le fournisseur…"), lambda: self._supprimer(i), True, True),
        )))

        f = Adw.ActionRow(title=_("Fichier de configuration"),
                          subtitle=fichier or _("Aucun — choisissez celui du fournisseur"))
        f.add_prefix(Gtk.Image(icon_name="text-x-generic-symbolic"))
        changer = Gtk.Button(label=_("Remplacer…") if fichier else _("Choisir…"),
                             valign=Gtk.Align.CENTER)
        changer.connect("clicked", lambda _b: self._choisir_fichier(i))
        f.add_suffix(changer)
        r.add_row(f)

        for j, compte in enumerate(comptes):
            c = Adw.ActionRow(title=modele.deobf(compte.get("u", "")),
                              subtitle=_("Compte {n} · mot de passe enregistré").format(n=j + 1))
            c.add_prefix(Gtk.Image(icon_name="avatar-default-symbolic"))
            c.add_suffix(menu_actions((
                (_("Essayer plus tôt"), lambda j=j: self._compte_deplacer(i, j, -1), j > 0, False),
                (_("Essayer plus tard"), lambda j=j: self._compte_deplacer(i, j, 1),
                 j < len(comptes) - 1, False),
                (_("Supprimer le compte…"), lambda j=j: self._compte_supprimer(i, j), True, True),
            )))
            r.add_row(c)

        ajout = Adw.ActionRow(title=_("Ajouter un compte"), activatable=True)
        ajout.add_prefix(Gtk.Image(icon_name="list-add-symbolic"))
        ajout.connect("activated", lambda _r: self._compte_ajouter(i))
        r.add_row(ajout)
        return r

    def _depliage(self, rangee, _p, nom):
        (self._ouverts.add if rangee.get_expanded() else self._ouverts.discard)(nom)

    # ── Actions ──────────────────────────────────────────────────────────────

    def _deplacer(self, i, delta):
        modele.deplacer(self.fournisseurs, i, delta)
        self._modifie()

    def _supprimer(self, i):
        nom = self.fournisseurs[i]["name"]
        confirmer(self.fen, _("Supprimer « {nom} » ?").format(nom=nom),
                  _("Le fournisseur et tous ses comptes seront retirés de "
                    "Katakomba. Son fichier de configuration reste sur le disque."),
                  _("Supprimer"), lambda: (self.fournisseurs.pop(i), self._modifie()))

    def _compte_deplacer(self, i, j, delta):
        modele.deplacer(self.fournisseurs[i].setdefault("accounts", []), j, delta)
        self._modifie()

    def _compte_supprimer(self, i, j):
        comptes = self.fournisseurs[i].setdefault("accounts", [])
        nom = modele.deobf(comptes[j].get("u", ""))
        confirmer(self.fen, _("Supprimer ce compte ?"),
                  _("Le compte « {nom} » sera retiré de ce fournisseur.").format(nom=nom),
                  _("Supprimer"), lambda: (comptes.pop(j), self._modifie()))

    def _compte_ajouter(self, i):
        liste = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        liste.add_css_class("boxed-list")
        ident = Adw.EntryRow(title=_("Identifiant"))
        secret = Adw.PasswordEntryRow(title=_("Mot de passe"))
        liste.append(ident)
        liste.append(secret)

        def reponse(r):
            if r != "ajouter" or not ident.get_text().strip():
                return
            self.fournisseurs[i].setdefault("accounts", []).append({
                "u": modele.obf(ident.get_text().strip()),
                "p": modele.obf(secret.get_text())})
            self._ouverts.add(self.fournisseurs[i]["name"])
            self._modifie()
            self.fen.notifier(_("Compte ajouté"))

        alerte(self.fen, _("Ajouter un compte"),
               _("Les identifiants OpenVPN de ce fournisseur, souvent différents "
                 "de ceux de votre compte sur son site."),
               reponses=(("annuler", _("Annuler")), ("ajouter", _("Ajouter"))),
               defaut="ajouter", suggeree="ajouter", rappel=reponse, extra=liste)

    def _choisir_fichier(self, i):
        nom = self.fournisseurs[i]["name"]
        choisir_fichiers(self.fen, _("Fichiers du fournisseur « {nom} »").format(nom=nom),
                         _("Configuration OpenVPN"), ["*.ovpn", "*.conf", "*.zip"],
                         lambda chemins: self._adapter(i, chemins))

    def _adapter(self, i, chemins):
        def pret(resultat):
            if isinstance(resultat, Exception):
                alerte(self.fen, _("Lecture impossible"), str(resultat))
                return
            res, erreurs = resultat
            if erreurs:
                alerte(self.fen, _("Ce fichier ne peut pas être utilisé"),
                       "\n\n".join(erreurs[:12]))
                return
            if res.modifications or res.avertissements:
                alerte(self.fen, _("Adaptation du fichier"),
                       modele.resume_adaptation(res),
                       reponses=(("annuler", _("Annuler")), ("ok", _("Enregistrer"))),
                       defaut="ok", suggeree="ok",
                       rappel=lambda r: r == "ok" and self._ecrire(i, res, chemins))
            else:
                self._ecrire(i, res, chemins)
        en_fond(modele.preparer_import, pret, chemins)

    def _ecrire(self, i, res, chemins):
        p = self.fournisseurs[i]
        try:
            p["ovpn_file"] = modele.ecrire_ovpn(p["name"], res, chemins)
        except OSError as e:
            alerte(self.fen, _("Écriture impossible"), str(e))
            return
        self._ouverts.add(p["name"])
        self._modifie()
        self.fen.notifier(_("Configuration de « {nom} » enregistrée").format(nom=p["name"]))
