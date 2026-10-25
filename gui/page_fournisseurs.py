"""
Fournisseurs : ordre de priorité, et pour chacun ses deux transports :
OpenVPN (fichier de configuration et comptes) et WireGuard (fichiers .conf,
chacun avec sa clé, son adresse et son serveur, ou WireGuard géré par
Katakomba chez IVPN), avec, s'il le faut, un ordre des transports propre au
fournisseur.  Chaque modification est
enregistrée aussitôt.
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
            description=_("Ajoutez votre fournisseur VPN : il suffit des fichiers "
                          "de configuration téléchargés sur son site (WireGuard "
                          ".conf ou OpenVPN .ovpn)."))
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
                          "Katakomba passe au compte suivant, puis à l'autre "
                          "transport (WireGuard ou OpenVPN), puis au fournisseur "
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
        confs = p.get("wireguard", [])
        morceaux = [_("Prioritaire") if i == 0 else _("Priorité {n}").format(n=i + 1),
                    modele.resume_comptes(p)]
        if comptes and not fichier:
            morceaux.append(_("aucun fichier OpenVPN"))
        r = Adw.ExpanderRow(title=p["name"], subtitle=" · ".join(morceaux))
        r.set_expanded(p["name"] in self._ouverts)
        r.connect("notify::expanded", self._depliage, p["name"])
        r.add_prefix(numero(i + 1))
        if not confs and not (fichier and comptes):
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

        if modele.deux_transports(p) or "transports" in p:
            r.add_row(self._rangee_transports(i, p))

        gere = modele.wg_gere(p)
        if comptes and modele.est_ivpn(p):
            for rangee in self._rangees_wg_gere(i, p):
                r.add_row(rangee)
        # WireGuard géré : le daemon ignore les .conf, inutile de les proposer.
        for j, entree in enumerate([] if gere else confs):
            titre, detail = modele.decrire_conf(entree)
            c = Adw.ActionRow(title=titre, subtitle=_("WireGuard {n} · {detail}").format(
                n=j + 1, detail=detail))
            c.add_prefix(Gtk.Image(icon_name="network-vpn-symbolic"))
            c.add_suffix(menu_actions((
                (_("Essayer plus tôt"), lambda j=j: self._conf_deplacer(i, j, -1), j > 0, False),
                (_("Essayer plus tard"), lambda j=j: self._conf_deplacer(i, j, 1),
                 j < len(confs) - 1, False),
                (_("Retirer ce fichier…"), lambda j=j: self._conf_supprimer(i, j), True, True),
            )))
            r.add_row(c)
        if not gere:
            ajout_wg = Adw.ActionRow(title=_("Ajouter des fichiers WireGuard (.conf)…"),
                                     activatable=True)
            ajout_wg.add_prefix(Gtk.Image(icon_name="list-add-symbolic"))
            ajout_wg.connect("activated", lambda _r: self._choisir_confs(i))
            r.add_row(ajout_wg)

        f = Adw.ActionRow(title=_("Fichier de configuration OpenVPN"),
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

        ajout = Adw.ActionRow(title=_("Ajouter un compte OpenVPN"), activatable=True)
        ajout.add_prefix(Gtk.Image(icon_name="list-add-symbolic"))
        ajout.connect("activated", lambda _r: self._compte_ajouter(i))
        r.add_row(ajout)
        return r

    def _rangee_transports(self, i, p):
        """Ordre propre à ce fournisseur ; le premier choix le laisse suivre
        le réglage général (page Réglages)."""
        choix = Adw.ComboRow(
            title=_("Transport"),
            subtitle=_("Pour ce fournisseur seulement."),
            model=Gtk.StringList.new([_("Comme le réglage général")]
                                     + modele.noms_ordres()))
        choix.add_prefix(Gtk.Image(icon_name="network-transmit-receive-symbolic"))
        ordre = tuple(p.get("transports", ()))
        choix.set_selected(modele.ORDRES_TRANSPORTS.index(ordre) + 1
                           if ordre in modele.ORDRES_TRANSPORTS else 0)
        choix.connect("notify::selected", self._transports_change, i)
        return choix

    def _rangees_wg_gere(self, i, p):
        """IVPN : clé WireGuard enregistrée par Katakomba sur l'un des
        comptes, par Tor, sans fichier .conf (daemon/gestion_wg.py)."""
        gere = modele.wg_gere(p)
        interrupteur = Adw.SwitchRow(
            title=_("WireGuard géré par Katakomba"),
            subtitle=_("Katakomba enregistre lui-même une clé WireGuard sur l'un "
                       "de ces comptes, par Tor : aucun fichier à créer. Une place "
                       "d'appareil par PC, rendue à la désinstallation."))
        interrupteur.add_prefix(Gtk.Image(icon_name="network-vpn-symbolic"))
        interrupteur.set_active(gere)
        interrupteur.connect("notify::active", lambda s, _p: self._wg_gere(
            i, actif=s.get_active()))
        rangees = [interrupteur]
        if not gere:
            return rangees
        g = p["wg_auto"]
        pays = Adw.EntryRow(title=_("Pays des serveurs (ex. NL, CH ; vide : tous)"),
                            show_apply_button=True)
        pays.set_text(", ".join(g.get("countries", [])))
        pays.connect("apply", lambda e: self._wg_gere_pays(i, e.get_text()))
        reserves = Adw.SwitchRow(
            title=_("Comptes réservés à Katakomba"),
            subtitle=_("Si tous les comptes sont pleins, Katakomba peut en remettre "
                       "un à zéro : ses autres appareils (téléphone, autre "
                       "ordinateur) sont déconnectés. À activer seulement si ces "
                       "comptes ne servent qu'à des PC Katakomba."))
        reserves.set_active(bool(g.get("reserved_accounts")))
        reserves.connect("notify::active", lambda s, _p: self._wg_gere(
            i, reserves=s.get_active()))
        return rangees + [pays, reserves]

    def _wg_gere(self, i, **reglage):
        p = self.fournisseurs[i]
        modele.regler_wg_gere(p, **reglage)
        self._ouverts.add(p["name"])
        self._modifie()

    def _wg_gere_pays(self, i, texte):
        pays, erreur = modele.lire_pays(texte)
        if erreur:
            alerte(self.fen, _("Pays des serveurs"), erreur)
            return
        self._wg_gere(i, pays=pays)

    def _transports_change(self, choix, _p, i):
        n = choix.get_selected()
        modele.regler_transports(self.fournisseurs[i],
                                 modele.ORDRES_TRANSPORTS[n - 1] if n else None)
        self._modifie()

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
                    "Katakomba. Ses fichiers de configuration restent sur le disque."),
                  _("Supprimer"), lambda: (self.fournisseurs.pop(i), self._modifie()))

    def _compte_deplacer(self, i, j, delta):
        modele.deplacer(self.fournisseurs[i].setdefault("accounts", []), j, delta)
        self._modifie()

    def _conf_deplacer(self, i, j, delta):
        modele.deplacer(self.fournisseurs[i].setdefault("wireguard", []), j, delta)
        self._modifie()

    def _conf_supprimer(self, i, j):
        confs = self.fournisseurs[i].setdefault("wireguard", [])
        nom = modele.decrire_conf(confs[j])[0]
        confirmer(self.fen, _("Retirer ce fichier ?"),
                  _("« {nom} » sera retiré de ce fournisseur ; il reste sur le "
                    "disque.").format(nom=nom),
                  _("Retirer"), lambda: (confs.pop(j), self._modifie()))

    def _choisir_confs(self, i):
        nom = self.fournisseurs[i]["name"]
        choisir_fichiers(self.fen, _("Fichiers WireGuard de « {nom} »").format(nom=nom),
                         _("Configuration WireGuard"), ["*.conf"],
                         lambda chemins: self._importer_confs(i, chemins))

    def _importer_confs(self, i, chemins):
        def pret(resultat):
            if isinstance(resultat, Exception):
                alerte(self.fen, _("Lecture impossible"), str(resultat))
                return
            prets, erreurs = resultat
            if erreurs:
                alerte(self.fen, _("Ce fichier ne peut pas être utilisé"),
                       "\n\n".join(erreurs[:12]))
                return
            if any(avert for _c, _r, avert in prets):
                alerte(self.fen, _("Fichiers lus"), modele.resume_import(prets),
                       reponses=(("annuler", _("Annuler")), ("ok", _("Enregistrer"))),
                       defaut="ok", suggeree="ok",
                       rappel=lambda r: r == "ok" and self._ajouter_confs(i, prets))
            else:
                self._ajouter_confs(i, prets)
        en_fond(modele.preparer_import_wg, pret, chemins)

    def _ajouter_confs(self, i, prets):
        p = self.fournisseurs[i]
        try:
            n = modele.ajouter_confs_wg(self.fen.config, p["name"],
                                        [c for c, _r, _a in prets])
        except PermissionError:
            alerte(self.fen, _("Écriture impossible"), modele.message_droits())
            return
        except OSError as e:
            alerte(self.fen, _("Écriture impossible"), str(e))
            return
        self._ouverts.add(p["name"])
        self._modifie()
        self.fen.notifier(ngettext("{n} fichier WireGuard ajouté",
                                   "{n} fichiers WireGuard ajoutés", n).format(n=n))

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
