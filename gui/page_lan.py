"""
Partage LAN (mode avancé) : une seconde carte réseau distribue la connexion
Tor + VPN aux appareils qui y sont branchés.
"""

from gi.repository import Adw, Gtk

from gui import modele
from gui.outils import bouton_icone, en_fond
from i18n import _


class PageLan(Adw.PreferencesPage):

    def __init__(self, fen):
        super().__init__()
        self.fen = fen
        self._charge = False
        self._interfaces = []

        g = Adw.PreferencesGroup(
            title=_("Partage de la connexion"),
            description=_("Les appareils branchés sur la seconde carte reçoivent une "
                          "adresse et passent par le tunnel Tor + VPN. Si le tunnel "
                          "tombe, leur trafic est bloqué. Pris en compte au prochain "
                          "démarrage du service."))
        self.actif = Adw.SwitchRow(title=_("Activer le partage LAN"))
        self.actif.connect("notify::active", self._actif_change)
        g.add(self.actif)

        self.modele_ifaces = Gtk.StringList()
        self.iface = Adw.ComboRow(title=_("Carte réseau"), model=self.modele_ifaces,
                                  subtitle=_("La carte qui porte l'accès Internet "
                                             "n'est jamais proposée."))
        self.iface.connect("notify::selected", self._iface_change)
        self.iface.add_suffix(bouton_icone("view-refresh-symbolic",
                                           _("Actualiser la liste"), self._lister))
        g.add(self.iface)

        self.passerelle = Adw.EntryRow(title=_("Adresse de la carte (passerelle des appareils)"),
                                       show_apply_button=True)
        self.passerelle.connect("apply", self._adresses_appliquees)
        g.add(self.passerelle)
        self.sous_reseau = Adw.EntryRow(title=_("Sous-réseau (ex. 10.0.0.0/24)"),
                                        show_apply_button=True)
        self.sous_reseau.connect("apply", self._adresses_appliquees)
        g.add(self.sous_reseau)
        self.dhcp = Adw.SwitchRow(title=_("Distribuer les adresses automatiquement"),
                                  subtitle=_("Serveur DHCP (paquet dnsmasq requis)."))
        self.dhcp.connect("notify::active", self._dhcp_change)
        g.add(self.dhcp)
        self.add(g)
        self.recharger()

    def recharger(self):
        c = self.fen.config
        self._charge = True
        try:
            self.actif.set_active(c.get("lan_auto", False))
            self.passerelle.set_text(c.get("lan_gateway", "10.0.0.1"))
            self.sous_reseau.set_text(c.get("lan_subnet", "10.0.0.0/24"))
            self.dhcp.set_active(c.get("lan_dhcp", True))
        finally:
            self._charge = False
        self._lister()

    def _lister(self):
        en_fond(modele.interfaces_lan, self._listees)

    def _listees(self, ifaces):
        if isinstance(ifaces, Exception):
            ifaces = []
        voulue = self.fen.config.get("lan_iface", "")
        if voulue and voulue not in ifaces:
            ifaces = [voulue, *ifaces]
        self._charge = True
        try:
            self._interfaces = ifaces
            self.modele_ifaces.splice(0, self.modele_ifaces.get_n_items(),
                                      ifaces or [_("(aucune carte disponible)")])
            self.iface.set_sensitive(bool(ifaces))
            if voulue in ifaces:
                self.iface.set_selected(ifaces.index(voulue))
        finally:
            self._charge = False

    def _actif_change(self, *_args):
        if self._charge:
            return
        actif = self.actif.get_active()
        if actif:
            erreurs = modele.erreurs_lan(self.passerelle.get_text(),
                                         self.sous_reseau.get_text())
            if erreurs:
                self._charge = True
                self.actif.set_active(False)
                self._charge = False
                self.fen.notifier(erreurs[0])
                return
            if not self.fen.config.get("lan_iface") and self._interfaces:
                self.fen.config["lan_iface"] = self._interfaces[self.iface.get_selected()]
        self.fen.config["lan_auto"] = actif
        self.fen.reglage_modifie()

    def _iface_change(self, *_args):
        if self._charge or not self._interfaces:
            return
        self.fen.config["lan_iface"] = self._interfaces[self.iface.get_selected()]
        self.fen.reglage_modifie()

    def _dhcp_change(self, *_args):
        if not self._charge:
            self.fen.config["lan_dhcp"] = self.dhcp.get_active()
            self.fen.reglage_modifie()

    def _adresses_appliquees(self, _r):
        erreurs = modele.erreurs_lan(self.passerelle.get_text(),
                                     self.sous_reseau.get_text())
        for champ in (self.passerelle, self.sous_reseau):
            (champ.add_css_class if erreurs else champ.remove_css_class)("error")
        if erreurs:
            self.fen.notifier(erreurs[0])
            return
        self.fen.config["lan_gateway"] = self.passerelle.get_text().strip()
        self.fen.config["lan_subnet"] = self.sous_reseau.get_text().strip()
        self.fen.reglage_modifie()
        self.fen.notifier(_("Adresses du partage LAN enregistrées"))
