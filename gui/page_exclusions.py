"""
Exclusions (mode avancé) : ce qui ne passe pas par le tunnel — réseaux
locaux, et domaines internes résolus par votre DNS local.
"""

from gi.repository import Adw, Gtk

from gui import modele
from gui.outils import GroupeListe, bouton_icone
from i18n import _


class PageExclusions(Adw.PreferencesPage):

    def __init__(self, fen):
        super().__init__()
        self.fen = fen

        g = Adw.PreferencesGroup(
            title=_("Serveur DNS local"),
            description=_("Résout les domaines locaux ci-dessous. Son réseau doit "
                          "aussi figurer dans les adresses exclues."))
        self.dns = Adw.EntryRow(title=_("Adresse IP du serveur"), show_apply_button=True)
        self.dns.connect("apply", self._dns_applique)
        g.add(self.dns)
        self.add(g)

        g = Adw.PreferencesGroup(
            title=_("Domaines locaux"),
            description=_("Envoyés à votre DNS local au lieu du DNS du VPN "
                          "(par exemple .lan ou .internal)."))
        self.domaines = GroupeListe(g)
        self.nouveau_domaine = Adw.EntryRow(title=_("Ajouter un domaine"),
                                            show_apply_button=True)
        self.nouveau_domaine.connect("apply", self._domaine_ajoute)
        self.nouveau_domaine.connect("entry-activated", self._domaine_ajoute)
        self._groupe_domaines = g
        self.add(g)

        g = Adw.PreferencesGroup(
            title=_("Adresses et réseaux exclus du tunnel"),
            description=_("Joints directement, par la passerelle locale : "
                          "imprimante, NAS, autres machines du réseau (IPv4)."))
        self.reseaux = GroupeListe(g)
        self.nouveau_reseau = Adw.EntryRow(title=_("Ajouter une adresse ou un réseau "
                                                   "(ex. 192.168.1.0/24)"),
                                           show_apply_button=True)
        self.nouveau_reseau.connect("apply", self._reseau_ajoute)
        self.nouveau_reseau.connect("entry-activated", self._reseau_ajoute)
        self._groupe_reseaux = g
        self.add(g)
        self.recharger()

    def recharger(self):
        c = self.fen.config
        self.dns.set_text(c.get("local_dns", ""))
        self.dns.remove_css_class("error")
        self.domaines.remplacer(
            [self._rangee(d, "excluded_domains") for d in c.get("excluded_domains", [])]
            + [self.nouveau_domaine])
        self.reseaux.remplacer(
            [self._rangee(r, "excluded_ips") for r in c.get("excluded_ips", [])]
            + [self.nouveau_reseau])

    def _rangee(self, valeur, cle):
        r = Adw.ActionRow(title=valeur)
        r.add_css_class("monospace")
        r.add_suffix(bouton_icone("user-trash-symbolic", _("Retirer"),
                                  lambda: self._retirer(cle, valeur)))
        return r

    def _retirer(self, cle, valeur):
        self.fen.config[cle] = [v for v in self.fen.config.get(cle, []) if v != valeur]
        self.fen.reglage_modifie()
        self.recharger()

    def _dns_applique(self, _r):
        texte = self.dns.get_text().strip()
        erreur = modele.erreur_dns(texte)
        if erreur:
            self.dns.add_css_class("error")
            self.fen.notifier(_("Serveur DNS local : {erreur}").format(erreur=erreur))
            return
        self.dns.remove_css_class("error")
        self.fen.config["local_dns"] = texte
        self.fen.reglage_modifie()
        self.fen.notifier(_("Serveur DNS local enregistré"))

    def _domaine_ajoute(self, _r):
        d = modele.normaliser_domaine(self.nouveau_domaine.get_text())
        if not d:
            return
        liste = self.fen.config.setdefault("excluded_domains", [])
        if d not in liste:
            liste.append(d)
            self.fen.reglage_modifie()
        self.nouveau_domaine.set_text("")
        self.recharger()

    def _reseau_ajoute(self, _r):
        net, erreur = modele.normaliser_ip(self.nouveau_reseau.get_text())
        if erreur:
            self.nouveau_reseau.add_css_class("error")
            self.fen.notifier(erreur)
            return
        self.nouveau_reseau.remove_css_class("error")
        if not net:
            return
        liste = self.fen.config.setdefault("excluded_ips", [])
        if net not in liste:
            liste.append(net)
            self.fen.reglage_modifie()
        self.nouveau_reseau.set_text("")
        self.recharger()
