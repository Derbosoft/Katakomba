"""
Veille de la connexion pendant que l'interface tourne en arrière-plan :
décide QUAND prévenir l'utilisateur, sans rien afficher (testé sans écran).

Toutes les notifications partagent un même emplacement (« connexion ») :
chacune remplace la précédente, jamais de pile de messages périmés.  Une
coupure donne « Connexion perdue » puis, sur place, « Connexion rétablie ».
Les reprises rapides restent silencieuses (médiane mesurée : 12 s).
"""

from dataclasses import dataclass

from gui.modele import duree_lisible, raison_lisible
from i18n import _

SEUIL_COUPURE = 20        # s sans tunnel, après avoir été connecté
SEUIL_ETABLISSEMENT = 120  # s sans tunnel depuis le démarrage du service
SILENCE_ACTION = 30       # s : l'utilisateur vient de piloter le service
IDENT = "connexion"


@dataclass
class Avis:
    titre: str = ""
    corps: str = ""
    urgent: bool = False
    bouton: str = ""          # « reconnecter » : bouton « Se connecter »
    retirer: bool = False     # efface la notification affichée
    ident: str = IDENT


class Veilleur:

    def __init__(self):
        self._service = None          # dernier état systemd observé
        self._connecte = False
        self._deja_connecte = False   # tunnel monté depuis le démarrage du service
        self._coupure = None          # début de la coupure en cours
        self._avisee = False          # une notification la signale
        self._raison = ""
        self._silence_jusqua = 0.0

    def action_utilisateur(self, maintenant: float, duree: float = SILENCE_ACTION):
        """Démarrage, arrêt, redémarrage ou réparation demandés depuis
        l'interface : ce qui suit est voulu, rien à signaler."""
        self._silence_jusqua = max(self._silence_jusqua, maintenant + duree)

    def observer(self, service: str, st: dict, maintenant: float,
                 discret: bool = False) -> list:
        """Nouvel état lu (toutes les 3 s).  discret : l'utilisateur regarde
        déjà la fenêtre, aucune NOUVELLE notification (une notification déjà
        affichée est encore mise à jour ou effacée)."""
        if service not in ("active", "inactive", "failed"):
            return []            # transitoire (activating…) ou illisible
        st = st or {}
        if service == "active" and not st:
            return []            # socket du daemon muet : état inconnu
        connecte = service == "active" and bool(st.get("tunnel_up"))
        silence = maintenant < self._silence_jusqua

        if self._service is None:                     # première lecture
            self._service, self._connecte = service, connecte
            self._deja_connecte = connecte
            if service == "active" and not connecte:
                self._debut_coupure(st, maintenant)
            return []

        avis = []
        if service != "active":
            if self._service == "active":
                avis += self._arret(service, silence, discret)
        elif connecte and not self._connecte:
            avis += self._retour(st, maintenant, discret)
        elif not connecte:
            if self._connecte or self._coupure is None:
                self._debut_coupure(st, maintenant)
                if silence:
                    # Redémarrage voulu : la reconnexion qui suit est un
                    # nouvel établissement, pas une perte.
                    self._deja_connecte = False
            avis += self._pendant_coupure(st, maintenant, discret)

        self._service, self._connecte = service, connecte
        return avis

    # ── Transitions ──────────────────────────────────────────────────────────

    def _debut_coupure(self, st, maintenant):
        # Le daemon sait depuis quand le tunnel est tombé ; à défaut, maintenant.
        depuis = st.get("tunnel_down_for")
        self._coupure = maintenant - depuis if isinstance(depuis, (int, float)) else maintenant
        self._avisee, self._raison = False, ""

    def _fin_coupure(self):
        self._coupure, self._avisee, self._raison = None, False, ""

    def _arret(self, service, silence, discret):
        avisee = self._avisee
        self._fin_coupure()
        self._deja_connecte = False
        if silence:
            # Arrêt demandé : une alerte de coupure encore affichée est périmée.
            return [Avis(retirer=True)] if avisee else []
        if discret and not avisee:
            return []
        if service == "failed":
            return [Avis(_("Katakomba s'est arrêté sur une erreur"),
                         _("La connexion VPN est coupée. Le diagnostic et le journal "
                           "en donnent la raison."), urgent=True, bouton="reconnecter")]
        return [Avis(_("Katakomba est arrêté"), _("La connexion VPN est coupée."),
                     urgent=True, bouton="reconnecter")]

    def _retour(self, st, maintenant, discret):
        avisee, coupure, deja = self._avisee, self._coupure, self._deja_connecte
        self._fin_coupure()
        self._deja_connecte = True
        if avisee and deja and coupure is not None:
            return [Avis(_("Connexion rétablie"),
                         _("Après {duree} de coupure.").format(
                             duree=duree_lisible(maintenant - coupure)))]
        if avisee or (not deja and not discret):
            fournisseur = st.get("provider")
            return [Avis(_("Katakomba est connecté"),
                         _("Via {fournisseur}, à travers Tor.").format(fournisseur=fournisseur)
                         if fournisseur else _("À travers Tor."))]
        return []

    def _pendant_coupure(self, st, maintenant, discret):
        depuis = st.get("tunnel_down_for")
        if isinstance(depuis, (int, float)):
            # Le daemon a pu voir la coupure commencer avant nous.
            self._coupure = min(self._coupure, maintenant - depuis)
        duree = maintenant - self._coupure
        raison = st.get("reconnect_reason") or ""
        if self._avisee:
            if raison and raison != self._raison:
                self._raison = raison
                return [self._avis_coupure(duree, raison)]
            return []
        seuil = SEUIL_COUPURE if self._deja_connecte else SEUIL_ETABLISSEMENT
        if duree < seuil or discret or maintenant < self._silence_jusqua:
            return []
        self._avisee, self._raison = True, raison
        return [self._avis_coupure(duree, raison)]

    def _avis_coupure(self, duree, raison):
        d = duree_lisible(duree)
        if self._deja_connecte:
            titre = _("Connexion perdue")
            corps = (_("Reconnexion en cours depuis {duree}. {raison}.") if raison
                     else _("Reconnexion en cours depuis {duree}."))
        else:
            titre = _("Connexion toujours en cours")
            corps = (_("Pas encore de tunnel après {duree}. {raison}.") if raison
                     else _("Pas encore de tunnel après {duree}."))
        return Avis(titre, corps.format(duree=d, raison=raison_lisible(raison)))
