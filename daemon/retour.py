"""
Mode secours : le signaler, et en revenir (v4.5.0).

Le daemon parcourt ses étapes (session.py) et reste sur celle qui marche.
Sans plus, un accroc passager (API injoignable à un démarrage, serveurs muets)
laisserait un PC sur le secours jusqu'au prochain redémarrage ; sur un parc,
les quelques comptes gardés en réserve finiraient occupés pour de bon.

Tant qu'il tourne sur une étape de rang inférieur, le daemon sonde donc
l'étape la mieux placée qui soit en WireGuard, toutes les
config["primary_retry_min"] minutes (30 par défaut, 0 : jamais), à un moment
tiré au hasard pour qu'un parc n'y aille pas d'un seul coup.

La sonde se fait À CÔTÉ du tunnel en service, jamais à sa place : une seconde
interface WireGuard, sans adresse ni route, et un second pont.  Couper le
tunnel pour essayer coûterait ses connexions ouvertes, toutes les 30 minutes,
pour rien si l'étape 1 est toujours en panne.  Le tunnel n'est remplacé
qu'après une poignée de main réussie, sur le serveur qui vient de répondre :
une seule coupure, au moment où elle sert.

OpenVPN n'est pas sondé : essayer une connexion prendrait une place au compte,
et sa réussite demande bien plus qu'une poignée de main.
"""

import random
import threading
import time

from .gestion_wg import CAUSE_INCONNUE, CAUSE_SERVEURS, service_gere

RETOUR_DEFAUT = 30              # minutes entre deux sondes
RETOUR_MIN = 5                  # plancher : config.json est modifiable par le groupe
RETOUR_ALEA = 1 / 3             # étalement, en part de l'intervalle


class RetourMixin:

    # ── Mode secours ─────────────────────────────────────────────────────────

    def _etape_montee(self):
        """Un tunnel vient de monter : note l'entrée en secours, ou sa fin."""
        if self._rang_etape() <= 1:
            if self._secours_depuis:
                self._log("Secours terminé : retour sur la première étape.", "OK")
            self._secours_depuis = 0.0
            self._cause_etape = ""
            self._retour_prochain = 0.0
            return
        if not self._secours_depuis:
            self._secours_depuis = time.time()
            self._log(f"Mode secours : étape {self._rang_etape()}/{len(self._etapes())} "
                      f"({self._cause_etape or CAUSE_INCONNUE}).", "WARN")

    def _statut_secours(self) -> dict:
        """Pour le statut : {} hors secours."""
        if not self._secours_depuis:
            return {}
        return {"since": int(self._secours_depuis),
                "reason": self._cause_etape or CAUSE_INCONNUE,
                "next_try": int(self._retour_prochain)}

    # ── Sonde ────────────────────────────────────────────────────────────────

    def _retour_minutes(self) -> int:
        """Minutes entre deux sondes, 0 si le retour est désactivé."""
        n = self.config.get("primary_retry_min", RETOUR_DEFAUT)
        if isinstance(n, bool) or not isinstance(n, int):
            return RETOUR_DEFAUT
        return max(n, RETOUR_MIN) if n > 0 else 0

    def _cible_retour(self):
        """(fournisseur, transport) de l'étape à sonder, ou None."""
        etapes = self._etapes()
        for etape in etapes[:max(0, self._rang_etape() - 1)]:
            if etape[1] == "wireguard":
                return etape
        return None

    def _planifier_retour(self):
        attente = self._retour_minutes() * 60
        self._retour_prochain = time.time() + attente * (1 + random.uniform(0, RETOUR_ALEA))

    def _retour_du(self) -> bool:
        """Une sonde est-elle due ?  Appelé par la surveillance, toutes les 3 s."""
        if (self._retour_en_cours or self._retour_vers or not self._tunnel_up
                or self._stop_vpn or self._stop_flag or self._mesure_en_cours
                or not self.config.get("auto_reconnect", True)
                or not self._retour_minutes() or self._cible_retour() is None):
            return False
        if not self._retour_prochain:
            self._planifier_retour()         # la première vient après un intervalle
            return False
        return time.time() >= self._retour_prochain

    def _lancer_sonde(self):
        """Dans son propre thread : la surveillance ne doit jamais attendre."""
        self._retour_en_cours = True
        threading.Thread(target=self._sonder_retour, daemon=True).start()

    def _reglages_sonde(self, idx: int):
        """(réglages, compte ou None, hôte ou None) d'un serveur de l'étape, ou
        None : pas de place, de clé ou de liste pour l'instant."""
        p = self.config["providers"][idx]
        if service_gere(p):
            with self._wg_verrou:
                pret = self._wg_gere_sonde(p)
            return (pret[0], None, pret[1]) if pret else None
        confs = list(range(len(p.get("wireguard", []))))
        random.shuffle(confs)
        for i in confs:
            chemin = self._chemin_conf(p, i)
            reglages = self._preparer_wg(chemin) if chemin else None
            if reglages:
                return reglages, i, None
        return None

    def _sonder_retour(self):
        try:
            cible = self._cible_retour()
            ids = self._utilisateur_vpn()
            if cible is None or ids is None:
                return
            idx, transport = cible
            nom = self.config["providers"][idx].get("name", "?")
            self._wg_cause = ""
            pret = self._reglages_sonde(idx)
            if pret is None:
                self._log(f"Retour vers {nom} : pas encore possible "
                          f"({self._wg_cause or CAUSE_INCONNUE}).", "INFO")
                self._cause_etape = self._wg_cause or self._cause_etape
                return
            if not self._sonder_poignee(pret[0], *ids):
                if not (self._stop_vpn or self._stop_flag):
                    self._log(f"Retour vers {nom} : pas de poignée de main, le "
                              "tunnel en service reste en place.", "INFO")
                    self._cause_etape = CAUSE_SERVEURS
                return
            if self._stop_vpn or self._stop_flag or not self._tunnel_up:
                return
            self._log(f"Retour vers {nom} : poignée de main réussie, le tunnel "
                      "de secours est remplacé.", "OK")
            self._retour_vers = (idx, transport, pret[1], pret[2])
            self._reconnect_reason = "retour sur la première étape"
            proc = self._processus_vpn()
            if proc and proc.poll() is None:
                proc.terminate()     # sans _stop_vpn : la boucle reprend d'elle-même
        except Exception as e:       # un thread de confort ne doit rien emporter
            self._log(f"Sonde de retour interrompue : {type(e).__name__}.", "WARN")
        finally:
            self._planifier_retour()
            self._retour_en_cours = False

    def _revenir(self):
        """Par la boucle VPN : se place sur l'étape sondée, sur son serveur.
        S'il ne répond plus, l'étape échoue vite et le secours reprend : son
        tirage ne contient que lui."""
        idx, transport, compte, hote = self._retour_vers
        self._retour_vers = None
        self._reconnect_vpn_count = 0
        self._circuit_retry = False
        self._entrer_fournisseur(idx, transport)
        if hote is not None:
            self._wg_hotes = [hote]
            self._account_order = sorted(self._account_order)
            compte = 0
        if compte in self._account_order:
            self._account_pos = self._account_order.index(compte)
            self._current_account_idx = compte
