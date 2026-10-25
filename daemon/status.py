"""
Statut : socket Unix en lecture seule exposant l'état du daemon en JSON.

Protocole volontairement minimal : à chaque connexion, le daemon écrit un
objet JSON suivi d'un saut de ligne puis ferme.  Aucune commande n'est
acceptée (pas de surface d'attaque en écriture).  Le socket n'expose aucun
secret (ni identifiant ni mot de passe), mais l'état décrit l'usage de la
machine : relais d'entrée Tor, fournisseur, compte.  Connaître les guards de
quelqu'un aide à le désanonymiser.  Il est donc réservé à des groupes (0660) :

- /run/katakomba.sock, groupe katakomba : le GUI et `katakomba doctor`,
  lancés par ses membres — qui peuvent aussi modifier la configuration ;
- /run/katakomba-statut.sock (v3.12.0), groupe katakomba-statut : le même
  JSON, pour une supervision ou un tableau de bord qui doit lire l'état
  sans pouvoir désactiver le blocage hors tunnel.  Créé seulement si le
  groupe existe (install.sh le crée).

Consommation côté client :
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX);
                s.connect('/run/katakomba.sock');
                sys.stdout.write(s.makefile().readline())"
"""

import grp
import json
import os
import socket
import threading
import time

from constants import GROUPE_STATUT, STATUS_SOCKET, STATUS_SOCKET_LECTURE, VERSION
from validation import exclusion_locale, verifier_exclusion


class StatusMixin:

    def _status_snapshot(self) -> dict:
        """État courant du daemon — uniquement des données non sensibles."""
        providers = self.config.get("providers", [])
        prov_name = ""
        if 0 <= self._current_provider_idx < len(providers):
            prov_name = providers[self._current_provider_idx].get("name", "")
        tor_alive = bool(self.tor_process and self.tor_process.poll() is None)
        rx_kbs = (self._rx_history[-1] / 3 / 1024) if self._rx_history else 0.0
        return {
            "version":        VERSION,
            "pid":            os.getpid(),
            "timestamp":      int(time.time()),
            "tor_running":    tor_alive,
            "tor_ready":      self._tor_ready.is_set(),
            # Progression du démarrage de Tor (0-100), pour l'accueil du GUI.
            "tor_bootstrap":  100 if self._tor_ready.is_set() else self._tor_bootstrap,
            "tunnel_up":      self._tunnel_up,
            "tunnel_iface":   self._tun_iface,
            "tunnel_uptime":  int(time.time() - self._tunnel_up_time)
                              if self._tunnel_up and self._tunnel_up_time else 0,
            # Tunnel absent : depuis combien de secondes, et pour quelle
            # raison connue (re-tirage de circuit, relance, démarrage…).
            # `katakomba doctor` y reconnaît une reconnexion en cours plutôt
            # que d'afficher une panne et de conseiller un redémarrage.
            "tunnel_down_for":  0 if self._tunnel_up
                                else int(time.time() - self._tunnel_down_at),
            "reconnect_reason": "" if self._tunnel_up else self._reconnect_reason,
            "provider":       prov_name,
            # Transport de l'étape en cours (v4.0.0) : « wireguard » ou
            # « openvpn » ; vide si le fournisseur n'en sert aucun.
            "transport":      self._transport,
            # WireGuard géré (v4.2.0) : fournisseur, numéro du compte qui
            # porte la session de ce PC, date de la clé ; vide sinon.
            "wg_managed":     self._wg_gere_statut(),
            "account_index":  self._current_account_idx,
            # Comptes de l'étape courante (fournisseur et transport) écartés
            # temporairement après un refus d'authentification ou une
            # connexion sans poignée de main, sous la forme « numéro affiché
            # → secondes restantes ».  Sans cette exposition, un compte
            # relégué serait invisible et son absence inexplicable.
            "accounts_cooldown": {
                str(cle[1] + 1): int(fin - time.time())
                for cle, fin in sorted(self._account_cooldown.items(), key=str)
                if cle == self._cle_compte(cle[1]) and fin > time.time()
            },
            "rx_kbs":         round(rx_kbs, 1),
            # Qualité du circuit mesurée à la connexion.  0 = pas de mesure
            # valide pour le tunnel courant (contrôle désactivé, mesure
            # impossible, ou tunnel tout juste monté).  L'âge permet de savoir
            # à quel point le chiffre est ancien : la mesure est unique, un
            # circuit peut s'être dégradé depuis.
            "last_circuit_kbs": round(self._last_circuit_kbs, 1),
            "last_circuit_age": int(time.time() - self._last_circuit_at)
                                if self._last_circuit_at else 0,
            "conn_failures":  self._conn_fail_count,
            "vpn_reconnects": self._reconnect_vpn_count,
            "full_restarts":  self._full_restart_count,
            "light_restarts": self._light_restart_count,
            # Relais Tor routés hors tunnel.  Rien de neuf pour un lecteur
            # local : « ip route » les montre déjà à tout utilisateur.  Sert à
            # `katakomba doctor`, qui sinon comptait comme guards toutes les
            # routes /32 — exclusions de l'utilisateur comprises.
            "tor_guard_routes": sorted(self._protected_routes),
            "lan_sharing":    self._lan_active,
            "ipv6_blocked":   self._ipv6_blocked,
            "kill_switch":    self._kill_active,
            # Réponses aux connexions entrantes (SSH…) hors tunnel, par la
            # carte d'origine : sans elles, une session distante tombe.
            "incoming_return": self._retour_actif,
            "kill_switch_config": bool(self.config.get("kill_switch", True)),
            "public_exclusions": self._exclusions_publiques(),
        }

    def _restreindre_socket(self, chemin, groupe: str) -> bool:
        """0660, au groupe donné ; 0600 (root seul) si c'est impossible.  Le
        propriétaire reste celui qui a créé le socket : root, pour le daemon."""
        try:
            os.chown(chemin, -1, grp.getgrnam(groupe).gr_gid)
        except (KeyError, OSError) as e:
            os.chmod(chemin, 0o600)
            self._log(f"Socket de statut {chemin} réservé à root (groupe {groupe} "
                      f"inutilisable : {e}).", "WARN")
            return False
        os.chmod(chemin, 0o660)
        return True

    def _exclusions_publiques(self) -> list:
        """Exclusions admises qui mènent à Internet : ce trafic sort avec
        l'adresse réelle.  Signalées par `katakomba doctor`."""
        nets = (verifier_exclusion(e)[0] for e in self.config.get("excluded_ips", []))
        return [n for n in nets if n and not exclusion_locale(n)]

    def _sockets_de_statut(self) -> list:
        """(chemin, groupe) de chaque socket à ouvrir.  Celui en lecture seule
        suppose le groupe katakomba-statut, créé par l'installation : sans
        lui, il ne servirait qu'à root."""
        sockets = [(STATUS_SOCKET, "katakomba")]
        try:
            grp.getgrnam(GROUPE_STATUT)
            sockets.append((STATUS_SOCKET_LECTURE, GROUPE_STATUT))
        except KeyError:
            self._log(f"Groupe {GROUPE_STATUT} absent : pas de statut en lecture "
                      "seule (sudo bash install.sh, ou réinstallez le paquet).", "INFO")
        return sockets

    def _start_status_server(self):
        """Ouvre chaque socket de statut, servi par son propre thread."""
        self._status_srvs = []
        for chemin, groupe in self._sockets_de_statut():
            srv = None
            try:
                chemin.unlink(missing_ok=True)
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind(str(chemin))
                self._restreindre_socket(chemin, groupe)
                srv.listen(4)
            except Exception as e:
                if srv is not None:
                    srv.close()              # sinon le descripteur reste ouvert
                self._log(f"Socket de statut indisponible ({chemin} : {e}) — "
                          "état exposé via journalctl uniquement.", "WARN")
                continue
            self._status_srvs.append((srv, chemin))
            threading.Thread(target=self._servir_statut, args=(srv,), daemon=True).start()
            self._log(f"Socket de statut : {chemin} (groupe {groupe})", "OK")

    def _servir_statut(self, srv):
        while not self._stop_flag:
            try:
                conn, _ = srv.accept()
            except OSError:
                break                          # socket fermé à l'arrêt
            try:
                conn.settimeout(2)
                payload = json.dumps(self._status_snapshot(),
                                     ensure_ascii=False) + "\n"
                conn.sendall(payload.encode())
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def _stop_status_server(self):
        for srv, chemin in getattr(self, "_status_srvs", []):
            try:
                srv.close()
            except Exception:
                pass
            chemin.unlink(missing_ok=True)
        self._status_srvs = []
