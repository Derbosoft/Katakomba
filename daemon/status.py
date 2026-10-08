"""
Statut : socket Unix en lecture seule exposant l'état du daemon en JSON.

Protocole volontairement minimal : à chaque connexion, le daemon écrit un
objet JSON suivi d'un saut de ligne puis ferme.  Aucune commande n'est
acceptée (pas de surface d'attaque en écriture).  Le socket est en 0666 :
il n'expose aucun secret (ni identifiant ni mot de passe), uniquement de
l'état opérationnel, et doit être lisible par le GUI non-root et le CLI.

Consommation côté client :
    python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX);
                s.connect('/run/katakomba.sock');
                sys.stdout.write(s.makefile().readline())"
"""

import json
import os
import socket
import threading
import time

from constants import STATUS_SOCKET, VERSION


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
            "account_index":  self._current_account_idx,
            # Comptes du fournisseur courant écartés temporairement après un
            # refus d'authentification, sous la forme « numéro affiché →
            # secondes restantes ».  Sans cette exposition, un compte relégué
            # serait invisible et son absence inexplicable.
            "accounts_cooldown": {
                str(a + 1): int(fin - time.time())
                for (p, a), fin in sorted(self._account_cooldown.items())
                if p == self._current_provider_idx and fin > time.time()
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
        }

    def _start_status_server(self):
        """Démarre le serveur de statut sur le socket Unix (thread daemon)."""
        srv = None
        try:
            STATUS_SOCKET.unlink(missing_ok=True)
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(STATUS_SOCKET))
            os.chmod(STATUS_SOCKET, 0o666)   # lecture seule, aucune donnée sensible
            srv.listen(4)
        except Exception as e:
            if srv is not None:
                srv.close()                  # sinon le descripteur reste ouvert
            self._log(f"Socket de statut indisponible ({e}) — "
                      "état exposé via journalctl uniquement.", "WARN")
            return

        self._status_srv = srv

        def _serve():
            while not self._stop_flag:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    break                      # socket fermé à l'arrêt
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

        threading.Thread(target=_serve, daemon=True).start()
        self._log(f"Socket de statut : {STATUS_SOCKET}", "OK")

    def _stop_status_server(self):
        srv = getattr(self, "_status_srv", None)
        if srv:
            try:
                srv.close()
            except Exception:
                pass
        STATUS_SOCKET.unlink(missing_ok=True)
