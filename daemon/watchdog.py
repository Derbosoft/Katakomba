"""
Watchdog : surveillance de connectivité, redémarrage automatique.
"""

import errno
import select
import socket
import subprocess
import sys
import time

from .core import _run, _sd_notify, CONN_FAIL_MAX, REPAIR_THRESHOLD, SCRIPT_DIR


class WatchdogMixin:

    def _vpn_is_active(self) -> bool:
        # Uniquement le processus lancé par ce daemon.  L'ancien repli sur
        # « pgrep -x openvpn » comptait n'importe quel OpenVPN de la machine.
        return bool(self.openvpn_process
                    and self.openvpn_process.poll() is None)

    _CONN_GRACE = 30  # secondes de grâce après tunnel up avant de vérifier la connectivité

    # Deux endpoints indépendants (Cloudflare, Quad9) : une panne ponctuelle
    # de l'un ne doit pas déclencher un redémarrage complet pour rien.
    _CONN_ENDPOINTS = (("1.1.1.1", 443), ("9.9.9.9", 443))

    _CONN_TIMEOUT = 5   # secondes, pour les deux endpoints ENSEMBLE

    def _check_connectivity(self) -> bool:
        """Joignabilité d'Internet PAR LE TUNNEL : vrai dès qu'un endpoint
        accepte la connexion.

        Les deux endpoints sont testés EN PARALLÈLE.  Testés l'un après
        l'autre, un tunnel mort coûtait 2 × 5 s par vérification — 10 s de
        coupure supplémentaires avant même de décider quoi que ce soit."""
        tun = self._tun_iface
        if _run("ip", "link", "show", tun).returncode != 0:
            return False
        if time.time() - self._tunnel_up_time < self._CONN_GRACE:
            return True
        ouverts, en_cours = [], []
        try:
            for host, port in self._CONN_ENDPOINTS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ouverts.append(s)
                    s.setsockopt(socket.SOL_SOCKET,
                                 getattr(socket, "SO_BINDTODEVICE", 25),
                                 tun.encode() + b"\0")
                    s.setblocking(False)
                    err = s.connect_ex((host, port))
                except OSError:
                    continue
                if err == 0:
                    return True
                if err in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                    en_cours.append(s)
            fin = time.time() + self._CONN_TIMEOUT
            while en_cours:
                reste = fin - time.time()
                if reste <= 0:
                    return False
                _, prets, _ = select.select([], en_cours, [], reste)
                if not prets:
                    return False
                for s in prets:
                    if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        return True
                    en_cours.remove(s)
            return False
        finally:
            for s in ouverts:
                try:
                    s.close()
                except OSError:
                    pass

    def _read_tun0_rx(self) -> int:
        tun = self._tun_iface
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    name, _, rest = line.partition(":")
                    if name.strip() == tun:
                        return int(rest.split()[0])
        except Exception:
            pass
        return 0

    def _emergency_repair(self):
        """Lance repair_network.sh --internal puis quitte : systemd relance le service."""
        self._log(
            f"Watchdog : {REPAIR_THRESHOLD} redémarrages échoués — "
            "lancement de repair_network.sh …", "ERROR")
        script = SCRIPT_DIR / "repair_network.sh"
        try:
            subprocess.run(["bash", str(script), "--internal"],
                           timeout=60, check=False)
        except Exception as e:
            self._log(f"repair_network.sh : {e}", "ERROR")
        self._log("Réparation terminée — sortie pour relance systemd.", "WARN")
        sys.exit(1)

    def _full_restart(self):
        self._full_restart_count += 1
        self._reconnect_reason = "redémarrage complet de Tor et d'OpenVPN"
        self._log(
            f"Watchdog : redémarrage complet "
            f"({self._full_restart_count}/{REPAIR_THRESHOLD}) …", "ERROR")
        if self._full_restart_count >= REPAIR_THRESHOLD:
            self._emergency_repair()
        self._stop_vpn      = True
        self._stop_tor_flag = True
        self._stop_openvpn()
        self._stop_tor()
        self._wait_vpn_loop_exit()
        self._cleanup_tor_routes()
        self._ipv6_block_off()
        # Attendre que le port SOCKS soit réellement libéré, pas un délai fixe
        # (6 s auparavant) : _stop_tor attend déjà la fin du processus, si
        # bien que le port est en général libre sur-le-champ.
        for _ in range(20):
            if not self._check_socks_port():
                break
            time.sleep(0.25)
        self._stop_vpn             = False
        self._stop_tor_flag        = False
        self._conn_fail_count      = 0
        self._conn_restart_pending = False
        self._reconnect_vpn_count  = 0
        self._reconnect_tor_count  = 0
        self._tunnel_up            = False
        self._tunnel_up_time       = 0.0
        self._tunnel_down_at       = time.time()
        self._tun_iface            = "tun0"
        self._light_restart_done   = False
        self._light_restart_at     = 0.0
        self._tor_ready.clear()
        self._log("Relance des services …", "WARN")
        if not self._start_services():
            self._log("Watchdog : relance échouée (Tor ne démarre pas).", "ERROR")

    # ── Reprise graduée ──────────────────────────────────────────────────────
    # Mesuré sur ~5 semaines de production : les redémarrages complets
    # faisaient 83 % du temps de coupure (médiane 28 s), alors que Tor allait
    # bien — il était de nouveau prêt 2 s après sa relance.  Le tunnel était
    # mort, pas Tor.  Premier recours : relancer OpenVPN seul, sur un circuit
    # neuf.  Le redémarrage complet ne vient qu'en second.
    _LIGHT_TIMEOUT = 45   # s sans tunnel après une relance légère → complet

    def _tor_is_healthy(self) -> bool:
        """Tor tourne et déclare pouvoir construire des circuits."""
        if not (self.tor_process and self.tor_process.poll() is None):
            return False
        try:
            rep = self._tor_ctrl("GETINFO status/circuit-established", timeout=3.0)
        except OSError:
            return False
        return "circuit-established=1" in rep

    def _restart_openvpn(self):
        """Relance OpenVPN seul, même compte, sur un circuit Tor neuf.

        Même mécanisme que le re-tirage de circuit : NEWNYM, puis arrêt du
        processus SANS _stop_vpn — la boucle OpenVPN reconnecte d'elle-même,
        après 2 s, sans temporisation ni changement de compte."""
        proc = self.openvpn_process
        self._new_tor_circuit()
        self._circuit_retry = True
        self._reconnect_reason = "perte de connectivité, relance d'OpenVPN"
        if proc and proc.poll() is None:
            proc.terminate()

    def _recover(self):
        """Panne de connectivité confirmée : reprise légère d'abord."""
        self._conn_fail_count = 0
        if not self._light_restart_done and self._tor_is_healthy():
            self._light_restart_done = True
            self._light_restart_at   = time.time()
            self._light_restart_count += 1
            self._log("Watchdog : Tor est sain — relance d'OpenVPN seul, sur "
                      "un circuit neuf …", "WARN")
            self._restart_openvpn()
            return
        if self._light_restart_done:
            self._log("Watchdog : la relance d'OpenVPN n'a pas suffi — "
                      "redémarrage complet.", "ERROR")
        self._conn_restart_pending = True
        self._full_restart()

    _GUARD_REFRESH_TICKS = 10   # ~30s (10 × 3s)
    _INERT_WARN_TICKS    = 20   # ~60s  d'inertie → avertissement
    _INERT_EXIT_TICKS    = 40   # ~120s d'inertie → sortie (relance systemd)

    def _monitor_loop(self):
        conn_tick  = 0
        guard_tick = 0
        while not self._stop_flag:
            time.sleep(3)
            if self._stop_flag:
                break

            # Ping watchdog systemd (WatchdogSec=90) : émis par CETTE boucle
            # uniquement — si elle gèle (deadlock, syscall suspendu), les
            # pings cessent et systemd tue puis relance le daemon.
            _sd_notify("WATCHDOG=1")

            rx   = self._read_tun0_rx()
            d_rx = max(0, rx - self._last_rx) if self._last_rx else 0
            self._last_rx    = rx
            self._rx_history.append(float(d_rx))

            # ── Filet anti-inertie ────────────────────────────────────────
            # Les boucles Tor/OpenVPN abandonnent après un nombre borné de
            # tentatives : sans ce filet, une longue coupure réseau laisserait
            # le daemon vivant mais inerte pour toujours.  Si plus aucune
            # boucle VPN ne tourne (et reconnexion auto active), on sort au
            # bout de 2 min : systemd (Restart=on-failure, illimité) relance
            # alors le daemon complet — aucune impasse n'est définitive.
            with self._vpn_lock:
                vpn_loop_alive = self._vpn_loop_active
            if (self.config.get("auto_reconnect", True)
                    and not vpn_loop_alive and not self._tunnel_up):
                self._inert_ticks += 1
                if self._inert_ticks == self._INERT_WARN_TICKS:
                    self._log(
                        "Watchdog : plus aucune boucle VPN active — sortie "
                        "pour relance systemd dans "
                        f"{(self._INERT_EXIT_TICKS - self._INERT_WARN_TICKS) * 3}s "
                        "si rien ne repart.", "WARN")
                elif self._inert_ticks >= self._INERT_EXIT_TICKS:
                    self._log(
                        "Watchdog : daemon inerte depuis "
                        f"{self._INERT_EXIT_TICKS * 3}s — sortie pour relance "
                        "complète par systemd.", "ERROR")
                    sys.exit(1)
            else:
                self._inert_ticks = 0

            # Rafraîchit les routes /32 des guards Tor : si Tor change de
            # garde en cours de session, son IP doit rester routée hors
            # tunnel, sinon boucle de routage (le tunnel dépend du guard).
            guard_tick += 1
            if self._tunnel_up and guard_tick >= self._GUARD_REFRESH_TICKS:
                guard_tick = 0
                self._protect_tor_routes()
                # Même rythme (~30s) : revérifie que le DNS n'a pas été
                # effacé par un redémarrage externe de systemd-resolved.
                self._ensure_dns_config()

            if self._tunnel_up:
                self._light_restart_at = 0.0     # la relance légère a abouti

            conn_tick += 1
            if conn_tick < 3:   # vérifier toutes les 9s (3 × 3s)
                continue
            conn_tick = 0

            # Relance légère restée sans effet : le tunnel ne remonte pas (Tor
            # malade malgré les apparences, serveur injoignable…).  Sans ce
            # garde, la boucle OpenVPN pourrait s'user seule en tentatives de
            # 60 s au lieu de rendre la main au redémarrage complet.
            if (self._light_restart_at and not self._tunnel_up
                    and self.config.get("auto_reconnect", True)
                    and not self._conn_restart_pending
                    and time.time() - self._light_restart_at > self._LIGHT_TIMEOUT):
                self._log(f"Watchdog : tunnel toujours absent "
                          f"{self._LIGHT_TIMEOUT} s après la relance "
                          "d'OpenVPN — redémarrage complet.", "ERROR")
                self._light_restart_at = 0.0
                self._conn_restart_pending = True
                self._full_restart()
                continue

            vpn_up = self._vpn_is_active()
            if not vpn_up or not self._tunnel_up:
                self._conn_fail_count = 0
                continue

            if not self.config.get("auto_reconnect", True) or self._conn_restart_pending:
                continue

            ok = self._check_connectivity()
            if ok:
                self._conn_fail_count    = 0
                self._full_restart_count = 0
                self._light_restart_done = False
            else:
                self._conn_fail_count += 1
                self._log(
                    f"Watchdog : pas de connectivité "
                    f"({self._conn_fail_count}/{CONN_FAIL_MAX}) …", "WARN")
                if self._conn_fail_count >= CONN_FAIL_MAX and not self._stop_vpn:
                    self._recover()
                else:
                    # Confirmation au tick suivant (3 s), pas au prochain
                    # cycle (9 s) : un second échec reste exigé contre les
                    # faux positifs, mais il n'a plus à se faire attendre.
                    conn_tick = 2
