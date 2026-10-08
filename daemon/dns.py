"""
DNS : split DNS via drop-in systemd-resolved, et DNS du VPN appliqué
nativement par resolvectl (sans dépendre du script update-resolv-conf).
"""

import shutil
import subprocess

from .core import _run, RESOLVED_DROP_IN


class DNSMixin:

    # ── Contrôle de l'environnement DNS ──────────────────────────────────────

    def _check_dns_stack(self):
        """Vérifie au démarrage que systemd-resolved est disponible et actif.
        Sans lui, le DNS du VPN et le split DNS ne peuvent pas s'appliquer :
        le trafic reste tunnelé, mais les requêtes DNS peuvent échouer ou
        fuir hors Tor.  On avertit tôt (au lieu d'attendre la 1re connexion)."""
        if not shutil.which("resolvectl"):
            self._log(
                "resolvectl introuvable — systemd-resolved requis pour la "
                "protection DNS (DNS du VPN + split DNS). Sans lui, la "
                "résolution DNS peut échouer ou fuir hors Tor. "
                "Installez systemd-resolved.", "WARN")
            return
        if _run("systemctl", "is-active", "systemd-resolved").stdout \
                .decode().strip() != "active":
            self._log(
                "systemd-resolved n'est pas actif — la protection DNS ne "
                "pourra pas s'appliquer. Lancez : "
                "systemctl enable --now systemd-resolved.", "WARN")

    @staticmethod
    def _resolvectl_link_status(iface: str) -> dict:
        """État DNS d'une interface sous forme d'étiquettes → valeurs.

        « resolvectl status <iface> » expose serveurs, domaines et
        default-route en UN seul appel — inutile d'en faire trois."""
        r = subprocess.run(["resolvectl", "status", iface],
                           capture_output=True, text=True, timeout=5)
        info = {}
        for ln in r.stdout.splitlines():
            label, sep, val = ln.partition(":")
            if sep:
                info[label.strip()] = val.strip()
        return info

    @staticmethod
    def _default_route_state(info: dict):
        """default-route de l'interface : True, False, ou None si illisible.

        Le format varie selon la version de systemd, et les deux formes
        coexistent sur les versions récentes :

          systemd 259  Protocols: +DefaultRoute -LLMNR …
                       Default Route: yes
          systemd 255  Protocols: +DefaultRoute -LLMNR …
                       (pas d'étiquette « Default Route »)

        On lit donc le drapeau de « Protocols » en premier — c'est la forme
        présente partout — et l'étiquette ne sert que de repli.

        Le troisième état compte autant que les deux autres : renvoyer False
        quand on n'a pas su lire ferait conclure à tort que le réglage manque,
        et le daemon réappliquerait le DNS à chaque tick du watchdog.
        L'appelant doit tester « is False », jamais « not ... »."""
        proto = info.get("Protocols", "")
        if "+DefaultRoute" in proto:
            return True
        if "-DefaultRoute" in proto:
            return False
        # Replis : étiquette dédiée, sous ses deux orthographes connues.
        for label in ("Default Route", "DefaultRoute setting"):
            if label in info:
                return info[label].strip().lower() in ("yes", "true")
        return None

    def _ensure_dns_config(self):
        """Réapplique le DNS s'il a disparu (ex. systemd-resolved redémarré
        par un autre outil).  Appelé périodiquement par le watchdog quand le
        tunnel est actif.  Léger : en temps normal, une simple lecture ;
        réapplication uniquement si la config a effectivement été perdue."""
        if not self._tunnel_up:
            return
        # 1. DNS du VPN (config runtime par interface — perdue si resolved
        #    redémarre, contrairement au drop-in qui est persistant).
        #
        #    On contrôle les TROIS attributs posés par _apply_vpn_dns : le
        #    serveur seul ne suffit pas.  Le hook natif dns-updown d'OpenVPN
        #    2.6+ réinstalle le serveur à chaque reconnexion interne
        #    (SIGUSR1), mais pas forcément « ~. » ni le default-route.  Sans
        #    eux, l'interface tunnel cesse d'être la destination DNS par
        #    défaut et les requêtes publiques peuvent repartir vers le DNS
        #    local — hors tunnel, et sans que rien ne le signale.
        if self._vpn_dns_ips:
            missing = []
            try:
                st = self._resolvectl_link_status(self._tun_iface)
            except Exception:
                st = {}
            if st:   # vide = lecture impossible : ne rien conclure
                if not any(ip in st.get("DNS Servers", "")
                           for ip in self._vpn_dns_ips):
                    missing.append("serveur")
                if "~." not in st.get("DNS Domain", "").split():
                    missing.append("domaine ~.")
                # « is False » et non « not ... » : sur None (format de
                # resolvectl non reconnu) on s'abstient.  Conclure à l'absence
                # déclencherait une réapplication du DNS à chaque tick du
                # watchdog, indéfiniment, sur une configuration saine.
                if self._default_route_state(st) is False:
                    missing.append("default-route")
            if missing:
                self._log(
                    f"[dns] Config DNS du VPN incomplète sur "
                    f"{self._tun_iface} ({', '.join(missing)}) — "
                    "réapplication.", "WARN")
                self._apply_vpn_dns()
        # 2. Drop-in split DNS (persistant, mais un autre outil a pu le
        #    supprimer) : le réécrire s'il devrait exister et manque.
        if (self.config.get("local_dns", "").strip()
                and self.config.get("excluded_domains")
                and not RESOLVED_DROP_IN.exists()):
            self._log("[dns] Drop-in split DNS disparu — réapplication.", "WARN")
            self._apply_dns_split()

    # ── DNS du VPN (poussé par le serveur, appliqué via resolvectl) ──────────

    def _apply_vpn_dns(self):
        """Applique les serveurs DNS poussés par le VPN (PUSH_REPLY
        dhcp-option DNS) sur l'interface tunnel via systemd-resolved.
        « ~. » fait de ces serveurs la destination DNS par défaut ; le
        drop-in du split DNS garde la priorité sur les domaines exclus."""
        ips = list(dict.fromkeys(self._vpn_dns_ips))   # dédup, ordre conservé
        if not ips:
            self._log(
                "Aucun DNS poussé par le VPN (dhcp-option DNS absent du "
                "PUSH_REPLY) — DNS système inchangé, risque de fuite ou de "
                "panne DNS derrière redirect-gateway.", "WARN")
            return
        tun = self._tun_iface
        try:
            r = subprocess.run(["resolvectl", "dns", tun, *ips],
                               capture_output=True, timeout=10)
            if r.returncode != 0:
                self._log(
                    f"resolvectl dns {tun} : "
                    f"{r.stderr.decode(errors='ignore').strip() or 'échec'} — "
                    "systemd-resolved est-il actif ?", "ERROR")
                return
            subprocess.run(["resolvectl", "domain", tun, "~."],
                           capture_output=True, timeout=10)
            subprocess.run(["resolvectl", "default-route", tun, "true"],
                           capture_output=True, timeout=10)
            self._log(f"DNS du VPN appliqué sur {tun} : {', '.join(ips)}", "OK")
        except FileNotFoundError:
            self._log("resolvectl introuvable — DNS du VPN non appliqué. "
                      "Installez systemd-resolved.", "ERROR")
        except Exception as e:
            self._log(f"DNS du VPN : {e}", "ERROR")

    def _revert_vpn_dns(self):
        """Retire la config DNS de l'interface tunnel (sans toucher au
        split DNS).  Sans effet si l'interface a déjà disparu."""
        try:
            subprocess.run(["resolvectl", "revert", self._tun_iface],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        self._vpn_dns_ips = []

    def _apply_dns_split(self):
        dns     = self.config.get("local_dns", "").strip()
        domains = self.config.get("excluded_domains", [])
        if not dns or not domains:
            self._remove_dns_split()
            return
        domain_str = " ".join(f"~{d.lstrip('.')}" for d in domains)
        try:
            RESOLVED_DROP_IN.parent.mkdir(parents=True, exist_ok=True)
            RESOLVED_DROP_IN.write_text(f"[Resolve]\nDNS={dns}\nDomains={domain_str}\n")
            # « resolvectl reload » n'existe pas, et « systemctl reload »
            # échoue sur les systemd sans ExecReload : reload-or-restart
            # applique le drop-in de manière fiable partout.
            subprocess.run(["systemctl", "reload-or-restart", "systemd-resolved"],
                           capture_output=True, timeout=15)
            self._log(f"DNS split actif : {len(domains)} domaine(s) → {dns}", "OK")
        except Exception as e:
            self._log(f"DNS split : {e}", "WARN")

    def _remove_dns_split(self):
        if RESOLVED_DROP_IN.exists():
            try:
                RESOLVED_DROP_IN.unlink()
                subprocess.run(["systemctl", "reload-or-restart", "systemd-resolved"],
                               capture_output=True, timeout=15)
                self._log("DNS split désactivé.", "OK")
            except Exception:
                pass
