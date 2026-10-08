"""
Pare-feu : blocage hors tunnel (kill switch), blocage IPv6, partage LAN.
"""

import ipaddress
import pwd
import shutil
import subprocess
import threading

from .core import (
    _run,
    KILL_CHAINS, KS6_CHAIN, KS6_FWD_CHAIN, KS_LAN_CHAIN,
    LAN_DNSMASQ_PID, TOR_USER,
)

# Destinations locales joignables hors tunnel : réseaux privés, lien local,
# multicast, diffusion.  Imprimante, NAS, routeur, DHCP, découverte mDNS : les
# couper rendrait la machine inutilisable sans rien protéger, ce trafic ne
# quittant pas le réseau local.  (Même choix que les clients VPN du commerce
# avec « partage du réseau local ».)
LOCAL_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
            "224.0.0.0/4", "255.255.255.255/32")
LOCAL_V6 = ("fe80::/10", "fc00::/7", "ff00::/8")
# Découverte de voisins et de routeurs IPv6 : sans elle, plus d'IPv6 local.
NDP_TYPES = ("router-solicitation", "router-advertisement",
             "neighbour-solicitation", "neighbour-advertisement")


class FirewallMixin:

    # ── Blocage hors tunnel (kill switch) ─────────────────────────────────────
    #
    # Sans lui, chaque reconnexion (circuit trop lent, relance d'OpenVPN,
    # redémarrage complet, bascule de compte) laissait quelques secondes à
    # quelques minutes pendant lesquelles le trafic sortait par la connexion
    # normale, avec l'adresse réelle.
    #
    # Principe : en sortie, seuls passent le tunnel (tun+), la boucle locale,
    # Tor lui-même — reconnu à son utilisateur, debian-tor, ce qui couvre ses
    # relais sans avoir à les connaître — et le réseau local.  OpenVPN ne
    # parle qu'à Tor (127.0.0.1:9050) puis au tunnel : il n'a besoin de rien
    # d'autre, y compris pour résoudre le nom du serveur VPN, transmis tel
    # quel au proxy SOCKS.
    #
    # Les chaînes vivent tant que le service tourne : posées avant le
    # démarrage de Tor, gardées pendant toutes les reconnexions et les
    # redémarrages complets, retirées à l'arrêt du service.

    def _kill_switch_destinations(self, v6: bool) -> list:
        """Destinations voulues hors tunnel : DNS local (split DNS) et
        exclusions, de la famille d'adresses demandée."""
        nets = []
        for entry in [self.config.get("local_dns", "")] + \
                list(self.config.get("excluded_ips", [])):
            try:
                net = ipaddress.ip_network(str(entry).strip(), strict=False)
            except ValueError:
                continue
            if (net.version == 6) == v6 and str(net) not in nets:
                nets.append(str(net))
        return nets

    def _kill_switch_rules(self, v6: bool, forward: bool, tor_uid: int) -> list:
        """Règles d'une chaîne, dans l'ordre : arguments après « -A chaîne ».

        L'ordre fait la sûreté : le refus du DNS précède l'ouverture du
        réseau local (sinon les requêtes partiraient vers le routeur, donc
        vers le FAI), et le REJECT final vient en dernier.

        REJECT plutôt que DROP, et « tcp-reset » pour TCP : une application
        bloquée échoue aussitôt au lieu d'attendre l'expiration.  En IPv6,
        l'ICMP « port injoignable » renvoyé à une connexion locale ne
        l'interrompt pas (vérifié) : seul le reset le fait."""
        regles = []
        if not forward:
            regles.append(["-o", "lo", "-j", "RETURN"])
        regles.append(["-o", "tun+", "-j", "RETURN"])
        if not forward:
            regles.append(["-m", "owner", "--uid-owner", str(tor_uid), "-j", "RETURN"])
        # Réponses aux connexions ENTRANTES (SSH depuis le LAN ou un VPN
        # d'administration) : --ctdir REPLY, jamais un simple ESTABLISHED,
        # qui laisserait continuer une connexion sortante ouverte à découvert.
        regles.append(["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                       "--ctdir", "REPLY", "-j", "RETURN"])
        if v6:
            regles += [["-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "RETURN"]
                       for t in NDP_TYPES]
        elif not forward:
            # Renouvellement du bail DHCP : sans lui, la machine perdrait son
            # adresse au bout du bail.
            regles.append(["-p", "udp", "--sport", "68", "--dport", "67", "-j", "RETURN"])
        regles += [["-d", net, "-j", "RETURN"]
                   for net in self._kill_switch_destinations(v6)]
        regles += [["-p", "udp", "--dport", "53", "-j", "REJECT"],
                   ["-p", "tcp", "--dport", "53", "-j", "REJECT", "--reject-with", "tcp-reset"]]
        regles += [["-d", net, "-j", "RETURN"] for net in (LOCAL_V6 if v6 else LOCAL_V4)]
        regles += [["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                   ["-j", "REJECT"]]
        return regles

    def _kill_switch_on(self) -> bool:
        """Pose le blocage hors tunnel, en tout ou rien : toutes les chaînes
        sont construites avant d'être branchées.  Une chaîne branchée à
        moitié pourrait bloquer Tor — et donc toute connexion — sans rien
        protéger de plus."""
        if self._kill_active:
            return True
        if not self.config.get("kill_switch", True):
            self._log("Blocage hors tunnel désactivé dans les réglages : pendant "
                      "une reconnexion, le trafic peut sortir à découvert.", "WARN")
            return False
        try:
            tor_uid = pwd.getpwnam(TOR_USER).pw_uid
        except KeyError:
            self._log(f"Blocage hors tunnel INACTIF : utilisateur {TOR_USER} absent, "
                      "impossible de laisser passer Tor seul. Il est créé par le "
                      "paquet tor : sudo apt install --reinstall tor", "ERROR")
            return False
        for tool, _parent, chain, v6, forward in KILL_CHAINS:
            _run(tool, "-N", chain)
            _run(tool, "-F", chain)
            for regle in self._kill_switch_rules(v6, forward, tor_uid):
                r = _run(tool, "-A", chain, *regle)
                if r.returncode != 0:
                    self._log(f"Blocage hors tunnel INACTIF : {tool} refuse "
                              f"« {' '.join(regle)} » "
                              f"({r.stderr.decode(errors='ignore').strip()}).", "ERROR")
                    self._kill_switch_off(force=True)
                    return False
        for tool, parent, chain, _v6, _fwd in KILL_CHAINS:
            if _run(tool, "-C", parent, "-j", chain).returncode == 0:
                continue
            if _run(tool, "-I", parent, "-j", chain).returncode != 0:
                self._log(f"Blocage hors tunnel INACTIF : branchement de {chain} "
                          f"sur {parent} impossible.", "ERROR")
                self._kill_switch_off(force=True)
                return False
        self._kill_active = True
        self._log("Blocage hors tunnel actif : seuls le tunnel, Tor et le réseau "
                  "local peuvent sortir.", "OK")
        return True

    def _kill_switch_off(self, force: bool = False):
        """Retire le blocage.  force : nettoie même s'il n'a pas abouti."""
        if not (self._kill_active or force):
            return
        for tool, parent, chain, _v6, _fwd in KILL_CHAINS:
            # Jumps d'abord : une chaîne vidée mais encore branchée ne
            # bloquerait rien, mais ne pourrait pas être supprimée.
            for _ in range(25):
                if _run(tool, "-D", parent, "-j", chain).returncode != 0:
                    break
            _run(tool, "-F", chain)
            _run(tool, "-X", chain)
        if self._kill_active:
            self._log("Blocage hors tunnel levé.", "OK")
        self._kill_active = False

    # ── Blocage IPv6 ──────────────────────────────────────────────────────────

    def _ipv6_block_on(self):
        if self._ipv6_blocked:
            return
        tun = self._tun_iface
        try:
            _run("ip6tables", "-N", KS6_CHAIN)
            _run("ip6tables", "-F", KS6_CHAIN)
            _run("ip6tables", "-A", KS6_CHAIN, "-o", "lo",  "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN, "-o", tun,   "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_CHAIN, "-j", "DROP")
            r = _run("ip6tables", "-I", "OUTPUT", "-j", KS6_CHAIN)
            if r.returncode != 0:
                self._log("ip6tables OUTPUT : échec.", "ERROR")
                return

            _run("ip6tables", "-N", KS6_FWD_CHAIN)
            _run("ip6tables", "-F", KS6_FWD_CHAIN)
            _run("ip6tables", "-A", KS6_FWD_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_FWD_CHAIN, "-i", "virbr+", "-o", "virbr+", "-j", "RETURN")
            _run("ip6tables", "-A", KS6_FWD_CHAIN, "-i", "virbr+", "-j", "DROP")
            _run("ip6tables", "-I", "FORWARD", "-j", KS6_FWD_CHAIN)

            self._ipv6_blocked = True
            self._log("IPv6 bloqué — host + VMs.", "OK")
        except Exception as e:
            self._log(f"IPv6 block : {e}", "ERROR")

    def _ipv6_block_off(self):
        if not self._ipv6_blocked:
            return
        try:
            _run("ip6tables", "-D", "OUTPUT",  "-j", KS6_CHAIN)
            _run("ip6tables", "-F", KS6_CHAIN)
            _run("ip6tables", "-X", KS6_CHAIN)
            _run("ip6tables", "-D", "FORWARD", "-j", KS6_FWD_CHAIN)
            _run("ip6tables", "-F", KS6_FWD_CHAIN)
            _run("ip6tables", "-X", KS6_FWD_CHAIN)
            self._ipv6_blocked = False
        except Exception:
            pass

    # ── Partage LAN ───────────────────────────────────────────────────────────

    def _setup_lan_sharing(self) -> bool:
        # Les règles figent le nom de l'interface tunnel (MASQUERADE -o tun,
        # RETURN -o tun).  Après un remontage du tunnel — redémarrage complet
        # du watchdog ou simple reconnexion OpenVPN — ce nom peut changer
        # (« dev tun » choisit le premier device libre).  Sortir en avance
        # laisserait alors des règles pointant dans le vide : le RETURN ne
        # correspond plus, le trafic LAN tombe sur le DROP final et les
        # clients perdent tout accès, en silence.  On reconstruit donc.
        if self._lan_active:
            if self._lan_tun == self._tun_iface:
                return True
            self._log(
                f"Partage LAN : interface tunnel changée "
                f"({self._lan_tun or '?'} → {self._tun_iface}) — "
                "reconstruction des règles.", "WARN")
            self._teardown_lan_sharing()
        iface  = self.config.get("lan_iface",   "").strip()
        gw     = self.config.get("lan_gateway", "10.0.0.1").strip()
        subnet = self.config.get("lan_subnet",  "10.0.0.0/24").strip()
        if not iface:
            self._log("Partage LAN : aucune interface configurée.", "ERROR")
            return False
        # Refus catégorique : ne jamais flush l'interface qui porte la route
        # par défaut (uplink Internet) — cela couperait toute connectivité.
        _, uplink = self._get_default_gateway()
        if uplink and iface == uplink:
            self._log(
                f"Partage LAN : '{iface}' porte la route par défaut (uplink) — "
                "configuration refusée pour ne pas couper le réseau.", "ERROR")
            return False
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            self._log(f"Partage LAN : sous-réseau invalide : {subnet}", "ERROR")
            return False
        try:
            _run("ip", "addr", "flush", "dev", iface)
            r = _run("ip", "addr", "add", f"{gw}/{net.prefixlen}", "dev", iface)
            if r.returncode != 0:
                self._log(f"Partage LAN : ip addr add : {r.stderr.decode().strip()}", "ERROR")
                return False
            _run("ip", "link", "set", iface, "up")
            tun = self._tun_iface
            _run("sysctl", "-w", "net.ipv4.ip_forward=1")
            r = _run("iptables", "-t", "nat", "-C", "POSTROUTING",
                     "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            if r.returncode != 0:
                _run("iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            _run("iptables", "-N", KS_LAN_CHAIN)
            _run("iptables", "-F", KS_LAN_CHAIN)
            _run("iptables", "-A", KS_LAN_CHAIN,
                 "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
            _run("iptables", "-A", KS_LAN_CHAIN, "-i", iface, "-o", tun, "-j", "RETURN")
            _run("iptables", "-A", KS_LAN_CHAIN, "-i", iface, "-j", "DROP")
            _run("iptables", "-I", "FORWARD", "-j", KS_LAN_CHAIN)
            self._lan_active = True
            self._lan_tun    = tun   # mémorisé pour le démontage et la détection
            self._log(f"Partage LAN actif : {iface} ({gw}/{net.prefixlen}) → {tun}.", "OK")
            if self.config.get("lan_dhcp", True):
                self._start_lan_dnsmasq(iface, gw, net)
            return True
        except Exception as e:
            self._log(f"Partage LAN : {e}", "ERROR")
            return False

    def _teardown_lan_sharing(self):
        if not self._lan_active:
            return
        iface  = self.config.get("lan_iface",  "").strip()
        subnet = self.config.get("lan_subnet", "10.0.0.0/24").strip()
        self._stop_lan_dnsmasq()
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            net = None
        try:
            _run("iptables", "-D", "FORWARD", "-j", KS_LAN_CHAIN)
            _run("iptables", "-F", KS_LAN_CHAIN)
            _run("iptables", "-X", KS_LAN_CHAIN)
            if net:
                # Supprimer avec l'interface RÉELLEMENT utilisée à la création,
                # pas avec _tun_iface : s'il a changé depuis, on effacerait une
                # règle inexistante en laissant la vraie orpheline dans le NAT.
                _run("iptables", "-t", "nat", "-D", "POSTROUTING",
                     "-s", str(net), "-o", self._lan_tun or self._tun_iface,
                     "-j", "MASQUERADE")
            if iface:
                _run("ip", "addr", "flush", "dev", iface)
            self._lan_active = False
            self._lan_tun    = ""
            self._log("Partage LAN désactivé.", "OK")
        except Exception as e:
            self._log(f"Partage LAN (désactivation) : {e}", "ERROR")

    def _start_lan_dnsmasq(self, iface: str, gw: str, net):
        if not shutil.which("dnsmasq"):
            self._log("dnsmasq non installé — DHCP inactif.", "WARN")
            return
        # Bornes calculées arithmétiquement : ne jamais matérialiser
        # net.hosts() (un /8 représenterait ~16 M d'adresses en mémoire).
        base = int(net.network_address)
        n    = max(net.num_addresses - 2, 0)   # nb d'hôtes (hors réseau/broadcast)
        if n < 1:
            self._log("Partage LAN : sous-réseau trop petit pour le DHCP.", "WARN")
            return
        if n >= 200:
            dhcp_start = str(ipaddress.ip_address(base + 100))
            dhcp_end   = str(ipaddress.ip_address(base + 200))
        elif n >= 10:
            dhcp_start = str(ipaddress.ip_address(base + 1 + n // 4))
            dhcp_end   = str(ipaddress.ip_address(base + 1 + 3 * n // 4))
        else:
            dhcp_start = str(ipaddress.ip_address(base + 1))
            dhcp_end   = str(ipaddress.ip_address(base + n))
        cmd = [
            "dnsmasq",
            f"--interface={iface}",
            "--bind-interfaces",
            "--no-daemon",
            f"--dhcp-range={dhcp_start},{dhcp_end},24h",
            f"--dhcp-option=3,{gw}",
            "--dhcp-option=6,1.1.1.1",
            "--no-resolv",
            # Pas de serveur DNS : les clients reçoivent 1.1.1.1 (option 6),
            # joint par le tunnel.  Sans --port=0, dnsmasq écoutait quand même
            # sur le port 53 de l'interface, sans serveur amont à interroger.
            "--port=0",
            f"--pid-file={LAN_DNSMASQ_PID}",
        ]

        def _run_dns():
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._dnsmasq_proc = proc
                self._log(f"dnsmasq DHCP démarré : {iface} ({dhcp_start}–{dhcp_end}).", "OK")
                proc.wait()
                self._log("dnsmasq terminé.", "WARN")
                LAN_DNSMASQ_PID.unlink(missing_ok=True)
            except Exception as ex:
                self._log(f"dnsmasq : {ex}", "ERROR")

        threading.Thread(target=_run_dns, daemon=True).start()

    def _stop_lan_dnsmasq(self):
        proc = self._dnsmasq_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        self._dnsmasq_proc = None
        LAN_DNSMASQ_PID.unlink(missing_ok=True)
