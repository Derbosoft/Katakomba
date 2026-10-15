"""
Réseau : gateway, SOCKS, routes Tor, routes exclues, et montage du tunnel
(adresse et routes), que le daemon pose lui-même depuis la v3.9.0 :
OpenVPN tourne sans aucun droit et ne touche plus au réseau.
"""

import ipaddress
import socket

from validation import verifier_exclusion

from .core import _run, _write_private, TOR_ROUTES_FILE


class NetworkMixin:

    def _get_default_gateway(self):
        try:
            r = _run("ip", "route", "show", "default")
            for line in r.stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
                    return parts[2], parts[4]
        except Exception:
            pass
        return None, None

    def _check_socks_port(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 9050), timeout=3):
                return True
        except OSError:
            return False

    def _connected_networks(self) -> list:
        """Réseaux directement connectés (routes kernel « scope link »)."""
        nets = []
        try:
            r = _run("ip", "-4", "route", "show", "scope", "link")
            for line in r.stdout.decode().splitlines():
                parts = line.split()
                if parts and "/" in parts[0]:
                    try:
                        nets.append(ipaddress.ip_network(parts[0], strict=False))
                    except ValueError:
                        pass
        except Exception:
            pass
        return nets

    def _build_route_args(self) -> list:
        """Exclusions sous forme d'options « --route … net_gateway »."""
        args = []
        for net in self._reseaux_exclus():
            args += ["--route", str(net.network_address), str(net.netmask), "net_gateway"]
        return args

    def _reseaux_exclus(self) -> list:
        """Exclusions à router hors du tunnel, validées (voir verifier_exclusion)."""
        nets = []
        connected = self._connected_networks()
        for entry in self.config.get("excluded_ips", []):
            # Même contrôle que le GUI : invalide, IPv6 (« --route » est une
            # option IPv4, l'exclusion serait ignorée en silence) ou trop
            # large vers Internet (config.json modifiée hors du GUI).
            valeur, erreur = verifier_exclusion(entry)
            if erreur:
                self._log(f"Exclusion ignorée : {erreur}", "WARN")
                continue
            if not valeur:
                continue
            net = ipaddress.ip_network(valeur)
            # Un réseau directement connecté ne doit JAMAIS être routé via
            # net_gateway : sa route kernel (scope link, /24 par ex.) prime
            # déjà sur redirect-gateway (0.0.0.0/1) par longest-prefix-match,
            # donc il est de toute façon hors tunnel.  L'exclure superpose une
            # route « via <gw> » de métrique 0 qui SUPPLANTE la route directe :
            # tout le LAN part alors en détour par le routeur (hairpin), ce qui
            # casse l'accès aux machines du même segment — typiquement un
            # serveur VPN d'accès distant hébergé sur ce LAN.
            if any(net.version == c.version and net.subnet_of(c)
                   for c in connected):
                self._log(
                    f"Exclusion ignorée ({entry}) : réseau directement "
                    "connecté, déjà hors tunnel via sa route locale. "
                    "L'exclure casserait l'accès aux machines de ce LAN.",
                    "INFO")
                continue
            nets.append(net)
        return nets

    # ── Montage du tunnel (OpenVPN sans privilège) ───────────────────────────

    def _creer_tun(self, utilisateur: str) -> bool:
        """Interface tunnel neuve, propriété de l'utilisateur d'OpenVPN : il
        l'ouvre sans aucun droit.  Une interface restée d'une session
        précédente est supprimée, avec ses adresses et ses routes."""
        tun = self._tun_iface
        _run("ip", "link", "del", "dev", tun)
        r = _run("ip", "tuntap", "add", "dev", tun, "mode", "tun",
                 "user", utilisateur, "group", utilisateur)
        if r.returncode != 0:
            self._log(f"Interface {tun} impossible à créer : "
                      f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")
            return False
        return True

    def _monter_tunnel(self, reglages: dict) -> bool:
        """Pose l'adresse et les routes du tunnel, dans l'ordre qui protège.

        1. Routes /32 des relais Tor, AVANT toute route du tunnel : sinon Tor
           joindrait ses relais par le tunnel qui dépend d'eux.  OpenVPN
           posant lui-même ses routes, le daemon devait guetter
           « net_addr_v4_add » dans sa sortie pour passer avant lui ; il
           n'y a plus de course.
        2. Adresse, MTU, interface levée.
        3. Exclusions, via la passerelle d'origine.
        4. Routes poussées acceptées (toutes dans le tunnel), puis les deux
           moitiés d'Internet (0/1 et 128/1) dans le tunnel."""
        tun = self._tun_iface
        for msg in reglages["refus"]:
            self._log(f"[tunnel] {msg}", "WARN")
        if not reglages["ifconfig"]:
            self._log("[tunnel] Le serveur VPN n'a fourni aucune adresse (ifconfig) "
                      "— tunnel non monté.", "ERROR")
            return False
        self._protect_tor_routes()

        local, second = reglages["ifconfig"]
        if reglages["topology"] == "subnet":
            prefixe = ipaddress.IPv4Network(f"{local}/{second}", strict=False).prefixlen
            adresse = ["ip", "addr", "add", f"{local}/{prefixe}", "dev", tun]
        else:
            adresse = ["ip", "addr", "add", local, "peer", second, "dev", tun]
        etapes = [["ip", "addr", "flush", "dev", tun], adresse]
        if reglages["tun_mtu"]:
            etapes.append(["ip", "link", "set", "dev", tun, "mtu", str(reglages["tun_mtu"])])
        etapes.append(["ip", "link", "set", "dev", tun, "up"])
        for cmd in etapes:
            r = _run(*cmd)
            if r.returncode != 0:
                self._log(f"[tunnel] « {' '.join(cmd)} » : "
                          f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")
                return False

        self._routes_exclues = []
        exclus = self._reseaux_exclus()
        if exclus and not self._orig_gw:
            self._log("[tunnel] Passerelle d'origine inconnue — exclusions non "
                      "routées hors du tunnel.", "WARN")
        elif exclus:
            for net in exclus:
                _run("ip", "route", "replace", str(net),
                     "via", self._orig_gw, "dev", self._orig_iface)
                self._routes_exclues.append(str(net))

        # Une route poussée vers un réseau local ou exclu détournerait ce
        # trafic dans le tunnel, vers le fournisseur VPN.
        locaux = self._connected_networks() + exclus
        for net in reglages["routes"]:
            if any(net.overlaps(n) for n in locaux):
                self._log(f"[tunnel] Route poussée ignorée : {net} recouvre un "
                          "réseau local ou exclu.", "WARN")
                continue
            _run("ip", "route", "replace", str(net), "dev", tun, "scope", "global")
        # « scope global » : sans passerelle, une route prendrait la portée
        # « link », celle des réseaux directement connectés — que le daemon
        # et `katakomba doctor` repèrent justement par elle.  Les deux
        # moitiés d'Internet passeraient pour un réseau local.
        for moitie in ("0.0.0.0/1", "128.0.0.0/1"):
            r = _run("ip", "route", "replace", moitie, "dev", tun, "scope", "global")
            if r.returncode != 0:
                self._log(f"[tunnel] Route {moitie} impossible : "
                          f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")
                return False
        self._log(f"[tunnel] {tun} : {local} ({reglages['topology']}), tout le "
                  "trafic dans le tunnel.", "OK")
        return True

    def _demonter_tunnel(self):
        """Supprime l'interface tunnel (adresse et routes partent avec elle)
        et les routes d'exclusion.  Sans elles, Tor rejoint ses relais par la
        route par défaut pour la reconnexion suivante."""
        for net in self._routes_exclues:
            _run("ip", "route", "del", net)
        self._routes_exclues = []
        _run("ip", "link", "del", "dev", self._tun_iface)

    def _add_protected_routes(self, ips, source: str):
        """Route en /32 via la gateway originale chaque IP IPv4 valide et
        nouvelle de `ips`, journalise et persiste l'ensemble."""
        added = []
        for ip in sorted(ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or ip.startswith(("127.", "0.")):
                continue
            if ip in self._protected_routes:
                continue
            _run("ip", "route", "replace", f"{ip}/32",
                 "via", self._orig_gw, "dev", self._orig_iface)
            self._protected_routes.add(ip)
            added.append(ip)
        if added:
            self._log(
                f"[route] {len(added)} IP(s) Tor protégée(s) via {source} "
                f"(total {len(self._protected_routes)}).", "INFO")
            # Écrit en root : jamais à travers un lien symbolique (le fichier
            # vit sous /var/lib/katakomba, hors de portée du groupe).
            # 0644 : `katakomba doctor`, lancé sans root, doit pouvoir le lire.
            try:
                _write_private(TOR_ROUTES_FILE,
                               "\n".join(sorted(self._protected_routes)) + "\n",
                               mode=0o644, dir_mode=0o755)
            except Exception:
                pass

    def _protect_tor_routes(self):
        """Ajoute des routes /32 statiques via la gateway originale pour chaque
        IP de relais Tor actif.  Appel SYNCHRONE depuis le thread stdout
        d'OpenVPN, avant l'installation de redirect-gateway.
        Source primaire : ControlPort (orconn-status) ; repli : ss -tnp."""
        if not self._orig_gw or not self.tor_process:
            return

        # Source primaire : le ControlPort (fiable, indépendant du format
        # de sortie de ss).  Repli : inspection des sockets établies.
        ctrl_ips = self._tor_relay_ips()
        if ctrl_ips:
            self._add_protected_routes(ctrl_ips, "ControlPort")
            return

        pid = self.tor_process.pid
        try:
            # ss -tnp state established → colonnes :
            #   Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
            # On extrait l'adresse pair (relais Tor), colonne d'index 3.
            r = _run("ss", "-tnp", "state", "established")
            peers = set()
            for line in r.stdout.decode().splitlines():
                if f"pid={pid}" not in line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                peer = parts[3]
                # IPv6 entre crochets ([2001:db8::1]:443) → ignoré (tunnel IPv4).
                if peer.startswith("["):
                    continue
                peers.add(peer.rsplit(":", 1)[0])
            self._add_protected_routes(peers, "ss")
        except Exception as e:
            self._log(f"[route] {e}", "WARN")

    def _cleanup_tor_routes(self):
        """Supprime les routes /32 Tor (session courante + fichier persistant)."""
        routes = set(self._protected_routes)
        if TOR_ROUTES_FILE.exists():
            try:
                routes.update(
                    ln.strip()
                    for ln in TOR_ROUTES_FILE.read_text().splitlines()
                    if ln.strip()
                )
            except Exception:
                pass
        for ip in routes:
            _run("ip", "route", "del", f"{ip}/32")
        self._protected_routes.clear()
        TOR_ROUTES_FILE.unlink(missing_ok=True)
        if routes:
            self._log(f"[route] {len(routes)} route(s) /32 Tor supprimée(s).", "INFO")
