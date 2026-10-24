"""
Réseau : gateway, SOCKS, routes Tor, routes exclues, et montage du tunnel
(adresse et routes), que le daemon pose lui-même depuis la v3.9.0 :
OpenVPN tourne sans aucun droit et ne touche plus au réseau.
"""

import ipaddress
import socket

from validation import verifier_exclusion

from .core import (
    _run, _write_private, TOR_ROUTES_FILE,
    RETOUR_CHAINES, RETOUR_MARQUE, RETOUR_PRIORITES, RETOUR_TABLE, SRC_VALID_MARK,
)


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

        # Avant les deux moitiés d'Internet : une session SSH déjà ouverte
        # ne doit pas voir une seule de ses réponses partir dans le tunnel.
        self._retour_entrant_on(local)

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
        self._retour_voulu = False
        self._retour_entrant_off()

    # ── Retour des connexions entrantes ──────────────────────────────────────
    #
    # Une fois Internet routé dans le tunnel, la réponse à une connexion
    # ENTRANTE — SSH sur un serveur, site web, partage de fichiers depuis
    # Internet — partirait elle aussi dans le tunnel : elle arriverait au
    # client depuis une autre adresse, et la session tomberait.  Sur un
    # serveur administré à distance, démarrer le service coupait la main.
    #
    # Les connexions entrantes sont donc marquées (conntrack), et une règle
    # de routage renvoie leurs paquets par la passerelle d'origine.  Le trafic
    # que la machine ÉMET elle-même n'est jamais marqué : il reste dans le
    # tunnel.  Rien ne fuit : ces réponses vont à qui a contacté la machine
    # par son adresse réelle, et la connaît donc déjà.

    def _retour_regles(self, local: str) -> dict:
        """Règles de la table mangle, par chaîne : arguments après « -A »."""
        tun, marque = self._tun_iface, RETOUR_MARQUE
        poser = ["-j", "CONNMARK", "--set-xmark", marque]
        restaurer = ["-m", "connmark", "--mark", marque,
                     "-j", "MARK", "--set-xmark", marque]
        return {
            # Paquet reçu dans le sens « aller » d'une connexion, à destination
            # de la machine : c'est le correspondant qui l'a ouverte.  Venue
            # du tunnel (redirection de port du fournisseur), elle doit au
            # contraire y répondre.  Le marquage du paquet lui-même sert au
            # filtrage de chemin inverse (rp_filter strict, src_valid_mark)
            # et aux réponses des conteneurs (Docker), qui sont routées.
            "KATAKOMBA_RETOUR": [
                ["-i", "lo", "-j", "RETURN"],
                ["-i", tun, "-j", "RETURN"],
                ["-m", "conntrack", "--ctdir", "ORIGINAL",
                 "-m", "addrtype", "--dst-type", "LOCAL", *poser],
                restaurer,
            ],
            # Paquet émis dans le sens « retour » : réponse de la machine à
            # une connexion ouverte par un autre.  Couvre une session SSH
            # ouverte AVANT ces règles : sa prochaine réponse est marquée sans
            # attendre un paquet du client.  Les connexions venues du tunnel
            # visent l'adresse du tunnel : exclues.
            "KATAKOMBA_RETOUR_OUT": [
                ["-o", "lo", "-j", "RETURN"],
                ["-m", "conntrack", "--ctdir", "REPLY", "!", "--ctorigdst", local, *poser],
                restaurer,
            ],
        }

    def _retour_entrant_on(self, local: str) -> bool:
        """Pose le retour des connexions entrantes, en tout ou rien.

        Deux règles de routage pour les paquets marqués : la table principale
        privée de ses routes de longueur 0 et 1 (route par défaut, 0/1 et
        128/1 du tunnel) — réseaux locaux, exclusions et relais Tor restent
        donc valables —, puis une table qui ne contient que l'ancienne route
        par défaut."""
        self._retour_entrant_off(force=True)
        if not self._orig_gw:
            self._log("[tunnel] Passerelle d'origine inconnue : les réponses aux "
                      "connexions entrantes (SSH, services) partiront dans le "
                      "tunnel — une session distante serait coupée.", "ERROR")
            return False
        self._retour_local = local
        regles = self._retour_regles(local)
        etapes = []
        for parent, chaine in RETOUR_CHAINES:
            _run("iptables", "-t", "mangle", "-N", chaine)
            _run("iptables", "-t", "mangle", "-F", chaine)
            etapes += [["iptables", "-t", "mangle", "-A", chaine, *r] for r in regles[chaine]]
            etapes.append(["iptables", "-t", "mangle", "-I", parent, "-j", chaine])
        etapes += [
            ["ip", "route", "replace", "default", "via", self._orig_gw,
             "dev", self._orig_iface, "table", RETOUR_TABLE],
            ["ip", "rule", "add", "priority", RETOUR_PRIORITES[0], "fwmark", RETOUR_MARQUE,
             "lookup", "main", "suppress_prefixlength", "1"],
            ["ip", "rule", "add", "priority", RETOUR_PRIORITES[1], "fwmark", RETOUR_MARQUE,
             "lookup", RETOUR_TABLE],
        ]
        for cmd in etapes:
            r = _run(*cmd)
            if r.returncode != 0:
                self._log(f"[tunnel] Retour des connexions entrantes impossible : "
                          f"« {' '.join(cmd)} » ({r.stderr.decode(errors='ignore').strip()}) "
                          "— une session SSH distante serait coupée.", "ERROR")
                self._retour_entrant_off(force=True)
                return False
        # Filtrage de chemin inverse strict (rp_filter=1) : sans la marque,
        # le noyau croirait qu'une réponse au client devait passer par le
        # tunnel et jetterait ses paquets à l'arrivée.
        try:
            avant = SRC_VALID_MARK.read_text().strip()
            if avant != "1":
                SRC_VALID_MARK.write_text("1\n")
                self._src_valid_mark = avant
        except OSError as e:
            self._log(f"[tunnel] src_valid_mark : {e}", "WARN")
        self._retour_actif = True
        self._retour_voulu = True
        self._log(f"[tunnel] Connexions entrantes : réponses par {self._orig_iface} "
                  "(SSH et services restent joignables).", "OK")
        return True

    def _retour_en_place(self) -> bool:
        """Les deux règles de routage et la table du retour existent encore."""
        r = _run("ip", "-4", "rule", "show")
        prios = {ligne.split(":", 1)[0].strip()
                 for ligne in r.stdout.decode(errors="ignore").splitlines()}
        if not all(p in prios for p in RETOUR_PRIORITES):
            return False
        r = _run("ip", "-4", "route", "show", "table", RETOUR_TABLE)
        return r.returncode == 0 and bool(r.stdout.strip())

    def _retour_entrant_off(self, force: bool = False):
        """Retire marquage et règles de routage.  force : sans rien supposer de
        l'état (session précédente, échec en cours de pose)."""
        if not (self._retour_actif or force):
            return
        for parent, chaine in RETOUR_CHAINES:
            for _ in range(25):
                if _run("iptables", "-t", "mangle", "-D", parent, "-j", chaine).returncode != 0:
                    break
            _run("iptables", "-t", "mangle", "-F", chaine)
            _run("iptables", "-t", "mangle", "-X", chaine)
        for priorite in RETOUR_PRIORITES:
            for _ in range(25):
                if _run("ip", "rule", "del", "priority", priorite).returncode != 0:
                    break
        _run("ip", "route", "flush", "table", RETOUR_TABLE)
        if self._src_valid_mark is not None:
            try:
                SRC_VALID_MARK.write_text(self._src_valid_mark + "\n")
            except OSError:
                pass
            self._src_valid_mark = None
        self._retour_actif = False

    def _add_protected_routes(self, ips, source: str) -> int:
        """Route en /32 via la gateway originale chaque IP IPv4 valide de
        `ips`, journalise et persiste l'ensemble.  Renvoie le nombre de
        routes reposées : connues, mais effacées entre-temps.

        L'ensemble en mémoire ne prouve pas que la route existe encore :
        systemd-networkd, à son redémarrage, retire les routes qu'il n'a pas
        posées.  Un relais d'entrée ainsi « oublié » passe dans le tunnel qui
        dépend de lui, et le tunnel se coupe lui-même.  Chaque IP connue est
        donc revérifiée dans la table de routage."""
        added, reposees = [], []
        presentes = None
        for ip in sorted(ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or ip.startswith(("127.", "0.")):
                continue
            connue = ip in self._protected_routes
            if connue:
                if presentes is None:
                    presentes = self._routes_principales()
                if self._orig_iface in presentes.get(f"{ip}/32", ()):
                    continue
            _run("ip", "route", "replace", f"{ip}/32",
                 "via", self._orig_gw, "dev", self._orig_iface)
            self._protected_routes.add(ip)
            (reposees if connue else added).append(ip)
        if reposees:
            self._log(
                f"[route] {len(reposees)} route(s) /32 Tor effacée(s) par un "
                "tiers (redémarrage de systemd-networkd ?) — reposée(s) : "
                f"{', '.join(reposees)}.", "WARN")
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
        return len(reposees)

    @staticmethod
    def _routes_principales() -> dict:
        """Routes IPv4 de la table principale : destination → interfaces.
        Une route d'hôte, qu'ip affiche sans longueur, est notée « /32 ».
        Vide si la table est illisible : tout passe alors pour absent, et
        « ip route replace » ne fait que reposer l'existant."""
        r = _run("ip", "-4", "-o", "route", "show", "table", "main")
        routes = {}
        if r.returncode != 0:
            return routes
        for ligne in r.stdout.decode(errors="ignore").splitlines():
            champs = ligne.split()
            if len(champs) < 3 or "dev" not in champs[:-1]:
                continue
            dest = "0.0.0.0/0" if champs[0] == "default" else champs[0]
            if "/" not in dest:
                dest += "/32"
            routes.setdefault(dest, set()).add(champs[champs.index("dev") + 1])
        return routes

    def _verifier_routage(self) -> list:
        """Repose ce qu'un tiers a retiré pendant que le tunnel est monté, et
        renvoie la liste de ce qui l'a été.

        systemd-networkd, à son (re)démarrage — une mise à jour suffit —,
        retire les routes et les règles de routage qu'il n'a pas posées
        (ManageForeignRoutes=, ManageForeignRoutingPolicyRules=, actifs par
        défaut) : les exclusions partiraient dans le tunnel, et les réponses
        aux connexions entrantes aussi.  Les relais Tor relèvent de
        _protect_tor_routes, appelé AVANT : les deux moitiés d'Internet ne
        doivent jamais revenir avant eux."""
        reposes = []

        def reposer(nom, *cmd):
            r = _run(*cmd)
            if r.returncode == 0:
                reposes.append(nom)
            else:
                self._log(f"[route] {nom} impossible à reposer : "
                          f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")

        routes = self._routes_principales()
        if self._orig_gw:
            for net in self._routes_exclues:
                if self._orig_iface not in routes.get(net, ()):
                    reposer(net, "ip", "route", "replace", net,
                            "via", self._orig_gw, "dev", self._orig_iface)
        tun = self._tun_iface
        for moitie in ("0.0.0.0/1", "128.0.0.0/1"):
            if tun not in routes.get(moitie, ()):
                reposer(moitie, "ip", "route", "replace", moitie,
                        "dev", tun, "scope", "global")
        # « Voulu » et non « actif » : un échec à le reposer le désactive, et
        # il doit être retenté au passage suivant, pas oublié jusqu'au
        # prochain tunnel — une session SSH distante en dépend.
        if (self._retour_voulu
                and not (self._retour_actif and self._retour_en_place())
                and self._retour_entrant_on(self._retour_local)):
            reposes.append("retour des connexions entrantes")
        if reposes:
            self._log("[route] Routage effacé par un tiers (redémarrage de "
                      "systemd-networkd ?) — reposé : " + ", ".join(reposes) + ".",
                      "WARN")
        return reposes

    def _protect_tor_routes(self):
        """Ajoute des routes /32 statiques via la gateway originale pour chaque
        IP de relais Tor actif.  Appel SYNCHRONE depuis le thread stdout
        d'OpenVPN, avant l'installation de redirect-gateway.
        Source primaire : ControlPort (orconn-status) ; repli : ss -tnp.
        Renvoie le nombre de routes reposées (voir _add_protected_routes)."""
        if not self._orig_gw or not self.tor_process:
            return 0

        # Source primaire : le ControlPort (fiable, indépendant du format
        # de sortie de ss).  Repli : inspection des sockets établies.
        ctrl_ips = self._tor_relay_ips()
        if ctrl_ips:
            return self._add_protected_routes(ctrl_ips, "ControlPort")

        pid = self.tor_process.pid
        # Tor abandonne root pour debian-tor : ses sockets sont reconnus à
        # leur propriétaire (« uid: », colonne étendue de ss), visible sans
        # aucun droit.  « pid= » (colonne Process) exige de pouvoir inspecter
        # un processus d'un autre utilisateur, CAP_SYS_PTRACE, que le service
        # n'a plus (v3.11.0) ; il reste valable pour un Tor resté root.
        uid = self._uid_processus(pid)
        try:
            # ss -tnpe state established → colonnes :
            #   Recv-Q Send-Q Local-Address:Port Peer-Address:Port [Process] …
            # On extrait l'adresse pair (relais Tor), colonne d'index 3.
            r = _run("ss", "-tnpe", "state", "established")
            peers = set()
            for line in r.stdout.decode().splitlines():
                champs = line.split()
                if f"pid={pid}," not in line and not (uid and f"uid:{uid}" in champs):
                    continue
                if len(champs) < 4:
                    continue
                peer = champs[3]
                # IPv6 entre crochets ([2001:db8::1]:443) → ignoré (tunnel IPv4).
                if peer.startswith("["):
                    continue
                peers.add(peer.rsplit(":", 1)[0])
            return self._add_protected_routes(peers, "ss")
        except Exception as e:
            self._log(f"[route] {e}", "WARN")
            return 0

    @staticmethod
    def _uid_processus(pid) -> int:
        """Utilisateur effectif d'un processus (0 si inconnu : root ou
        processus disparu).  /proc/<pid>/status est lisible sans droit."""
        try:
            with open(f"/proc/{int(pid)}/status") as f:
                for ligne in f:
                    if ligne.startswith("Uid:"):
                        return int(ligne.split()[2])
        except (OSError, ValueError, IndexError):
            pass
        return 0

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
