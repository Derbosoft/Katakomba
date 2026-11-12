"""
Pare-feu : blocage hors tunnel (kill switch), blocage IPv6, partage LAN.
"""

import functools
import ipaddress
import os
import pwd
import shutil
import subprocess
import threading

from validation import interface_lan_admissible, verifier_dns, verifier_exclusion

from .core import (
    _run,
    KILL_CHAINS, KS6_CHAIN, KS6_FWD_CHAIN, KS_LAN_CHAIN,
    LAN_DNSMASQ_PID, TOR_USER, VPN_CHAINS, VPN_USER,
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


def _exclusif(methode):
    """Une seule opération sur le pare-feu à la fois (voir DaemonCore)."""
    @functools.wraps(methode)
    def enveloppe(self, *args, **kwargs):
        with self._pare_feu:
            return methode(self, *args, **kwargs)
    return enveloppe


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
    # Les chaînes vivent tant que le service n'est pas ARRÊTÉ : posées avant
    # le démarrage de Tor, gardées pendant toutes les reconnexions, les
    # redémarrages du service et ses sorties en échec (v4.7.0 : le script
    # d'ExecStopPost ne les retire qu'à l'arrêt demandé), revérifiées toutes
    # les 30 s (_verifier_blocage).

    def _kill_switch_destinations(self, v6: bool) -> list:
        """Destinations voulues hors tunnel : DNS local (split DNS) et
        exclusions, de la famille d'adresses demandée.  Mêmes contrôles que
        pour les routes : une exclusion refusée là ne doit pas passer ici."""
        entrees = [verifier_dns(self.config.get("local_dns", ""))[0]]
        entrees += [verifier_exclusion(e)[0] for e in self.config.get("excluded_ips", [])]
        nets = []
        for entree in filter(None, entrees):
            net = ipaddress.ip_network(entree, strict=False)
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
        if not forward and tor_uid is not None:
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

    @staticmethod
    def _table(chaines: dict) -> str:
        """Texte pour « iptables-restore --noflush » : chaque chaîne déclarée
        est vidée puis remplie d'un seul tenant, sans jamais exister à moitié
        ni vide.  Reconstruire règle par règle laissait la chaîne ouverte le
        temps de la remplir."""
        lignes = ["*filter"] + [f":{c} - [0:0]" for c in chaines]
        for c, regles in chaines.items():
            lignes += [" ".join(["-A", c, *r]) for r in regles]
        return "\n".join(lignes + ["COMMIT", ""])

    def _poser_chaines(self, tool: str, chaines: dict) -> str:
        """Pose ou remplace ces chaînes ; message d'erreur, vide si posées."""
        r = _run(f"{tool}-restore", "--noflush", "-w", "5",
                 entree=self._table(chaines).encode())
        if r.returncode == 0:
            return ""
        return r.stderr.decode(errors="ignore").strip()[:200] or f"code {r.returncode}"

    @staticmethod
    def _regles_de(tool: str, chain: str):
        """Règles « -A … » de la chaîne, ou None si elle est illisible."""
        r = _run(tool, "-S", chain)
        if r.returncode != 0:
            return None
        return [l.strip() for l in r.stdout.decode(errors="ignore").splitlines()
                if l.startswith("-A ")]

    def _brancher(self, tool: str, parent: str, chain: str):
        """Branche la chaîne en tête de sa chaîne parente : devant toute règle
        qui n'est pas de Katakomba, et une seule fois.  Un autre outil (Docker,
        un pare-feu rechargé) peut insérer ses règles au-dessus, ou vider la
        chaîne parente : ce qu'il accepterait là ne passerait plus par le
        blocage.

        Renvoie None si le branchement échoue, True s'il a fallu brancher ou
        déplacer, False si tout était en place."""
        saut = f"-A {parent} -j {chain}"
        regles = self._regles_de(tool, parent)
        places = [i for i, l in enumerate(regles or []) if l == saut]
        if places and len(places) == 1 and all(
                l.startswith(f"-A {parent} -j KATAKOMBA_") for l in regles[:places[0]]):
            return False
        if _run(tool, "-I", parent, "1", "-j", chain).returncode != 0:
            return None
        # Anciens branchements, du dernier au premier : chaque numéro reste
        # juste (décalé d'un rang par l'insertion en tête).
        for i in reversed(places):
            _run(tool, "-D", parent, str(i + 2))
        return True

    def _kill_refus(self, message: str):
        """Signale un échec de pose — une fois, pas à chaque nouvel essai."""
        if message != self._kill_echec:
            self._kill_echec = message
            self._log(message, "ERROR")

    @_exclusif
    def _kill_switch_on(self) -> bool:
        """Pose le blocage hors tunnel, en tout ou rien : les chaînes d'une
        famille d'adresses sont remplacées d'un seul tenant, puis branchées.
        Une chaîne branchée à moitié pourrait bloquer Tor — et donc toute
        connexion — sans rien protéger de plus.

        Des chaînes gardées d'un lancement précédent (sortie en échec,
        redémarrage du service) restent en place jusqu'à leur remplacement :
        aucun instant sans blocage."""
        if self._kill_active:
            return True
        if not self.config.get("kill_switch", True):
            self._log("Blocage hors tunnel désactivé dans les réglages : pendant "
                      "une reconnexion, le trafic peut sortir à découvert.", "WARN")
            return False
        try:
            tor_uid = pwd.getpwnam(TOR_USER).pw_uid
        except KeyError:
            self._kill_refus(
                f"Blocage hors tunnel INACTIF : utilisateur {TOR_USER} absent, "
                "impossible de laisser passer Tor seul. Il est créé par le "
                "paquet tor : sudo apt install --reinstall tor")
            return False
        par_outil = {}
        for tool, _parent, chain, v6, forward in KILL_CHAINS:
            par_outil.setdefault(tool, {})[chain] = self._kill_switch_rules(
                v6, forward, tor_uid)
        for tool, chaines in par_outil.items():
            erreur = self._poser_chaines(tool, chaines)
            if erreur:
                self._kill_refus(f"Blocage hors tunnel INACTIF : {tool}-restore "
                                 f"refuse les règles ({erreur}).")
                self._kill_switch_off(force=True)
                return False
        for tool, parent, chain, _v6, _fwd in KILL_CHAINS:
            if self._brancher(tool, parent, chain) is None:
                self._kill_refus(f"Blocage hors tunnel INACTIF : branchement de "
                                 f"{chain} sur {parent} impossible.")
                self._kill_switch_off(force=True)
                return False
        self._kill_attendu = {chain: len(regles) for chaines in par_outil.values()
                              for chain, regles in chaines.items()}
        self._kill_active = True
        self._kill_echec = ""
        self._log("Blocage hors tunnel actif : seuls le tunnel, Tor et le réseau "
                  "local peuvent sortir.", "OK")
        return True

    @_exclusif
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
        self._kill_attendu = {}

    def _chaines_intactes(self, chaines, attendu: dict) -> bool:
        """Chaque chaîne (outil, parente, nom) porte le nombre de règles posé."""
        for tool, _parent, chain in chaines:
            regles = self._regles_de(tool, chain)
            if regles is None or len(regles) != attendu.get(chain):
                return False
        return True

    @_exclusif
    def _verifier_blocage(self) -> bool:
        """Revérifie, toutes les 30 s, que le blocage posé l'est encore — et
        en tête.  Sans cela, un outil qui vide ou recharge les règles iptables
        le retirait sans bruit : le statut affichait « actif », et plus rien
        ne bloquait.  Vrai si quelque chose a été reposé."""
        repose = False
        if self.config.get("kill_switch", True) and not self._kill_renonce:
            chaines = [(t, p, c) for t, p, c, _v6, _fwd in KILL_CHAINS]
            if not self._kill_active:
                repose = self._kill_switch_on()       # pose impossible plus tôt
            elif not self._chaines_intactes(chaines, self._kill_attendu):
                self._log("Blocage hors tunnel modifié ou retiré par un autre "
                          "outil (pare-feu rechargé ?) — reposé.", "WARN")
                self._kill_active = False
                repose = self._kill_switch_on()
            else:
                for tool, parent, chain in chaines:
                    etat = self._brancher(tool, parent, chain)
                    if etat:
                        repose = True
                        self._log(f"Blocage hors tunnel : {chain} n'était plus en "
                                  f"tête de {parent} (règles d'un autre outil "
                                  "au-dessus, ou branchement retiré) — remis.", "WARN")
                    elif etat is None:
                        self._kill_refus(f"Blocage hors tunnel : {chain} impossible "
                                         f"à rebrancher sur {parent}.")
        if self._ipv6_blocked:
            chaines = [("ip6tables", "OUTPUT", KS6_CHAIN),
                       ("ip6tables", "FORWARD", KS6_FWD_CHAIN)]
            if not self._chaines_intactes(chaines, self._ks6_attendu):
                self._log("Blocage IPv6 modifié ou retiré par un autre outil — "
                          "reposé.", "WARN")
                self._ipv6_blocked = False
                self._ipv6_block_on()
                repose = True
            else:
                for tool, parent, chain in chaines:
                    if self._brancher(tool, parent, chain):
                        repose = True
        return repose

    # ── Garde du compte katakomba-vpn ─────────────────────────────────────────
    #
    # OpenVPN, le pont WireGuard et les assistants d'API tournent sous ce
    # compte et ne parlent qu'à Tor, en local (127.0.0.1:9050).  Tout ce qu'ils
    # enverraient ailleurs serait une connexion SANS Tor : un .ovpn qui
    # déjouerait --socks-proxy, un programme détourné par le serveur.  Refusé
    # ici, que le blocage hors tunnel soit activé ou non.

    @_exclusif
    def _garde_vpn_on(self):
        try:
            uid = str(pwd.getpwnam(VPN_USER).pw_uid)
        except KeyError:
            return
        regles = [["-o", "lo", "-j", "RETURN"],
                  ["-m", "owner", "--uid-owner", uid, "-p", "tcp",
                   "-j", "REJECT", "--reject-with", "tcp-reset"],
                  ["-m", "owner", "--uid-owner", uid, "-j", "REJECT"]]
        for tool, parent, chain in VPN_CHAINS:
            erreur = self._poser_chaines(tool, {chain: regles})
            if erreur or self._brancher(tool, parent, chain) is None:
                self._log(f"Garde du compte {VPN_USER} ({tool}) impossible à "
                          f"poser{' : ' + erreur if erreur else ''}.", "WARN")
                continue
            self._garde_vpn = True

    @_exclusif
    def _garde_vpn_off(self):
        if not self._garde_vpn:
            return
        for tool, parent, chain in VPN_CHAINS:
            for _ in range(25):
                if _run(tool, "-D", parent, "-j", chain).returncode != 0:
                    break
            _run(tool, "-F", chain)
            _run(tool, "-X", chain)
        self._garde_vpn = False

    # ── Blocage IPv6 ──────────────────────────────────────────────────────────
    #
    # Le tunnel ne porte que l'IPv4.  Tant qu'il est monté, l'IPv6 vers
    # Internet est refusé, par les mêmes règles que le blocage hors tunnel :
    # voisinage et réseau local passent, Tor aussi, et seules les réponses aux
    # connexions entrantes continuent.  Utile quand le blocage hors tunnel est
    # désactivé ; redondant sinon.

    @_exclusif
    def _ipv6_block_on(self):
        if self._ipv6_blocked:
            return
        try:
            tor_uid = pwd.getpwnam(TOR_USER).pw_uid
        except KeyError:
            tor_uid = None
        chaines = {KS6_CHAIN:     self._kill_switch_rules(True, False, tor_uid),
                   KS6_FWD_CHAIN: self._kill_switch_rules(True, True, tor_uid)}
        erreur = self._poser_chaines("ip6tables", chaines)
        if erreur:
            self._log(f"Blocage IPv6 INACTIF : ip6tables-restore refuse les "
                      f"règles ({erreur}).", "ERROR")
            return
        for parent, chain in (("OUTPUT", KS6_CHAIN), ("FORWARD", KS6_FWD_CHAIN)):
            if self._brancher("ip6tables", parent, chain) is None:
                self._log(f"Blocage IPv6 INACTIF : branchement de {chain} sur "
                          f"{parent} impossible.", "ERROR")
                self._ipv6_blocked = True       # pour que le retrait nettoie
                self._ipv6_block_off()
                return
        self._ks6_attendu = {c: len(r) for c, r in chaines.items()}
        self._ipv6_blocked = True
        self._log("IPv6 bloqué hors du réseau local, tant que le tunnel est "
                  "monté.", "OK")

    @_exclusif
    def _ipv6_block_off(self):
        if not self._ipv6_blocked:
            return
        for parent, chain in (("OUTPUT", KS6_CHAIN), ("FORWARD", KS6_FWD_CHAIN)):
            for _ in range(25):
                if _run("ip6tables", "-D", parent, "-j", chain).returncode != 0:
                    break
            _run("ip6tables", "-F", chain)
            _run("ip6tables", "-X", chain)
        self._ipv6_blocked = False
        self._ks6_attendu = {}

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
        # Le GUI ne propose que des cartes admissibles, mais config.json se
        # modifie sans lui : vider les adresses de « lo » couperait Tor,
        # celles de docker0 ou wg0 d'autres services.
        if not interface_lan_admissible(iface) or not self._interface_existe(iface):
            self._log(f"Partage LAN : interface {iface!r} refusée — absente, "
                      "boucle locale ou interface virtuelle.", "ERROR")
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
            # Jamais remis à 0 à l'arrêt, exprès : Docker, libvirt ou un
            # autre VPN démarrés entre-temps comptent dessus sans l'avoir
            # réécrit, et le leur retirer couperait leur réseau en silence.
            # Sans les règles NAT, retirées à l'arrêt, il ne route plus rien
            # d'ici.
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
            self._lan_active  = True
            self._lan_tun     = tun   # mémorisé pour le démontage et la détection
            self._lan_iface   = iface
            self._lan_adresse = f"{gw}/{net.prefixlen}"
            self._log(f"Partage LAN actif : {iface} ({gw}/{net.prefixlen}) → {tun}.", "OK")
            if self.config.get("lan_dhcp", True):
                self._start_lan_dnsmasq(iface, gw, net)
            return True
        except Exception as e:
            self._log(f"Partage LAN : {e}", "ERROR")
            return False

    def _verifier_lan(self) -> bool:
        """Repose l'adresse de la carte de partage LAN si un tiers l'a retirée
        — systemd-networkd, à son démarrage, retire les adresses qu'il n'a pas
        posées sur les cartes qu'il gère.  Sans elle, les clients du LAN
        perdent leur passerelle, en silence.  Vrai si elle a été reposée."""
        if not (self._lan_active and self._lan_iface and self._lan_adresse):
            return False
        r = _run("ip", "-4", "-o", "addr", "show", "dev", self._lan_iface)
        if r.returncode != 0:      # carte débranchée : rien à reposer
            return False
        if self._lan_adresse in r.stdout.decode(errors="ignore").split():
            return False
        r = _run("ip", "addr", "replace", self._lan_adresse, "dev", self._lan_iface)
        if r.returncode != 0:
            self._log(f"Partage LAN : adresse {self._lan_adresse} impossible à "
                      f"reposer sur {self._lan_iface} : "
                      f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")
            return False
        _run("ip", "link", "set", self._lan_iface, "up")
        self._log(f"Partage LAN : adresse {self._lan_adresse} retirée de "
                  f"{self._lan_iface} par un tiers (redémarrage de "
                  "systemd-networkd ?) — reposée.", "WARN")
        return True

    @staticmethod
    def _interface_existe(nom: str) -> bool:
        return os.path.isdir(f"/sys/class/net/{nom}")

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
            self._lan_active  = False
            self._lan_tun     = ""
            self._lan_iface   = ""
            self._lan_adresse = ""
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
        # DNS remis aux clients : celui que le VPN a donné, le même que pour
        # cette machine.  1.1.1.1 seulement s'il n'en a donné aucun : c'était
        # la valeur fixe d'avant la v4.7.0, qui confiait à un tiers les
        # requêtes de tout le réseau partagé.
        dns = next((ip for ip in self._vpn_dns_ips if verifier_dns(ip)[0]), "1.1.1.1")
        cmd = [
            "dnsmasq",
            f"--interface={iface}",
            "--bind-interfaces",
            "--no-daemon",
            f"--dhcp-range={dhcp_start},{dhcp_end},24h",
            f"--dhcp-option=3,{gw}",
            f"--dhcp-option=6,{dns}",
            "--no-resolv",
            # Pas de serveur DNS ici : les clients reçoivent celui du VPN
            # (option 6), joint par le tunnel.  Sans --port=0, dnsmasq
            # écoutait quand même sur le port 53 de l'interface, sans serveur
            # amont à interroger.
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
