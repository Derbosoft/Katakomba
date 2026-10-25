"""
Boucle VPN : fournisseurs, transports, comptes, failover, contrôle du circuit.

Depuis la v4.0.0, un fournisseur peut offrir deux transports :

  wireguard  des fichiers .conf (config « wireguard ») : une clé, une
             adresse, un serveur chacun.  WireGuardMixin.
  openvpn    un .ovpn et des identifiants (config « ovpn_file » et
             « accounts »).  OpenVPNMixin.

Le parcours se fait par ÉTAPES : un fournisseur et l'un de ses transports,
dans l'ordre de config["transports"] (WireGuard d'abord par défaut, OpenVPN
en secours), ou dans celui du fournisseur s'il en a un (v4.1.0).  Dans une étape, les comptes passent dans l'ordre planifié
(_plan_accounts) ; une étape épuisée laisse la place à l'autre transport du
même fournisseur, puis au fournisseur suivant.

Chaque transport fournit deux méthodes : le compte courant
(_compte_openvpn, _compte_wireguard) et une session, du lancement à la
chute du tunnel (_session_openvpn, _session_wireguard).  Une session rend
son issue ; la décision qui suit est prise ici.
"""

import grp
import pwd
import random
import subprocess
import threading
import time

from .core import (
    RECONNECT_DELAY, RECONNECT_MAX, AUTH_COOLDOWN, AUTH_PASS_MAX,
    AUTH_PASS_DELAY, VPN_USER,
)

TRANSPORTS = ("wireguard", "openvpn")
NOMS_TRANSPORT = {"wireguard": "WireGuard", "openvpn": "OpenVPN"}
# Échecs de connexion WireGuard d'affilée (aucune poignée de main) sur un
# même .conf avant de passer au suivant.
ECHECS_PAR_CONF = 2


def ordre_transports(config, fournisseur=None) -> list:
    """Transports à essayer, dans l'ordre : celui du fournisseur s'il en
    impose un (sa clé « transports »), sinon le réglage général.  Une valeur
    illisible est ignorée ; le défaut prend le relais : mieux vaut les deux
    transports qu'aucun."""
    for source in (fournisseur or {}, config):
        voulu = source.get("transports")
        if (isinstance(voulu, list) and voulu
                and all(t in TRANSPORTS for t in voulu)
                and len(set(voulu)) == len(voulu)):
            return list(voulu)
    return list(TRANSPORTS)


def transports_du(fournisseur: dict, ordre) -> list:
    """Transports que ce fournisseur peut servir, dans l'ordre voulu."""
    offerts = {
        "wireguard": bool(fournisseur.get("wireguard")),
        "openvpn":   bool(fournisseur.get("ovpn_file") or fournisseur.get("accounts")),
    }
    return [t for t in ordre if offerts[t]]


class SessionMixin:

    def _utilisateur_vpn(self):
        """(uid, gid) de l'utilisateur sans privilège d'OpenVPN et du pont
        WireGuard, ou None (journalisé)."""
        try:
            return pwd.getpwnam(VPN_USER).pw_uid, grp.getgrnam(VPN_USER).gr_gid
        except KeyError:
            self._log(f"Utilisateur {VPN_USER} absent : OpenVPN et le pont "
                      "WireGuard ne tournent jamais en root et ont besoin de "
                      "lui. Réinstallez Katakomba (sudo apt install --reinstall "
                      "katakomba, ou sudo bash install.sh).", "ERROR")
            return None

    def _stop_vpn_process(self):
        """Arrête le processus VPN, quel que soit le transport en cours."""
        self._stop_openvpn()
        self._stop_wireguard()

    def _processus_vpn(self):
        """Processus qui porte le tunnel de l'étape courante : OpenVPN, ou
        le pont WireGuard."""
        if self._transport == "wireguard":
            return self.pont_process
        return self.openvpn_process

    # ── Étapes : fournisseur et transport ────────────────────────────────────

    def _comptes(self) -> list:
        """Comptes de l'étape courante : identifiants OpenVPN, ou .conf."""
        providers = self.config.get("providers", [])
        if not (0 <= self._current_provider_idx < len(providers)):
            return []
        p = providers[self._current_provider_idx]
        if not self._transport:
            # Étape pas encore fixée (appel avant l'entrée dans la boucle) :
            # le premier transport que ce fournisseur sert.
            offerts = transports_du(p, ordre_transports(self.config, p))
            self._transport = offerts[0] if offerts else ""
        if self._transport == "wireguard":
            return p.get("wireguard", [])
        if self._transport == "openvpn":
            return p.get("accounts", [])
        return []

    def _entrer_fournisseur(self, idx: int, transport=None):
        """Se place sur le fournisseur `idx`, sur `transport` s'il le sert,
        sinon sur son premier transport ; planifie l'ordre des comptes."""
        providers = self.config.get("providers", [])
        self._current_provider_idx = idx
        offerts = (transports_du(providers[idx], ordre_transports(self.config, providers[idx]))
                   if 0 <= idx < len(providers) else [])
        self._transport = (transport if transport in offerts
                           else offerts[0] if offerts else "")
        self._plan_accounts()

    def _etape_suivante(self) -> bool:
        """Passe à l'étape suivante, sur son premier compte : l'autre
        transport du même fournisseur, ou le fournisseur suivant.

        À la différence de _try_failover, ne parcourt PAS les comptes
        restants de l'étape courante.  Sert quand l'étape entière est
        inutilisable (.ovpn refusé, aucun compte), ou quand une panne vient
        du serveur : tous les comptes OpenVPN d'un fournisseur partagent le
        même .ovpn, donc les mêmes serveurs, et en changer n'y ferait rien."""
        providers = self.config.get("providers", [])
        if 0 <= self._current_provider_idx < len(providers):
            p = providers[self._current_provider_idx]
            offerts = transports_du(p, ordre_transports(self.config, p))
            if self._transport in offerts:
                rang = offerts.index(self._transport)
                if rang + 1 < len(offerts):
                    ancien, self._transport = self._transport, offerts[rang + 1]
                    self._log(f"{p.get('name', '?')} : {NOMS_TRANSPORT[ancien]} "
                              f"épuisé → {NOMS_TRANSPORT[self._transport]}", "WARN")
                    self._plan_accounts()
                    return True
        if self._current_provider_idx + 1 >= len(providers):
            return False
        self._entrer_fournisseur(self._current_provider_idx + 1)
        self._log(f"Fournisseur suivant : "
                  f"{providers[self._current_provider_idx]['name']}", "WARN")
        return True

    # ── Comptes : ordre, quarantaine, failover ───────────────────────────────

    def _cle_compte(self, account_idx: int) -> tuple:
        """Clé d'un compte de l'étape courante dans _account_cooldown.  Les
        comptes OpenVPN gardent la forme d'avant la v4.0.0, (fournisseur,
        compte) ; un .conf porte en plus le nom de son transport."""
        if self._transport == "wireguard":
            return (self._current_provider_idx, account_idx, "wireguard")
        return (self._current_provider_idx, account_idx)

    def _cooldown_restant(self, account_idx: int) -> float:
        """Secondes de quarantaine restantes pour un compte de l'étape
        courante, 0 s'il est disponible."""
        fin = self._account_cooldown.get(self._cle_compte(account_idx), 0.0)
        return max(0.0, fin - time.time())

    def _mettre_en_quarantaine(self, account_idx: int):
        """Recule un compte refusé en fin d'ordre pour AUTH_COOLDOWN secondes."""
        self._account_cooldown[self._cle_compte(account_idx)] = \
            time.time() + AUTH_COOLDOWN

    def _plan_accounts(self):
        """Fixe l'ordre de passage des comptes de l'étape courante.

        Tirage au hasard si config["random_account"], sinon ordre de la liste.
        Les comptes en quarantaine sont relégués en FIN d'ordre — jamais
        retirés : un refus d'authentification ne prouve pas qu'un compte est
        mort, le quota de connexions simultanées produit le même message.
        L'ordre est journalisé : sans lui, un incident survenu sur un tirage
        donné serait impossible à reconstituer après coup."""
        providers = self.config.get("providers", [])
        if not (0 <= self._current_provider_idx < len(providers)):
            self._account_order = []
            self._account_pos   = 0
            self._current_account_idx = 0
            return
        p = providers[self._current_provider_idx]
        n = len(self._comptes())
        libres  = [i for i in range(n) if not self._cooldown_restant(i)]
        punis   = [i for i in range(n) if self._cooldown_restant(i)]
        if self.config.get("random_account", True):
            random.shuffle(libres)
            random.shuffle(punis)
        # Les deux groupes concaténés : l'ordre reste une permutation complète,
        # donc « tous les comptes essayés » garde son sens.
        ordre = libres + punis
        quoi = "des .conf" if self._transport == "wireguard" else "des comptes"
        if n > 1 and self.config.get("random_account", True):
            self._log(f"[provider] {p.get('name','?')} : ordre {quoi} tiré "
                      f"au hasard → {' '.join(str(i+1) for i in ordre)}", "INFO")
        if punis:
            self._log(f"[provider] {p.get('name','?')} : "
                      f"{len(punis)} compte(s) en quarantaine, essayé(s) en "
                      f"dernier → {' '.join(str(i+1) for i in punis)}", "INFO")
        self._account_order = ordre
        self._account_pos   = 0
        # Pas de compte : on laisse l'index à 0, le compte courant sera None
        # et l'appelant passera à l'étape suivante.
        self._current_account_idx = ordre[0] if ordre else 0

    def _try_failover(self) -> bool:
        """Compte suivant de l'étape ; à défaut, étape suivante.  Faux quand
        tout est épuisé (on revient alors au premier fournisseur)."""
        providers = self.config.get("providers", [])
        if not providers:
            return False
        cur_p    = providers[self._current_provider_idx]
        accounts = self._comptes()
        # Plan absent ou périmé.  Absent : _try_failover peut être appelé avant
        # l'entrée dans la boucle.  Périmé : le GUI écrit config.json à chaud,
        # donc un fournisseur peut gagner ou perdre des comptes en cours de
        # route et l'ordre ne couvrirait plus la liste réelle.
        if len(self._account_order) != len(accounts):
            self._plan_accounts()
        # On avance dans l'ordre planifié, pas dans l'ordre de la liste : la
        # position dit combien de comptes ont déjà été essayés, ce qui reste
        # vrai que l'ordre soit mélangé ou non.
        if self._account_pos + 1 < len(self._account_order):
            self._account_pos += 1
            self._current_account_idx = self._account_order[self._account_pos]
            self._log(
                f"Failover : compte {self._current_account_idx+1} "
                f"({self._account_pos+1}/{len(accounts)} essayés) "
                f"chez {cur_p['name']}", "WARN")
            return True
        if self._etape_suivante():
            return True
        self._log("Failover : tous les fournisseurs et comptes épuisés.", "ERROR")
        self._entrer_fournisseur(0)
        return False

    def _compte_courant(self):
        if self._transport == "wireguard":
            return self._compte_wireguard()
        if self._transport == "openvpn":
            return self._get_active_creds()
        return None

    # ── Tunnel monté ─────────────────────────────────────────────────────────

    def _tunnel_monte(self):
        """Le tunnel vient d'être monté (adresse et routes posées) : état,
        DNS, IPv6, partage LAN, contrôle du circuit.  Commun aux deux
        transports."""
        self._tunnel_up      = True
        self._tunnel_up_time = time.time()
        self._reconnect_reason = ""
        self._reconnect_vpn_count = 0
        # Une connexion réussie clôt la série de refus : le compteur de passes
        # ne doit pas s'accumuler sur la durée de vie du daemon.
        self._auth_passes = 0
        # Le compte qui vient de réussir n'est évidemment pas à mettre à
        # l'écart.
        self._account_cooldown.pop(self._cle_compte(self._current_account_idx), None)
        # Nouveau circuit : la mesure du précédent ne le décrit plus.  Remise
        # à zéro plutôt qu'héritage.
        self._last_circuit_kbs = 0.0
        self._last_circuit_at  = 0.0
        self._log("Tunnel VPN actif.", "OK")
        # DNS du VPN d'abord (resolvectl sur l'interface), puis le split DNS
        # (drop-in) qui garde la priorité sur les domaines exclus.
        self._apply_vpn_dns()
        self._apply_dns_split()
        if self.config.get("block_ipv6"):
            self._ipv6_block_on()
        if self.config.get("lan_auto") and self.config.get("lan_iface"):
            self._setup_lan_sharing()
        # Contrôle qualité du circuit — en thread : la mesure ne doit pas
        # bloquer la lecture de la sortie d'OpenVPN ni le suivi des poignées
        # de main.
        threading.Thread(target=self._circuit_quality_check, daemon=True).start()

    # ── Contrôle qualité du circuit Tor ──────────────────────────────────────

    _SPEED_URL     = "https://speed.cloudflare.com/__down?bytes={n}"
    # Échauffement : petit et bon marché.  Son rôle est d'ouvrir la fenêtre de
    # contrôle de flux du circuit Tor, pas de mesurer quoi que ce soit.
    _SPEED_WARMUP_BYTES   = 500_000
    _SPEED_WARMUP_TIMEOUT = 15
    # Échantillons : 2 Mo, la taille sur laquelle le seuil circuit_min_kbs est
    # calibré.  NE PAS RÉDUIRE : chaque curl ouvre une connexion TCP neuve, si
    # bien qu'un échantillon court passe l'essentiel de sa vie en slow-start et
    # sous-estime massivement le débit.  Mesuré en conditions réelles, après
    # échauffement, sur le même circuit :
    #     500 Ko →  383 KB/s      2 Mo → 1061 KB/s
    #       1 Mo →  652 KB/s      5 Mo → 1520 KB/s
    # Descendre à 500 Ko diviserait la mesure par ~2,8 et ferait rejeter des
    # circuits sains — exactement le défaut que ce correctif vise à supprimer.
    _SPEED_BYTES   = 2_000_000
    _SPEED_SAMPLES = 2
    _SPEED_TIMEOUT = 30
    _SPEED_WAIT    = 5         # stabilisation du tunnel avant la mesure
    _SPEED_RETRY   = 5         # attente avant la seconde salve
    # Plafond de durée TOTALE du contrôle.  Sans lui, 2 salves × 4 requêtes à
    # 20 s valent 165 s dans le pire cas, contre 40 s pour la version à une
    # seule requête : un circuit pathologique ferait durer le contrôle plus
    # longtemps que la reconnexion qu'il est censé décider.
    _SPEED_BUDGET  = 75

    def _fetch_speed(self, iface: str, nbytes: int, timeout: int) -> float:
        """Une requête : débit descendant en KB/s, -1 si elle n'aboutit pas.

        « --interface » lie la requête au tunnel : si celui-ci tombe pendant
        la mesure, curl échoue au lieu de basculer sur la route par défaut —
        ce qui fausserait le résultat et enverrait la requête hors Tor."""
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}",
               "--max-time", str(timeout)]
        if iface:
            cmd += ["--interface", iface]
        try:
            r = subprocess.run(
                cmd + [self._SPEED_URL.format(n=nbytes)],
                capture_output=True, text=True, timeout=timeout + 10)
            bps = float(r.stdout.strip() or 0)
            return bps / 1024 if bps > 0 else -1.0
        except Exception:
            return -1.0

    def _measure_tunnel_speed(self, iface: str = "", still_valid=None) -> float:
        """Capacité descendante du tunnel en KB/s (-1 si aucune mesure).

        La mesure crée elle-même la demande qu'elle mesure : contrairement à
        une lecture passive des compteurs, un résultat faible signifie bien
        « le lien est lent » et non « rien n'est demandé ».

        Trois choix, tous dictés par des mesures :

        1. UNE REQUÊTE D'ÉCHAUFFEMENT, dont le résultat est jeté.  La première
           requête paie l'ouverture d'un flux TCP/TLS à travers Tor et la
           montée de la fenêtre de congestion.  Relevé sur un circuit vieux de
           9 h : 344 KB/s au premier essai, 985 et 979 aux suivants.  Sans
           échauffement, on mesure le coût d'établissement, pas la capacité.

        2. LE MAXIMUM, pas la moyenne.  La question posée est « ce circuit
           peut-il aller assez vite ? ».  Un bon échantillon prouve la
           capacité ; la contention ne tire les mesures que vers le bas, si
           bien qu'une moyenne pénaliserait un circuit correct momentanément
           gêné.  Sur 344/985/979, la moyenne dirait 769 pour une capacité
           réelle de ~985.

        3. DES ÉCHANTILLONS DE 2 Mo, inchangés.  L'échauffement seul est
           réduit à 500 Ko.  Un échantillon court sous-estime le débit (voir
           le tableau au-dessus de _SPEED_BYTES) et le seuil circuit_min_kbs
           est calibré sur 2 Mo.

        Le plancher de mesure passe de 51 à 67 KB/s (2 Mo en 30 s au lieu de
        40).  C'est le prix du budget de durée ; en dessous, un circuit est de
        toute façon inutilisable pour un tunnel VPN.

        Empreinte réseau : 500 Ko + 2 × 2 Mo = 4,5 Mo par contrôle, contre
        2 Mo auparavant.  Le contrôle n'a lieu qu'une fois par tunnel monté.

        `still_valid` est un prédicat consulté entre les requêtes : la mesure
        en enchaîne désormais plusieurs, elle doit s'interrompre dès que le
        tunnel disparaît au lieu de continuer à sonder une interface morte."""
        fin = time.time() + self._SPEED_BUDGET

        def peut_continuer():
            if still_valid is not None and not still_valid():
                return False
            return time.time() < fin

        for salve in (1, 2):
            if not peut_continuer():
                break
            # Échauffement : résultat volontairement ignoré.
            self._fetch_speed(iface, self._SPEED_WARMUP_BYTES,
                              self._SPEED_WARMUP_TIMEOUT)
            mesures = []
            for _ in range(self._SPEED_SAMPLES):
                if not peut_continuer():
                    break
                kbs = self._fetch_speed(iface, self._SPEED_BYTES,
                                        self._SPEED_TIMEOUT)
                if kbs > 0:
                    mesures.append(kbs)
            if mesures:
                return max(mesures)
            if salve == 1 and peut_continuer():
                # Cas typique : la salve part trop tôt après un NEWNYM, avant
                # que le circuit soit utilisable.  Une seconde tentative, pas
                # une boucle.
                self._log("[circuit] Aucun échantillon exploitable — "
                          "seconde salve …", "WARN")
                time.sleep(self._SPEED_RETRY)
        return -1.0

    def _circuit_quality_check(self):
        """Contrôle qualité UNIQUE, juste après l'établissement du tunnel.

        Le circuit Tor est tiré au sort à la connexion : on vérifie tout de
        suite si le tirage est bon.  S'il est mauvais, on force un circuit
        neuf (NEWNYM) puis on relance OpenVPN ou le pont WireGuard — seule
        action qui change réellement les relais.  Borné par
        circuit_max_retries pour ne jamais boucler : au-delà, on garde le
        circuit tel quel."""
        if not self.config.get("circuit_check", True):
            return
        min_kbs = self.config.get("circuit_min_kbs", 250)
        max_try = self.config.get("circuit_max_retries", 3)
        if min_kbs <= 0:
            return

        time.sleep(self._SPEED_WAIT)
        if not self._tunnel_up or self._stop_vpn or self._stop_flag:
            return

        # Processus et interface capturés AVANT la mesure : celle-ci enchaîne
        # plusieurs requêtes, pendant lesquelles le tunnel peut tomber et être
        # remplacé par un autre.
        proc = self._processus_vpn()
        tun  = self._tun_iface

        def tunnel_intact():
            return (proc is self._processus_vpn() and self._tunnel_up
                    and not self._stop_vpn and not self._stop_flag)

        # Contrôle PENDANT la mesure : inutile de continuer à sonder une
        # interface morte pendant plusieurs requêtes.
        kbs = self._measure_tunnel_speed(tun, still_valid=tunnel_intact)

        # Et contrôle APRÈS : le tunnel peut tomber entre la dernière requête
        # et l'exploitation du résultat.  Sans ce second contrôle, un thread
        # périmé interpréterait le débit d'un tunnel disparu et, pire, tuerait
        # le processus qui a pris sa place.
        if not tunnel_intact():
            self._log("[circuit] Tunnel renouvelé pendant la mesure — "
                      "résultat ignoré.", "WARN")
            return

        if kbs < 0:
            self._log("[circuit] Mesure du débit impossible — "
                      "circuit conservé.", "WARN")
            return
        mbps = kbs * 8 / 1000
        # Mesure conservée pour le socket de statut : elle est prise une seule
        # fois, autant la rendre consultable au lieu de la laisser filer dans
        # le journal.  Aucun trafic supplémentaire n'est généré.
        self._last_circuit_kbs = kbs
        self._last_circuit_at  = time.time()

        if kbs >= min_kbs:
            self._log(f"[circuit] Débit OK : {kbs:.0f} KB/s "
                      f"(~{mbps:.1f} Mbps).", "OK")
            self._circuit_attempts = 0
            return

        if self._circuit_attempts >= max_try:
            self._log(
                f"[circuit] Débit toujours faible ({kbs:.0f} KB/s) après "
                f"{max_try} essais — circuit conservé (mieux vaut un tunnel "
                "lent qu'une boucle de reconnexions).", "WARN")
            return

        self._circuit_attempts += 1
        self._log(
            f"[circuit] Débit faible : {kbs:.0f} KB/s (~{mbps:.1f} Mbps) "
            f"< {min_kbs} KB/s — nouveau tirage de circuit "
            f"({self._circuit_attempts}/{max_try}) …", "WARN")

        # NEWNYM AVANT la reconnexion : sinon MaxCircuitDirtiness ferait
        # réutiliser le même circuit, donc les mêmes relais lents.
        self._new_tor_circuit()
        self._circuit_retry = True
        self._reconnect_reason = "circuit Tor trop lent, nouveau tirage"
        if proc and proc.poll() is None:   # proc : celui qu'on vient de mesurer
            proc.terminate()   # sans _stop_vpn : la boucle reconnecte d'elle-même

    # ── Boucle ───────────────────────────────────────────────────────────────

    def _wait_vpn_loop_exit(self, timeout: float = 15.0) -> bool:
        """Attend que la boucle VPN en cours se termine (utilisé avant d'en
        relancer une — évite deux boucles/processus concurrents)."""
        for _ in range(int(timeout * 10)):
            with self._vpn_lock:
                if not self._vpn_loop_active:
                    return True
            time.sleep(0.1)
        return False

    def _vpn_loop(self, start_provider_idx: int = 0, start_account_idx=None,
                  start_transport=None):
        # Garde-fou : une seule boucle VPN active à la fois.
        with self._vpn_lock:
            if self._vpn_loop_active:
                self._log("Boucle VPN déjà active — second démarrage ignoré.", "WARN")
                return
            self._vpn_loop_active = True
        try:
            self._vpn_loop_body(start_provider_idx, start_account_idx, start_transport)
        finally:
            with self._vpn_lock:
                self._vpn_loop_active = False

    def _attendre(self, secondes: int) -> bool:
        """Attente interrompue par un arrêt ; faux si arrêt demandé."""
        for _ in range(secondes):
            if self._stop_flag or self._stop_vpn:
                return False
            time.sleep(1)
        return True

    def _attendre_tor(self) -> bool:
        """Proxy SOCKS de Tor joignable, au besoin après 60 s d'attente."""
        if not self._check_socks_port():
            self._log("Proxy Tor inaccessible — attente (60s max) …", "WARN")
            for _ in range(60):
                if self._stop_flag or self._stop_vpn:
                    return False
                if self._check_socks_port():
                    break
                time.sleep(1)
        if not self._check_socks_port():
            self._log("Proxy Tor inaccessible après attente — abandon.", "ERROR")
            return False
        self._log("Proxy SOCKS5 127.0.0.1:9050 OK.", "OK")
        return True

    def _noter_passerelle(self):
        self._orig_gw, self._orig_iface = self._get_default_gateway()
        if self._orig_gw:
            self._log(f"Passerelle : {self._orig_gw} via {self._orig_iface}")
        else:
            # Sans passerelle, _protect_tor_routes() ne peut rien faire et
            # sortait en silence : Tor tente alors de joindre ses relais
            # par le tunnel qui dépend d'eux — boucle de routage, tunnel
            # qui tombe, et aucune trace de la cause.  Cas typique : une
            # route par défaut point-à-point (« default dev ppp0 »), sans
            # « via », que _get_default_gateway ne sait pas lire.
            self._log(
                "Passerelle par défaut introuvable — la protection des "
                "routes /32 des guards Tor est DÉSACTIVÉE : risque de "
                "boucle de routage. Vérifiez « ip route show default » "
                "(une route sans « via » n'est pas reconnue).", "ERROR")

    def _nouvelle_passe(self, quoi: str):
        """Toutes les étapes épuisées sur des refus (OpenVPN) ou des
        connexions sans poignée de main (WireGuard).  Ce n'est pas forcément
        un problème de compte : tous peuvent être occupés au même instant, ou
        le circuit Tor mauvais.  Une seconde passe, après temporisation,
        avant de rendre la main à systemd.

        Renvoie True pour continuer, False pour abandonner, None si un arrêt
        est demandé pendant l'attente."""
        self._auth_passes += 1
        if self._auth_passes < AUTH_PASS_MAX:
            self._log(
                f"Aucun compte n'a pu {quoi} (passe "
                f"{self._auth_passes}/{AUTH_PASS_MAX}) — nouvelle passe "
                f"dans {AUTH_PASS_DELAY}s : des comptes sont "
                f"peut-être simplement occupés.", "WARN")
            if not self._attendre(AUTH_PASS_DELAY):
                return None
            self._entrer_fournisseur(0)
            return True
        self._log(
            f"Aucun compte n'a pu {quoi} après {AUTH_PASS_MAX} passes, chez "
            "aucun fournisseur — vérifiez les identifiants, les fichiers .conf "
            "(clé révoquée ?) et Tor.", "ERROR")
        return False

    def _vpn_loop_body(self, start_provider_idx: int = 0, start_account_idx=None,
                       start_transport=None):
        # Tirage de l'ordre des comptes, puis positionnement sur le compte
        # demandé s'il est explicite (reprise après réparation d'urgence).
        self._entrer_fournisseur(start_provider_idx, start_transport)
        # « is not None » et non un test de vérité : 0 est un index de compte
        # valide (le compte 1).  Avec « if start_account_idx », le compte 1
        # n'aurait jamais pu être imposé explicitement.
        if start_account_idx is not None and start_account_idx in self._account_order:
            self._account_pos = self._account_order.index(start_account_idx)
            self._current_account_idx = start_account_idx
        self._reconnect_vpn_count  = 0
        self._stop_vpn             = False
        self._circuit_attempts     = 0
        self._circuit_retry        = False
        echecs = 0          # WireGuard : sans poignée de main, d'affilée, sur ce .conf

        while not self._stop_vpn and not self._stop_flag:
            compte = self._compte_courant()
            if not compte:
                # Étape inutilisable (.ovpn manquant, aucun compte) : le défaut
                # touche l'étape entière, pas un compte — inutile de parcourir
                # ses autres comptes.
                if self._etape_suivante():
                    continue
                self._log("Aucun fournisseur/compte utilisable.", "ERROR")
                break
            transport = self._transport
            prov_name = self.config["providers"][self._current_provider_idx].get("name", "?")
            acc_idx = self._current_account_idx
            if transport == "wireguard":
                self._log(f"Fournisseur : {prov_name}  (WireGuard, .conf "
                          f"{acc_idx+1} : {compte[0].rsplit('/', 1)[-1]})", "INFO")
            else:
                self._log(f"Fournisseur : {prov_name}  (compte {acc_idx+1})", "INFO")

            ids = self._utilisateur_vpn()
            if ids is None:
                self._reconnect_reason = f"utilisateur {VPN_USER} absent"
                break

            if not self._attendre_tor():
                if self._stop_flag or self._stop_vpn:
                    return
                break
            self._noter_passerelle()

            if transport == "wireguard":
                issue = self._session_wireguard(compte[0], *ids)
            else:
                issue = self._session_openvpn(compte, *ids)

            if issue == "arret" or self._stop_vpn or self._stop_flag:
                self._ipv6_block_off()
                break
            if issue == "interface":
                self._reconnect_reason = "interface tunnel impossible à créer"
                break
            if issue == "absent":
                # Programme manquant (openvpn, wg) : l'étape entière est
                # perdue, l'autre transport peut servir.
                if self._etape_suivante():
                    continue
                break
            if issue == "refus":
                if transport == "openvpn":
                    # .ovpn refusé : tous les comptes de l'étape le partagent.
                    if self._etape_suivante():
                        continue
                    self._log("Aucun fournisseur/compte utilisable.", "ERROR")
                    break
                # Un .conf refusé ne concerne que lui : le suivant peut servir.
                self._reconnect_reason = "fichier .conf refusé"
                echecs = 0
                if self._try_failover():
                    continue
                self._log("Aucun .conf utilisable.", "ERROR")
                break

            if not self.config.get("auto_reconnect", True):
                self._ipv6_block_off()
                break

            # Reconnexion demandée pour re-tirer un circuit Tor : on garde le
            # MÊME compte (ce n'est pas un échec d'authentification).
            if self._circuit_retry:
                self._circuit_retry = False
                self._log("Reconnexion sur un circuit Tor neuf …", "WARN")
                time.sleep(2)
                continue

            # ── Décision de reconnexion ──────────────────────────────────────
            # Trois causes de rupture, trois réponses différentes.
            #
            # 1. OpenVPN : le serveur a REFUSÉ les identifiants.  Le compte est
            #    en cause.  Changer de compte est la bonne réponse, et tout de
            #    suite — s'acharner ne servirait à rien.
            #
            #    Mais le refus ne dit PAS pourquoi : le fournisseur envoie un
            #    « AUTH_FAILED » nu, identique pour un mot de passe invalide et
            #    pour un quota de connexions simultanées atteint.  Or les deux
            #    cas s'opposent : le premier est définitif, le second est
            #    temporaire (le compte remarche dès que l'autre session se
            #    termine).  Constaté en production : un compte refusé deux
            #    fois s'est ensuite connecté sans problème une douzaine de
            #    fois.
            #
            #    Réponse : quarantaine, pas exclusion.  Le compte recule en fin
            #    d'ordre pendant AUTH_COOLDOWN, et reste essayé si les autres
            #    échouent aussi.
            #
            # 2. WireGuard : aucune poignée de main.  Circuit Tor lent, serveur
            #    arrêté ou clé révoquée — WireGuard ne dit pas lequel.  Une
            #    seconde chance au même .conf (un autre circuit suffit
            #    souvent), puis le suivant, qui vise en général un autre
            #    serveur.  Le .conf abandonné passe en quarantaine, comme un
            #    compte refusé.
            #
            # 3. Tout le reste (coupure réseau, TLS qui expire, ping-exit,
            #    poignées de main qui cessent) : le compte n'y est pour rien.
            #    On réessaie le même, après temporisation.  Ce n'est qu'après
            #    RECONNECT_MAX échecs consécutifs qu'on change : d'étape pour
            #    OpenVPN (tous ses comptes partagent les mêmes serveurs), de
            #    .conf pour WireGuard (chacun vise en général un autre
            #    serveur).
            #
            # Auparavant, toute rupture déclenchait un failover : les dix
            # comptes du premier fournisseur puis ceux du suivant étaient
            # brûlés en une trentaine de secondes, sans que la temporisation
            # n'entre jamais en jeu.
            if issue == "identifiants":
                self._reconnect_reason = "identifiants refusés, compte suivant"
                self._mettre_en_quarantaine(acc_idx)
                self._log(f"Compte {acc_idx+1} refusé "
                          f"({prov_name}) — mis en quarantaine "
                          f"{AUTH_COOLDOWN//60} min (mot de passe invalide ou "
                          f"connexions simultanées épuisées).", "WARN")
                if self._try_failover():
                    self._log("Compte suivant, reconnexion immédiate …", "WARN")
                    time.sleep(3)
                    continue
                suite = self._nouvelle_passe("s'authentifier")
                if suite is None:
                    return
                if suite:
                    continue
                break

            if issue == "echec":
                echecs += 1
                if echecs < ECHECS_PAR_CONF:
                    self._reconnect_reason = "aucune poignée de main, nouvel essai"
                    self._log(f"WireGuard : nouvel essai du même .conf dans "
                              f"{RECONNECT_DELAY}s ({echecs}/{ECHECS_PAR_CONF}) …", "WARN")
                    if not self._attendre(RECONNECT_DELAY):
                        return
                    continue
                echecs = 0
                self._reconnect_reason = "aucune poignée de main, .conf suivant"
                self._mettre_en_quarantaine(acc_idx)
                self._log(f".conf {acc_idx+1} ({prov_name}) sans poignée de "
                          f"main — mis en quarantaine {AUTH_COOLDOWN//60} min.",
                          "WARN")
                if self._try_failover():
                    time.sleep(3)
                    continue
                suite = self._nouvelle_passe("se connecter")
                if suite is None:
                    return
                if suite:
                    continue
                break

            echecs = 0
            nom = NOMS_TRANSPORT[transport]
            self._reconnect_vpn_count += 1
            if self._reconnect_vpn_count > RECONNECT_MAX:
                # Le compte courant ne repart pas après plusieurs essais
                # espacés : la panne est probablement côté serveur.
                change = (self._etape_suivante() if transport == "openvpn"
                          else self._try_failover())
                if change:
                    self._reconnect_vpn_count = 0
                    time.sleep(3)
                    continue
                self._log(
                    f"{nom} : {RECONNECT_MAX} tentatives échouées et plus "
                    "aucun fournisseur de secours, abandon.", "ERROR")
                break

            quoi = "même .conf" if transport == "wireguard" else "même compte"
            self._log(
                f"{nom} : reconnexion du {quoi} dans {RECONNECT_DELAY}s "
                f"({self._reconnect_vpn_count}/{RECONNECT_MAX}) …", "WARN")
            if not self._attendre(RECONNECT_DELAY):
                return
