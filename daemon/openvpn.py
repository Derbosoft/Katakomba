"""
OpenVPN : gestion du processus, failover, boucle de reconnexion.

Corrections critiques appliquées :
  - --verb 3  : requis pour que net_addr_v4_add apparaisse dans les logs
  - --connect-timeout 60 : évite les faux échecs lors d'un circuit Tor lent
  - _protect_tor_routes() synchrone à net_addr_v4_add : évite la boucle de routage
  - _apply_dns_split() après "Initialization Sequence Completed" : évite que le
    script up d'OpenVPN écrase la config DNS split appliquée au démarrage
"""

import os
import random
import re
import subprocess
import threading
import time
from pathlib import Path

from .core import (
    _run, _deobf, _read_regular, _write_private, AUTH_TMP, OVPN_RUN,
    OPENVPN_PATTERN, SCRIPT_DIR, RECONNECT_DELAY, RECONNECT_MAX,
    AUTH_COOLDOWN, AUTH_PASS_MAX, AUTH_PASS_DELAY,
)
from validation import analyser_ovpn


class OpenVPNMixin:

    def _write_auth_tmp(self, username: str, password: str):
        # Création directe en 0600, sans suivre de lien symbolique, dans un
        # répertoire réservé à root (voir _write_private).
        _write_private(AUTH_TMP, f"{username}\n{password}\n")

    def _stop_openvpn(self):
        self._stop_vpn = True
        if self.openvpn_process and self.openvpn_process.poll() is None:
            self.openvpn_process.terminate()
            try:
                self.openvpn_process.wait(timeout=5)   # reape, évite le zombie
            except Exception:
                self.openvpn_process.kill()            # SIGTERM ignoré → SIGKILL
                try:
                    self.openvpn_process.wait(timeout=3)
                except Exception:
                    pass
        else:
            # Orphelin d'une session précédente, reconnu à sa ligne de
            # commande — jamais un autre OpenVPN de la machine.
            _run("pkill", "-f", OPENVPN_PATTERN)
        if AUTH_TMP.exists():
            AUTH_TMP.unlink()

    def _get_active_creds(self):
        providers = self.config.get("providers", [])
        if not providers or self._current_provider_idx >= len(providers):
            return None
        p    = providers[self._current_provider_idx]
        ovpn = p.get("ovpn_file", "")
        if not ovpn:
            return None
        path = Path(ovpn)
        if not path.is_absolute():
            path = SCRIPT_DIR / path
        if not path.exists():
            self._log(f"[provider] Fichier .ovpn introuvable : {path}", "ERROR")
            return None
        accounts = p.get("accounts", [])
        if not accounts or self._current_account_idx >= len(accounts):
            return None
        acc = accounts[self._current_account_idx]
        return (
            str(path),
            _deobf(acc.get("u", "")),
            _deobf(acc.get("p", "")),
            p["name"],
            self._current_account_idx,
        )

    def _cooldown_restant(self, account_idx: int) -> float:
        """Secondes de quarantaine restantes pour un compte du fournisseur
        courant, 0 s'il est disponible."""
        fin = self._account_cooldown.get(
            (self._current_provider_idx, account_idx), 0.0)
        return max(0.0, fin - time.time())

    def _mettre_en_quarantaine(self, account_idx: int):
        """Recule un compte refusé en fin d'ordre pour AUTH_COOLDOWN secondes."""
        self._account_cooldown[(self._current_provider_idx, account_idx)] = \
            time.time() + AUTH_COOLDOWN

    def _plan_accounts(self):
        """Fixe l'ordre de passage des comptes du fournisseur courant.

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
        n = len(p.get("accounts", []))
        libres  = [i for i in range(n) if not self._cooldown_restant(i)]
        punis   = [i for i in range(n) if self._cooldown_restant(i)]
        if self.config.get("random_account", True):
            random.shuffle(libres)
            random.shuffle(punis)
        # Les deux groupes concaténés : l'ordre reste une permutation complète,
        # donc « tous les comptes essayés » garde son sens.
        ordre = libres + punis
        if n > 1 and self.config.get("random_account", True):
            self._log(f"[provider] {p.get('name','?')} : ordre des comptes tiré "
                      f"au hasard → {' '.join(str(i+1) for i in ordre)}", "INFO")
        if punis:
            self._log(f"[provider] {p.get('name','?')} : "
                      f"{len(punis)} compte(s) en quarantaine, essayé(s) en "
                      f"dernier → {' '.join(str(i+1) for i in punis)}", "INFO")
        self._account_order = ordre
        self._account_pos   = 0
        # Pas de compte : on laisse l'index à 0, _get_active_creds renverra None
        # et l'appelant passera au fournisseur suivant.
        self._current_account_idx = ordre[0] if ordre else 0

    def _try_failover(self) -> bool:
        providers = self.config.get("providers", [])
        if not providers:
            return False
        cur_p    = providers[self._current_provider_idx]
        accounts = cur_p.get("accounts", [])
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
        if self._current_provider_idx + 1 < len(providers):
            self._current_provider_idx += 1
            next_p = providers[self._current_provider_idx]
            self._log(f"Failover : {cur_p['name']} épuisé → {next_p['name']}", "WARN")
            self._plan_accounts()
            return True
        self._current_provider_idx = 0
        self._log("Failover : tous les fournisseurs et comptes épuisés.", "ERROR")
        self._plan_accounts()
        return False

    def _try_next_provider(self) -> bool:
        """Passe au fournisseur suivant, sur son premier compte.

        À la différence de _try_failover, ne parcourt PAS les comptes restants
        du fournisseur courant : tous partagent le même fichier .ovpn, donc la
        même liste de serveurs.  En changer n'a aucun effet sur une panne côté
        serveur — seul le changement de fournisseur en a."""
        providers = self.config.get("providers", [])
        if self._current_provider_idx + 1 >= len(providers):
            return False
        self._current_provider_idx += 1
        self._log(f"Fournisseur suivant : "
                  f"{providers[self._current_provider_idx]['name']}", "WARN")
        self._plan_accounts()
        return True

    _PUSH_DNS_RE = re.compile(r"dhcp-option\s+DNS\s+(\d{1,3}(?:\.\d{1,3}){3})",
                              re.IGNORECASE)

    _OVPN_MAX = 1_000_000     # octets ; un .ovpn réel en fait quelques Ko

    def _prepare_ovpn(self, cur_conf: str):
        """Valide le .ovpn et en écrit une copie privée pour OpenVPN.

        Renvoie le chemin de la copie, ou None si le fichier est refusé.

        Le groupe katakomba peut écrire les .ovpn, et OpenVPN les lit en root.
        « --script-security 1 » ne suffit pas : « plugin /x.so » charge une
        bibliothèque — donc exécute du code — quel que soit ce niveau
        (vérifié sur OpenVPN 2.7.0).  Le fichier est donc contrôlé par liste
        blanche (validation.py), et OpenVPN reçoit une COPIE de ce qui a été
        contrôlé : le fichier d'origine peut changer entre le contrôle et la
        lecture, la copie non.

        Lecture sans suivre de lien symbolique : un .ovpn remplacé par un
        lien vers /etc/shadow ferait sinon recopier ce fichier, ligne à
        ligne, dans les messages d'erreur d'OpenVPN — donc dans le journal."""
        nom = os.path.basename(cur_conf)
        try:
            texte = _read_regular(cur_conf, self._OVPN_MAX).decode(
                "utf-8", errors="replace")
        except OSError as e:
            self._log(f"[provider] {nom} illisible ({e.strerror or e}) — "
                      "lien symbolique, fichier spécial ou trop volumineux. "
                      "Fournisseur ignoré.", "ERROR")
            return None
        refus, avertissements = analyser_ovpn(texte)
        for m in avertissements:
            self._log(m, "WARN")
        if refus:
            for m in refus:
                self._log(f"[provider] {nom} : {m}", "ERROR")
            self._log(
                f"[provider] {nom} refusé — fournisseur ignoré. Retirez la ou "
                "les lignes signalées : le daemon ne lance jamais OpenVPN, en "
                "root, sur une configuration capable d'exécuter du code ou "
                "d'écrire des fichiers.", "ERROR")
            return None
        try:
            _write_private(OVPN_RUN, texte)
        except OSError as e:
            self._log(f"[provider] Copie privée du .ovpn impossible : {e}",
                      "ERROR")
            return None
        return str(OVPN_RUN)

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
        neuf (NEWNYM) puis on relance OpenVPN — seule action qui change
        réellement les relais.  Borné par circuit_max_retries pour ne jamais
        boucler : au-delà, on garde le circuit tel quel."""
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
        proc = self.openvpn_process
        tun  = self._tun_iface

        def tunnel_intact():
            return (proc is self.openvpn_process and self._tunnel_up
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

    def _wait_vpn_loop_exit(self, timeout: float = 15.0) -> bool:
        """Attend que la boucle OpenVPN en cours se termine (utilisé avant
        d'en relancer une — évite deux boucles/processus concurrents)."""
        for _ in range(int(timeout * 10)):
            with self._vpn_lock:
                if not self._vpn_loop_active:
                    return True
            time.sleep(0.1)
        return False

    def _openvpn_loop(self, start_provider_idx: int = 0, start_account_idx=None):
        # Garde-fou : une seule boucle OpenVPN active à la fois.
        with self._vpn_lock:
            if self._vpn_loop_active:
                self._log("Boucle OpenVPN déjà active — second démarrage ignoré.", "WARN")
                return
            self._vpn_loop_active = True
        try:
            self._openvpn_loop_body(start_provider_idx, start_account_idx)
        finally:
            with self._vpn_lock:
                self._vpn_loop_active = False

    def _openvpn_loop_body(self, start_provider_idx: int, start_account_idx=None):
        self._current_provider_idx = start_provider_idx
        # Tirage de l'ordre des comptes, puis positionnement sur le compte
        # demandé s'il est explicite (reprise après réparation d'urgence).
        self._plan_accounts()
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

        while not self._stop_vpn and not self._stop_flag:
            result = self._get_active_creds()
            if not result:
                # Fournisseur inutilisable (.ovpn manquant, aucun compte) : le
                # défaut touche le fournisseur entier, pas un compte — inutile
                # de parcourir ses autres comptes, on passe au suivant.
                if self._try_next_provider():
                    continue
                self._log("Aucun fournisseur/compte utilisable.", "ERROR")
                break
            cur_conf, username, password, prov_name, acc_idx = result
            self._log(f"Fournisseur : {prov_name}  (compte {acc_idx+1})", "INFO")

            # Refus = défaut du fournisseur entier (tous ses comptes partagent
            # le même .ovpn) : on passe directement au suivant.
            conf_run = self._prepare_ovpn(cur_conf)
            if conf_run is None:
                if self._try_next_provider():
                    continue
                self._log("Aucun fournisseur/compte utilisable.", "ERROR")
                break

            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible — attente (60s max) …", "WARN")
                for _ in range(60):
                    if self._stop_flag or self._stop_vpn:
                        return
                    if self._check_socks_port():
                        break
                    time.sleep(1)
            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible après attente — abandon.", "ERROR")
                break
            self._log("Proxy SOCKS5 127.0.0.1:9050 OK.", "OK")

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

            self._write_auth_tmp(username, password)

            route_args = self._build_route_args()
            cmd = [
                "openvpn",
                "--config",            conf_run,
                "--auth-user-pass",    str(AUTH_TMP),
                # « 1 » IMPOSÉ, et APRÈS --config : c'est la position qui fait
                # la sécurité.  Aucun .ovpn n'a besoin de scripts — le daemon
                # applique le DNS lui-même — et les autoriser permettrait à
                # quiconque peut écrire un .ovpn (le groupe katakomba) de faire
                # exécuter du code par le daemon, EN ROOT.  (Les autres voies
                # — plugin, providers… — sont fermées par _prepare_ovpn.)
                #
                # Se contenter de ne pas passer « --script-security 2 » ne
                # suffisait pas : le fichier peut déclarer la directive
                # lui-même, et OpenVPN la prend.  Vérifié — une config
                # contenant « script-security 2 » + « up … » exécute bien le
                # script ; la même avec « --script-security 1 » placé après
                # --config ne l'exécute pas.  Le niveau 1 laisse passer les
                # exécutables intégrés d'OpenVPN, dont dns-updown.
                "--script-security",   "1",
                "--verb",              "3",   # requis pour net_addr_v4_add
                "--ping",              "10",
                "--ping-exit",         "60",
                "--connect-timeout",   "60",  # Tor peut être lent à établir un circuit
                "--connect-retry",     "1",
                "--connect-retry-max", "1",
                "--socks-proxy",       "127.0.0.1", "9050",
            ]
            cmd += route_args

            self._log(f"OpenVPN : {os.path.basename(cur_conf)} via Tor …")
            tunnel_up = False
            self._tunnel_up   = False
            self._auth_failed = False
            self._vpn_dns_ips = []
            try:
                self.openvpn_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                for line in self.openvpn_process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()

                    if "tun/tap device" in low and "opened" in low:
                        for word in line.split():
                            if word.startswith("tun") and word != "tun/tap":
                                self._tun_iface = word
                                self._log(f"[openvpn] Interface tunnel : {self._tun_iface}", "INFO")
                                break

                    # Synchrone — doit s'exécuter avant que le script up
                    # installe redirect-gateway.
                    elif "net_addr_v4_add" in low:
                        self._protect_tor_routes()

                    # DNS poussés par le serveur (PUSH_REPLY, visible en --verb 3)
                    elif "push" in low and "dhcp-option" in low:
                        found = self._PUSH_DNS_RE.findall(line)
                        if found:
                            self._vpn_dns_ips.extend(found)

                    # Refus des identifiants par le serveur.  Deux signatures
                    # indépendantes, toutes deux observées en production :
                    #   « AUTH: Received control message: AUTH_FAILED »
                    #   « SIGTERM[soft,auth-failure] received, process exiting »
                    # Mémorisé pour que la boucle bascule de compte, au lieu
                    # de s'acharner sur un compte que le serveur refuse.
                    if "auth_failed" in low or "auth-failure" in low:
                        self._auth_failed = True

                    # AVANT le test « error » : OpenVPN écrit « Initialization
                    # Sequence Completed With Errors » quand une route ou
                    # l'interface n'a pu être posée.  Le tunnel est pourtant
                    # monté et le trafic y passe.  Pris pour une erreur, il
                    # n'était jamais déclaré actif : ni DNS du VPN (requêtes
                    # vers le DNS local, hors tunnel), ni blocage IPv6, ni
                    # watchdog.
                    if "initialization sequence completed" in low:
                        if "with errors" in low:
                            self._log(
                                "OpenVPN signale une erreur d'initialisation "
                                "(route ou interface, voir les lignes "
                                "précédentes) — tunnel monté malgré tout, pris "
                                "en charge normalement.", "WARN")
                        if not tunnel_up:
                            # Filet de sécurité si net_addr_v4_add a été manqué.
                            threading.Thread(
                                target=self._protect_tor_routes, daemon=True).start()
                            tunnel_up = True
                            self._tunnel_up      = True
                            self._tunnel_up_time = time.time()
                            self._reconnect_reason = ""
                            self._reconnect_vpn_count = 0
                            # Une connexion réussie clôt la série de refus : le
                            # compteur de passes ne doit pas s'accumuler sur la
                            # durée de vie du daemon.
                            self._auth_passes = 0
                            # Le compte qui vient de réussir n'est évidemment
                            # pas à mettre à l'écart.
                            self._account_cooldown.pop(
                                (self._current_provider_idx,
                                 self._current_account_idx), None)
                            # Nouveau circuit : la mesure du précédent ne le
                            # décrit plus.  Remise à zéro plutôt qu'héritage.
                            self._last_circuit_kbs = 0.0
                            self._last_circuit_at  = 0.0
                            self._log("Tunnel VPN actif.", "OK")
                            # DNS du VPN d'abord (resolvectl sur l'interface),
                            # puis le split DNS (drop-in) qui garde la priorité
                            # sur les domaines exclus.
                            self._apply_vpn_dns()
                            self._apply_dns_split()
                            if self.config.get("block_ipv6"):
                                self._ipv6_block_on()
                            if self.config.get("lan_auto") and self.config.get("lan_iface"):
                                self._setup_lan_sharing()
                            # Contrôle qualité du circuit — en thread : la
                            # mesure ne doit pas bloquer la lecture du flux
                            # stdout d'OpenVPN.
                            threading.Thread(
                                target=self._circuit_quality_check,
                                daemon=True).start()
                        self._log(f"[openvpn] {line}",
                                  "WARN" if "with errors" in low else "OK")
                    elif "error" in low or "failed" in low:
                        self._log(f"[openvpn] {line}", "ERROR")
                    elif "warning" in low:
                        self._log(f"[openvpn] {line}", "WARN")
                    else:
                        self._log(f"[openvpn] {line}")

                if tunnel_up:
                    self._tunnel_down_at = time.time()
                    if not self._reconnect_reason:
                        self._reconnect_reason = "connexion VPN interrompue"
                self._tunnel_up = False
                self._revert_vpn_dns()
                self._log("Processus OpenVPN terminé.", "WARN")

            except FileNotFoundError:
                self._log("openvpn introuvable : sudo apt install openvpn", "ERROR")
                break
            except Exception as e:
                self._log(f"OpenVPN : {e}", "ERROR")
            finally:
                if AUTH_TMP.exists():
                    AUTH_TMP.unlink()

            if self._stop_vpn or self._stop_flag:
                self._ipv6_block_off()
                break

            if not self.config.get("auto_reconnect", True):
                self._ipv6_block_off()
                break

            # Reconnexion demandée pour re-tirer un circuit Tor : on garde le
            # MÊME fournisseur/compte (ce n'est pas un échec d'authentification).
            if self._circuit_retry:
                self._circuit_retry = False
                self._log("Reconnexion sur un circuit Tor neuf …", "WARN")
                time.sleep(2)
                continue

            # ── Décision de reconnexion ──────────────────────────────────────
            # Deux causes de rupture, deux réponses différentes.
            #
            # 1. Le serveur a REFUSÉ les identifiants : le compte est en cause.
            #    Changer de compte est la bonne réponse, et tout de suite —
            #    s'acharner ne servirait à rien.
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
            # 2. Tout le reste (coupure réseau, TLS qui expire, ping-exit) : le
            #    compte n'y est pour rien.  En changer ne changerait d'ailleurs
            #    RIEN au problème, puisque tous les comptes d'un fournisseur
            #    partagent le même .ovpn, donc les mêmes serveurs.  On réessaie
            #    le même compte, après temporisation.  Ce n'est qu'après
            #    RECONNECT_MAX échecs consécutifs qu'on change de fournisseur —
            #    le seul changement qui touche réellement au serveur.
            #
            # Auparavant, toute rupture déclenchait un failover : les dix
            # comptes du premier fournisseur puis ceux du suivant étaient brûlés en une trentaine
            # de secondes, sans que la temporisation n'entre jamais en jeu.
            if self._auth_failed:
                self._auth_failed = False
                self._reconnect_reason = "identifiants refusés, compte suivant"
                self._mettre_en_quarantaine(self._current_account_idx)
                self._log(f"Compte {self._current_account_idx+1} refusé "
                          f"({prov_name}) — mis en quarantaine "
                          f"{AUTH_COOLDOWN//60} min (mot de passe invalide ou "
                          f"connexions simultanées épuisées).", "WARN")
                if self._try_failover():
                    self._log("Compte suivant, reconnexion immédiate …", "WARN")
                    time.sleep(3)
                    continue
                # Plus un seul compte disponible.  Ce n'est pas forcément un
                # problème d'identifiants : tous les comptes peuvent être
                # occupés au même instant.  On tente une seconde passe après
                # temporisation avant de rendre la main à systemd.
                self._auth_passes += 1
                if self._auth_passes < AUTH_PASS_MAX:
                    self._log(
                        f"Aucun compte n'a pu s'authentifier (passe "
                        f"{self._auth_passes}/{AUTH_PASS_MAX}) — nouvelle passe "
                        f"dans {AUTH_PASS_DELAY}s : des comptes sont "
                        f"peut-être simplement occupés.", "WARN")
                    for _ in range(AUTH_PASS_DELAY):
                        if self._stop_flag or self._stop_vpn:
                            return
                        time.sleep(1)
                    self._current_provider_idx = 0
                    self._plan_accounts()
                    continue
                self._log(
                    f"Aucun compte n'a pu s'authentifier après "
                    f"{AUTH_PASS_MAX} passes, chez aucun fournisseur — "
                    "vérifiez les identifiants.", "ERROR")
                break

            self._reconnect_vpn_count += 1
            if self._reconnect_vpn_count > RECONNECT_MAX:
                # Le compte courant ne repart pas après plusieurs essais
                # espacés : la panne est probablement côté serveur.
                if self._try_next_provider():
                    self._reconnect_vpn_count = 0
                    time.sleep(3)
                    continue
                self._log(
                    f"OpenVPN : {RECONNECT_MAX} tentatives échouées et plus "
                    "aucun fournisseur de secours, abandon.", "ERROR")
                break

            self._log(
                f"OpenVPN : reconnexion du même compte dans {RECONNECT_DELAY}s "
                f"({self._reconnect_vpn_count}/{RECONNECT_MAX}) …", "WARN")
            for _ in range(RECONNECT_DELAY):
                if self._stop_flag or self._stop_vpn:
                    return
                time.sleep(1)
