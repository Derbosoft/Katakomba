"""
WireGuard : un des deux transports (voir session.py pour la boucle, le
failover et le contrôle du circuit).

Tor ne transporte que du TCP ; WireGuard ne parle qu'UDP.  Entre les deux,
le pont (pont_wg.py) emballe les paquets de WireGuard dans une connexion
TCP, à la façon que le fournisseur sait déballer (TLS chez Proton, VMess
chez IVPN, udp-over-tcp chez Mullvad), et la fait passer par le proxy
SOCKS de Tor :

  interface WireGuard (noyau) ──UDP──► pont, 127.0.0.1 ──► Tor ──► serveur

Le pont tourne sans aucun droit, sous l'utilisateur dédié : il analyse des
données reçues du réseau.  L'interface WireGuard est créée et configurée
par le daemon ; la clé privée ne passe que par un fichier de /etc/wireguard,
effacé aussitôt lu (le profil AppArmor de wg, sous Ubuntu, ne lui laisse
lire que ce répertoire).

Un « compte » WireGuard est un fichier .conf : une clé, une adresse, un serveur.
Deux .conf d'un même fournisseur visent en général deux serveurs différents :
changer de .conf, c'est aussi changer de serveur.

Le tunnel est déclaré actif à la première poignée de main WireGuard réussie,
et mort quand le pont s'arrête ou que les poignées de main cessent.
"""

import os
import subprocess
import sys
import threading
import time

from .core import (
    _run, _read_regular, _write_private, PONT_ECOUTE, PONT_PATTERN, SCRIPT_DIR,
    WG_CONF_RUN, WG_MTU_DEFAUT,
)
from .gestion_wg import SERVEURS_GERES, service_gere
from validation import analyser_wg, chemin_fournisseur_sur, conf_wg_noyau

# Poignée de main : délai pour la première (circuit Tor neuf, puis TLS ou
# VMess, puis WireGuard), et âge au-delà duquel le tunnel est mort.  WireGuard
# renouvelle ses clés toutes les 2 min et les refuse après 3 : passé 200 s
# sans poignée de main, plus rien ne passe.
POIGNEE_DELAI = 90
POIGNEE_PERIMEE = 200


class WireGuardMixin:

    def _stop_wireguard(self):
        self._stop_vpn = True
        proc = self.pont_process
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)                   # reape, évite le zombie
            except Exception:
                proc.kill()                            # SIGTERM ignoré → SIGKILL
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
        else:
            # Orphelin d'une session précédente, reconnu à sa ligne de
            # commande — jamais un autre programme de la machine.
            _run("pkill", "-f", PONT_PATTERN)

    def _compte_wireguard(self):
        """(chemin du .conf, fournisseur, index) du .conf courant, ou None
        (journalisé quand c'est une erreur de configuration)."""
        providers = self.config.get("providers", [])
        if not providers or self._current_provider_idx >= len(providers):
            return None
        p = providers[self._current_provider_idx]
        if service_gere(p):
            # WireGuard géré : pas de fichier ; le serveur et la session sont
            # préparés par la boucle, Tor prêt (GestionWgMixin).
            if self._current_account_idx >= SERVEURS_GERES:
                return None
            return "", p.get("name", "?"), self._current_account_idx
        confs = p.get("wireguard", [])
        if not confs or self._current_account_idx >= len(confs):
            return None
        conf = confs[self._current_account_idx].get("conf", "")
        if not conf:
            return None
        # Chemin relatif sous providers/, rien d'autre : config.json est
        # modifiable par le groupe, et tout autre chemin ferait lire au
        # daemon, en root, un fichier arbitraire de la machine.
        if not chemin_fournisseur_sur(conf):
            self._log(f"[provider] {p.get('name', '?')!r} : chemin du .conf "
                      "refusé (hors de providers/<fournisseur>/).", "ERROR")
            return None
        path = SCRIPT_DIR / conf
        if not path.exists():
            self._log(f"[provider] Fichier .conf introuvable : {path}", "ERROR")
            return None
        return str(path), p.get("name", "?"), self._current_account_idx

    _WG_MAX = 65536     # octets ; un .conf réel en fait quelques centaines

    def _preparer_wg(self, chemin: str):
        """Lit et contrôle un .conf.  Réglages, ou None s'il est refusé.

        Lecture sans suivre de lien symbolique : un .conf remplacé par un
        lien vers /etc/shadow ferait sinon analyser ce fichier en root."""
        nom = os.path.basename(chemin)
        try:
            texte = _read_regular(chemin, self._WG_MAX).decode("utf-8", errors="replace")
        except OSError as e:
            self._log(f"[provider] {nom} illisible ({e.strerror or e}) — "
                      "lien symbolique, fichier spécial ou trop volumineux.",
                      "ERROR")
            return None
        reglages, refus, avertissements = analyser_wg(texte)
        for m in avertissements:
            self._log(f"[provider] {nom} : {m}", "WARN")
        for m in refus:
            self._log(f"[provider] {nom} : {m}", "ERROR")
        if refus:
            self._log(f"[provider] {nom} refusé.", "ERROR")
        return reglages

    def _configurer_wg(self, reglages: dict) -> str:
        """Interface WireGuard neuve : clés, pair joint par le pont local,
        adresse, levée.  Aucune route : _monter_tunnel les pose après la
        première poignée de main, relais Tor protégés d'abord.

        Renvoie "" si tout est en place, « absent » si WireGuard manque à la
        machine (module noyau, wg), « interface » pour tout autre échec."""
        tun = self._tun_iface
        _run("ip", "link", "del", "dev", tun)
        r = _run("ip", "link", "add", "dev", tun, "type", "wireguard")
        if r.returncode != 0:
            self._log(f"Interface WireGuard {tun} impossible à créer "
                      f"({r.stderr.decode(errors='ignore').strip()}) — module "
                      "noyau wireguard absent ?", "ERROR")
            return "absent"
        try:
            # La clé privée ne fait que passer : fichier 0600 en root, effacé
            # dès que wg l'a lu.
            _write_private(WG_CONF_RUN, conf_wg_noyau(reglages, PONT_ECOUTE))
            r = _run("wg", "setconf", tun, str(WG_CONF_RUN))
            erreur = "" if r.returncode == 0 else "wg setconf a échoué"
            issue = "interface"
        except FileNotFoundError:
            erreur = "wg introuvable : sudo apt install wireguard-tools"
            issue = "absent"
        except OSError as e:
            erreur = f"fichier de configuration impossible à écrire ({e})"
            issue = "interface"
        finally:
            WG_CONF_RUN.unlink(missing_ok=True)
        if erreur:
            # Jamais la sortie de wg : il y recopie une clé qu'il refuse.
            self._log(f"WireGuard : {erreur}.", "ERROR")
            _run("ip", "link", "del", "dev", tun)
            return issue
        mtu = reglages["mtu"] or WG_MTU_DEFAUT
        for cmd in (["ip", "addr", "add", f"{reglages['adresse']}/32", "dev", tun],
                    ["ip", "link", "set", "dev", tun, "mtu", str(mtu)],
                    ["ip", "link", "set", "dev", tun, "up"]):
            r = _run(*cmd)
            if r.returncode != 0:
                self._log(f"WireGuard : « {' '.join(cmd)} » : "
                          f"{r.stderr.decode(errors='ignore').strip()}", "ERROR")
                _run("ip", "link", "del", "dev", tun)
                return "interface"
        return ""

    def _lancer_pont(self, reglages: dict, uid: int, gid: int):
        """Le pont, sans aucun droit.  Ses arguments ne contiennent rien de
        secret (l'identifiant VMess d'IVPN est public, le même pour tous)."""
        cmd = [sys.executable, "-I", str(SCRIPT_DIR / "pont_wg.py"),
               "--emballage", reglages["emballage"],
               "--serveur",   reglages["serveur"],
               "--socks",     "127.0.0.1:9050",
               "--ecoute",    PONT_ECOUTE]
        if reglages["emballage"] == "ivpn":
            cmd += ["--cible", reglages["cible"], "--uuid", reglages["uuid"]]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            user=uid, group=gid, extra_groups=[], cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        threading.Thread(target=self._journal_pont, args=(proc,), daemon=True).start()
        return proc

    def _journal_pont(self, proc):
        for ligne in proc.stdout:
            ligne = ligne.strip()
            # Le pont horodate ses lignes ; le journal du daemon aussi.
            if len(ligne) > 9 and ligne[2] == ":" and ligne[5] == ":" and ligne[8] == " ":
                ligne = ligne[9:]
            if ligne:
                grave = ligne.startswith(("Échec", "Connexion perdue"))
                self._log(f"[pont] {ligne}", "WARN" if grave else "INFO")

    def _poignee_age(self):
        """Secondes depuis la dernière poignée de main WireGuard, None si
        aucune n'a encore réussi."""
        r = _run("wg", "show", self._tun_iface, "latest-handshakes")
        if r.returncode != 0:
            return None
        for ligne in r.stdout.decode(errors="ignore").splitlines():
            champs = ligne.split()
            if len(champs) == 2 and champs[1].isdigit() and int(champs[1]) > 0:
                return max(0.0, time.time() - int(champs[1]))
        return None

    def _tunnel_actif(self, reglages: dict) -> bool:
        """Première poignée de main réussie : routes, DNS, et tout ce qui
        suit un tunnel monté."""
        tunnel = {"refus": [], "ifconfig": (reglages["adresse"], "255.255.255.255"),
                  "topology": "subnet", "tun_mtu": reglages["mtu"] or WG_MTU_DEFAUT,
                  "routes": [], "dns": list(reglages["dns"])}
        if not self._monter_tunnel(tunnel):
            self._reconnect_reason = "tunnel impossible à monter"
            return False
        self._tunnel_monte()
        return True

    def _session_wireguard(self, chemin: str, uid: int, gid: int,
                           reglages=None) -> str:
        """Une connexion, du .conf à la chute du tunnel.  `reglages` : déjà
        lus et contrôlés (WireGuard géré) ; `chemin` n'est alors qu'un nom
        pour le journal.  Renvoie :
          « arret »     arrêt demandé
          « refus »     .conf refusé
          « absent »    WireGuard manque à la machine (module noyau, wg)
          « interface » interface WireGuard impossible à créer
          « echec »     aucune poignée de main (serveur, circuit, clé révoquée)
          « coupure »   tunnel monté, puis perdu"""
        if reglages is None:
            reglages = self._preparer_wg(chemin)
        if reglages is None:
            return "refus"
        self._vpn_dns_ips = list(reglages["dns"])
        issue = self._configurer_wg(reglages)
        if issue:
            return issue
        self._log(f"WireGuard : {os.path.basename(chemin)} "
                  f"({reglages['emballage']}, {reglages['serveur']}) via Tor …")
        self._tunnel_up = False
        try:
            proc = self.pont_process = self._lancer_pont(reglages, uid, gid)
        except OSError as e:
            self._log(f"Pont WireGuard impossible à lancer : {e}", "ERROR")
            _run("ip", "link", "del", "dev", self._tun_iface)
            return "interface"

        def continuer():
            return not (self._stop_vpn or self._stop_flag) and proc.poll() is None

        monte = False
        for _ in range(POIGNEE_DELAI):
            if not continuer():
                break
            if self._poignee_age() is not None:
                monte = self._tunnel_actif(reglages)
                break
            time.sleep(1)
        else:
            self._log(f"WireGuard : aucune poignée de main en {POIGNEE_DELAI} s.", "WARN")
        if monte:
            while continuer():
                time.sleep(2)
                if not continuer():
                    break
                age = self._poignee_age()
                if age is None or age > POIGNEE_PERIMEE:
                    self._log("WireGuard : plus de poignée de main depuis "
                              f"{POIGNEE_PERIMEE} s — tunnel mort.", "WARN")
                    break
            self._tunnel_down_at = time.time()
            if not self._reconnect_reason:
                self._reconnect_reason = "connexion VPN interrompue"
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        self._tunnel_up = False
        self._revert_vpn_dns()
        self._demonter_tunnel()
        if self._stop_vpn or self._stop_flag:
            return "arret"
        self._log("Pont WireGuard arrêté.", "WARN")
        return "coupure" if monte else "echec"
