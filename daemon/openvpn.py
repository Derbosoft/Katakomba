"""
OpenVPN : un des deux transports (voir session.py pour la boucle, le
failover et le contrôle du circuit).

Depuis la v3.9.0, OpenVPN tourne sans aucun droit : sous l'utilisateur
katakomba-vpn, sur une interface tunnel créée par le daemon, avec
--ifconfig-noexec et --route-noexec.  Il analyse des données reçues du réseau
(TLS, messages du serveur) : une faille, ou un serveur malveillant, ne donne
plus la machine.  Le daemon lit ce que le serveur a poussé et pose lui-même
l'adresse et les routes (NetworkMixin._monter_tunnel).

  - --verb 3 : requis pour que le PUSH_REPLY apparaisse dans la sortie
  - --connect-timeout 60 : évite les faux échecs lors d'un circuit Tor lent
"""

import os
import re
import subprocess
import time

from .core import (
    _run, _deobf, _read_regular, _write_private, AUTH_TMP, OVPN_RUN,
    OPENVPN_PATTERN, SCRIPT_DIR, VPN_USER,
)
from validation import analyser_ovpn, analyser_push, chemin_fournisseur_sur, preparer_copie_ovpn

# Messages d'OpenVPN reconnus à leur forme EXACTE, ancrée en début de ligne
# (horodatage facultatif).  Chercher un mot-clé n'importe où dans la ligne
# laissait le serveur piloter le daemon : le texte d'un message qu'il envoie
# (« AUTH: Received control message: AUTH_FAILED,… ») est recopié tel quel.
_HORODATAGE = r"(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d |\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4} )?"
_PUSH_REPLY = re.compile(rf"^{_HORODATAGE}PUSH: Received control message: '(PUSH_REPLY,.*)'$")
# « With Errors » est suivi d'un renvoi vers la FAQ d'OpenVPN.
_INIT_OK    = re.compile(rf"^{_HORODATAGE}Initialization Sequence Completed( With Errors\b.*)?$")


class OpenVPNMixin:

    def _write_auth_tmp(self, username: str, password: str, uid: int, gid: int):
        # 0400 au nom de katakomba-vpn (v3.12.0) : OpenVPN, qui tourne sous ce
        # compte, le lit ; personne d'autre, groupe compris.  En 0640 groupe
        # katakomba-vpn, OpenVPN signalait à chaque connexion « file … is
        # group or others accessible ».  Le répertoire reste root:katakomba-vpn
        # en 0750 : OpenVPN ne peut ni y créer ni y supprimer de fichier.
        # Création sans suivre de lien symbolique (voir _write_private).
        _write_private(AUTH_TMP, f"{username}\n{password}\n", mode=0o400,
                       dir_mode=0o750, gid=gid, uid=uid)

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
        # Chemin relatif sous providers/, rien d'autre : config.json est
        # modifiable par le groupe, et tout autre chemin ferait lire au
        # daemon, en root, un fichier arbitraire de la machine.
        if not chemin_fournisseur_sur(ovpn):
            self._log(f"[provider] {p.get('name', '?')!r} : chemin du .ovpn "
                      "refusé (hors de providers/<fournisseur>/).", "ERROR")
            return None
        path = SCRIPT_DIR / ovpn
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

    _OVPN_MAX = 1_000_000     # octets ; un .ovpn réel en fait quelques Ko

    def _prepare_ovpn(self, cur_conf: str, gid: int):
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
        # Copie lisible par OpenVPN seul (en plus de root), directives qui
        # exigeraient des droits neutralisées.
        self._ovpn_texte = texte
        try:
            _write_private(OVPN_RUN, preparer_copie_ovpn(texte), mode=0o640,
                           dir_mode=0o750, gid=gid)
        except OSError as e:
            self._log(f"[provider] Copie privée du .ovpn impossible : {e}",
                      "ERROR")
            return None
        return str(OVPN_RUN)

    def _session_openvpn(self, compte, vpn_uid: int, vpn_gid: int) -> str:
        """Une connexion OpenVPN, du .ovpn à la fin du processus.  Renvoie :
          « arret »        arrêt demandé
          « refus »        .ovpn refusé (l'étape entière : ses comptes le partagent)
          « interface »    interface tunnel impossible à créer
          « absent »       openvpn n'est pas installé
          « identifiants » identifiants refusés par le serveur
          « coupure »      tout le reste : connexion impossible, ou tunnel perdu"""
        cur_conf, username, password = compte[0], compte[1], compte[2]
        # Refus = défaut de l'étape entière (tous ses comptes partagent le même
        # .ovpn) : la boucle passe directement à la suivante.
        conf_run = self._prepare_ovpn(cur_conf, vpn_gid)
        if conf_run is None:
            return "refus"
        self._write_auth_tmp(username, password, vpn_uid, vpn_gid)
        if not self._creer_tun(VPN_USER):
            if AUTH_TMP.exists():
                AUTH_TMP.unlink()
            return "interface"

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
            "--verb",              "3",   # requis pour le PUSH_REPLY
            "--ping",              "10",
            "--ping-exit",         "60",
            "--connect-timeout",   "60",  # Tor peut être lent à établir un circuit
            "--connect-retry",     "1",
            "--connect-retry-max", "1",
            "--socks-proxy",       "127.0.0.1", "9050",
            # Sans aucun droit : interface créée par le daemon, qui pose
            # aussi l'adresse et les routes.  Pas de DCO (module noyau,
            # exige des droits ; inutilisable via un proxy de toute façon)
            # ni de hook DNS (le daemon applique le DNS).  dns-updown
            # n'existe qu'à partir d'OpenVPN 2.7 : ignoré par la 2.6.
            "--dev",               self._tun_iface,
            "--dev-type",          "tun",
            "--ifconfig-noexec",
            "--route-noexec",
            "--disable-dco",
            "--ignore-unknown-option", "dns-updown",
            "--dns-updown",        "disable",
        ]

        self._log(f"OpenVPN : {os.path.basename(cur_conf)} via Tor …")
        tunnel_up = False
        self._tunnel_up   = False
        self._auth_failed = False
        self._vpn_dns_ips = []
        try:
            self.openvpn_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                user=vpn_uid, group=vpn_gid, extra_groups=[], cwd="/",
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})

            pousse = []        # options du PUSH_REPLY (éventuellement en plusieurs messages)
            for line in self.openvpn_process.stdout:
                line = line.strip()
                if not line:
                    continue
                low = line.lower()

                m = _PUSH_REPLY.match(line)
                if m:
                    pousse += m.group(1).split(",")[1:]

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
                init = _INIT_OK.match(line)
                if init:
                    if init.group(1):
                        self._log(
                            "OpenVPN signale une erreur d'initialisation "
                            "(route ou interface, voir les lignes "
                            "précédentes) — tunnel monté malgré tout, pris "
                            "en charge normalement.", "WARN")
                    if not tunnel_up:
                        reglages = analyser_push(pousse, self._ovpn_texte)
                        self._vpn_dns_ips = list(reglages["dns"])
                        if not self._monter_tunnel(reglages):
                            self._reconnect_reason = "tunnel impossible à monter"
                            self.openvpn_process.terminate()
                            continue
                        tunnel_up = True
                        self._tunnel_monte()
                    self._log(f"[openvpn] {line}", "WARN" if init.group(1) else "OK")
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
            self._demonter_tunnel()
            self._log("Processus OpenVPN terminé.", "WARN")

        except FileNotFoundError:
            self._log("openvpn introuvable : sudo apt install openvpn", "ERROR")
            return "absent"
        except Exception as e:
            self._log(f"OpenVPN : {e}", "ERROR")
        finally:
            if AUTH_TMP.exists():
                AUTH_TMP.unlink()

        if self._stop_vpn or self._stop_flag:
            return "arret"
        if self._auth_failed:
            self._auth_failed = False
            return "identifiants"
        return "coupure"

