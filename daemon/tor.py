"""
Gestion du processus Tor : démarrage, arrêt, nouveau circuit (NEWNYM).
"""

import os
import pwd
import re
import shutil
import socket
import stat
import threading
import time

from .core import (
    _run, _ensure_private_dir, _read_regular, _write_private,
    TOR_DATA_DIR, LEGACY_TOR_DATA, TOR_COOKIE, TOR_CTRL_PORT, TORRC_FILE,
    TORRC_RUN, TOR_USER, TOR_PATTERN, STATE_DIR,
    RECONNECT_DELAY, RECONNECT_MAX,
)
from validation import analyser_torrc

# « … [notice] Bootstrapped 45% (loading_descriptors): Loading relay descriptors »
_BOOTSTRAP = re.compile(r"Bootstrapped (\d{1,3})%")


class TorMixin:

    _TORRC_MAX = 100_000      # octets

    # ── Préparation : répertoire de données et torrc ─────────────────────────

    @staticmethod
    def _chown_tree(racine, uid: int, gid: int):
        """chown récursif sans jamais suivre de lien symbolique."""
        for base, dirs, fichiers in os.walk(racine):     # followlinks=False
            for nom in dirs + fichiers:
                os.chown(os.path.join(base, nom), uid, gid, follow_symlinks=False)
        os.chown(racine, uid, gid, follow_symlinks=False)

    def _prepare_tor_data_dir(self):
        """Prépare le DataDirectory ; renvoie l'utilisateur à passer à --User
        (None : Tor reste en root).

        Tor analyse des données reçues du réseau : le faire tourner en root
        donnerait la machine entière à quiconque exploiterait une faille de
        son analyseur.  Il démarre donc en root (le daemon en a besoin pour
        les ports et la lecture du torrc), puis abandonne ses droits au profit
        de debian-tor, utilisateur créé par le paquet tor.  Tor exige alors
        que son DataDirectory appartienne à cet utilisateur.

        Le répertoire quitte /etc/katakomba (inscriptible par le groupe
        katakomba) pour /var/lib/katakomba : l'ancien emplacement est
        déplacé une fois, ce qui conserve les guards Tor déjà choisis."""
        _ensure_private_dir(STATE_DIR, 0o755)
        if not os.path.lexists(TOR_DATA_DIR):
            try:
                st = os.lstat(LEGACY_TOR_DATA)
                # Répertoire réel appartenant à root : ni lien, ni objet
                # déposé par un membre du groupe.
                if stat.S_ISDIR(st.st_mode) and st.st_uid == 0:
                    shutil.move(str(LEGACY_TOR_DATA), str(TOR_DATA_DIR))
                    self._log(f"[tor] Données Tor déplacées : {LEGACY_TOR_DATA}"
                              f" → {TOR_DATA_DIR} (guards conservés).", "INFO")
            except FileNotFoundError:
                pass
            except OSError as e:
                self._log(f"[tor] Migration de {LEGACY_TOR_DATA} impossible "
                          f"({e}) — nouveau répertoire, nouveaux guards.", "WARN")
        try:
            os.mkdir(TOR_DATA_DIR, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(TOR_DATA_DIR)
        if not stat.S_ISDIR(st.st_mode):
            raise PermissionError(f"{TOR_DATA_DIR} n'est pas un répertoire")
        os.chmod(TOR_DATA_DIR, 0o700)
        if os.geteuid() != 0:
            return None                  # lancement de debug hors root
        try:
            pw = pwd.getpwnam(TOR_USER)
        except KeyError:
            self._log(f"[tor] Utilisateur {TOR_USER} absent — Tor reste en "
                      "root. Il est créé par le paquet tor : "
                      "sudo apt install --reinstall tor", "WARN")
            self._chown_tree(TOR_DATA_DIR, 0, 0)
            return None
        try:
            self._chown_tree(TOR_DATA_DIR, pw.pw_uid, pw.pw_gid)
        except OSError as e:
            self._log(f"[tor] Attribution de {TOR_DATA_DIR} à {TOR_USER} "
                      f"impossible ({e}) — Tor reste en root.", "WARN")
            try:
                self._chown_tree(TOR_DATA_DIR, 0, 0)
            except OSError:
                pass
            return None
        return TOR_USER

    # Notices que Tor émet à chaque interrogation du ControlPort par le daemon
    # lui-même (état des circuits, relais à protéger : deux fois toutes les
    # 30 s environ).  Recopiées, elles faisaient ~5 700 lignes par jour et
    # noyaient le reste du journal.
    _TOR_ROUTINE = ("New control connection opened",)

    def _prepare_torrc(self) -> str:
        """Valide le torrc et en écrit une copie privée ; renvoie son chemin.

        Le groupe katakomba écrit le torrc (onglet Tor du GUI), Tor le lit au
        démarrage en root.  « ClientTransportPlugin x exec /chemin » y ferait
        lancer un programme en root : le fichier est donc contrôlé par liste
        blanche (validation.py).  Refusé, il est ignoré en entier et Tor
        démarre avec la configuration de base — un tunnel sans réglages fins
        vaut mieux qu'aucun tunnel.  Comme pour le .ovpn, Tor lit une copie
        de ce qui a été contrôlé, pas le fichier d'origine."""
        texte = ""
        if os.path.lexists(TORRC_FILE):
            try:
                texte = _read_regular(TORRC_FILE, self._TORRC_MAX).decode(
                    "utf-8", errors="replace")
            except OSError as e:
                self._log(f"[tor] torrc illisible ({e.strerror or e}) — "
                          "ignoré, configuration de base.", "ERROR")
            else:
                refus = analyser_torrc(texte)
                if refus:
                    for m in refus:
                        self._log(f"[tor] torrc : {m}", "ERROR")
                    self._log("[tor] torrc refusé — Tor démarre avec la "
                              "configuration de base. Corrigez-le dans "
                              "l'onglet Tor du GUI.", "ERROR")
                    texte = ""
        try:
            _write_private(TORRC_RUN, texte)
        except OSError as e:
            self._log(f"[tor] Copie privée du torrc impossible ({e}) — "
                      "configuration de base.", "ERROR")
            return os.devnull
        return str(TORRC_RUN)

    def _tor_command(self, user) -> list:
        """Paramètres vitaux imposés en ligne de commande, APRÈS le torrc.

        Pour Tor, la ligne de commande remplace les valeurs du fichier
        (vérifié : un torrc déclarant d'autres ControlPort, DataDirectory et
        Log est ignoré sur ces trois points).  Le daemon garantit ainsi les
        ports qu'il utilise, un journal sur stdout — qu'il analyse — et un
        DataDirectory hors de portée du groupe katakomba."""
        cmd = [
            "tor",
            "--torrc-file",           self._prepare_torrc(),
            "--SocksPort",            "9050",
            "--ControlPort",          str(TOR_CTRL_PORT),
            "--CookieAuthentication", "1",
            "--DataDirectory",        str(TOR_DATA_DIR),
            "--Log",                  "notice stdout",
        ]
        if user:
            cmd += ["--User", user]
        return cmd

    # ── Processus ─────────────────────────────────────────────────────────────

    def _start_tor(self):
        if self.tor_process and self.tor_process.poll() is None:
            return
        if not shutil.which("tor"):
            self._log("Tor non installé — lancez : sudo apt install tor", "ERROR")
            return

        # Libérer le port 9050 si le service tor système tourne encore
        try:
            s = socket.socket()
            s.settimeout(1)
            busy = s.connect_ex(("127.0.0.1", 9050)) == 0
            s.close()
        except OSError:
            busy = False
        if busy:
            self._log("[tor] Port 9050 occupé — arrêt service tor système …", "WARN")
            _run("systemctl", "stop", "tor")
            # Seulement un Tor orphelin de ce daemon : « pkill -x tor »
            # couperait aussi le Tor de Tor Browser.
            _run("pkill", "-f", TOR_PATTERN)
            time.sleep(2)

        # Attendre la sortie de l'ancien thread _run_tor AVANT de remettre
        # _stop_tor_flag à False : sinon l'ancien thread, encore dans son
        # attente de reconnexion, repartirait → deux processus Tor.
        if self._tor_thread and self._tor_thread.is_alive():
            self._tor_thread.join(timeout=10)
            if self._tor_thread.is_alive():
                self._log("[tor] Ancien thread Tor toujours actif — "
                          "démarrage annulé.", "ERROR")
                return

        try:
            user = self._prepare_tor_data_dir()
        except OSError as e:
            self._log(f"[tor] Répertoire de données inutilisable : {e}", "ERROR")
            return
        if user is None and self._kill_active:
            # Le blocage laisse passer Tor par son utilisateur, debian-tor.
            # Resté root, Tor serait bloqué, et toute connexion avec lui.
            self._log("[tor] Tor reste en root : le blocage hors tunnel "
                      "l'empêcherait de joindre ses relais — blocage levé.", "ERROR")
            self._kill_switch_off()
        cmd = self._tor_command(user)
        self._tor_ready.clear()
        self._stop_tor_flag = False

        def _run_tor():
            import subprocess
            self._reconnect_tor_count = 0
            while True:
                self._log("Démarrage de Tor …")
                self._tor_bootstrap = 0
                try:
                    self.tor_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    for line in self.tor_process.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        low = line.lower()
                        avance = _BOOTSTRAP.search(line)
                        if avance:
                            self._tor_bootstrap = int(avance.group(1))
                        if "bootstrapped 100%" in low:
                            self._tor_ready.set()
                            self._reconnect_tor_count = 0
                            self._log("[tor] Réseau Tor prêt (100%).", "OK")
                        # Niveaux entre crochets : un simple « err » repérait
                        # aussi « interrupted » ou « overriding ».
                        elif "[err]" in low:
                            self._log(f"[tor] {line}", "ERROR")
                        elif "[warn]" in low:
                            self._log(f"[tor] {line}", "WARN")
                        elif not any(m in line for m in self._TOR_ROUTINE):
                            self._log(f"[tor] {line}")
                    self._tor_ready.clear()
                    self._log("Processus Tor terminé.", "WARN")
                except FileNotFoundError:
                    self._log("tor introuvable.", "ERROR")
                    break
                except Exception as e:
                    self._log(f"Tor : {e}", "ERROR")

                if self._stop_tor_flag or self._stop_flag:
                    break
                if not self.config.get("auto_reconnect", True):
                    break
                self._reconnect_tor_count += 1
                if self._reconnect_tor_count > RECONNECT_MAX:
                    self._log(f"Tor : {RECONNECT_MAX} tentatives échouées.", "ERROR")
                    break
                self._log(
                    f"Tor : reconnexion dans {RECONNECT_DELAY}s "
                    f"({self._reconnect_tor_count}/{RECONNECT_MAX}) …", "WARN")
                for _ in range(RECONNECT_DELAY):
                    if self._stop_flag or self._stop_tor_flag:
                        return
                    time.sleep(1)

        self._tor_thread = threading.Thread(target=_run_tor, daemon=True)
        self._tor_thread.start()


    # ── ControlPort ───────────────────────────────────────────────────────────

    @staticmethod
    def _lire_reponse(s) -> bytes:
        """Lit UNE réponse complète du ControlPort.

        La réponse se termine sur une ligne « NNN » suivie d'une espace
        (« 250 OK », « 552 Unrecognized key »), hors d'un bloc de données
        ouvert par « NNN+ » et refermé par une ligne « . ».

        L'ancienne détection cherchait « \\r\\n5 » dans le tampon : une erreur
        en PREMIÈRE ligne (« 552 … » sans rien avant, cas d'un relais absent
        du consensus) passait inaperçue.  La lecture attendait alors le
        timeout — 8 s, pendant qu'OpenVPN installe ses routes — puis perdait
        toute la liste des relais."""
        buf, pos, donnees = b"", 0, False
        while True:
            fin = buf.find(b"\r\n", pos)
            while fin >= 0:
                ligne, pos = buf[pos:fin], fin + 2
                if donnees:
                    if ligne == b".":
                        donnees = False
                elif len(ligne) >= 4 and ligne[:3].isdigit():
                    if ligne[3:4] == b" ":
                        return buf
                    if ligne[3:4] == b"+":
                        donnees = True
                fin = buf.find(b"\r\n", pos)
            chunk = s.recv(4096)
            if not chunk:
                return buf
            buf += chunk

    @staticmethod
    def _cookie() -> bytes:
        """Cookie du ControlPort, b"" s'il est absent ou suspect.

        Tor tourne sous debian-tor et possède ce fichier : le lire sans
        suivre de lien empêche un Tor compromis de faire envoyer au
        ControlPort — qu'il écoute — le contenu d'un fichier de root."""
        try:
            return _read_regular(TOR_COOKIE, 64)
        except OSError:
            return b""

    def _tor_ctrl(self, *commands, timeout: float = 3.0) -> str:
        """Envoie une ou plusieurs commandes au ControlPort (auth cookie)
        et renvoie la réponse brute.  Lève OSError en cas d'échec réseau."""
        cookie = self._cookie()
        auth = (b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n"
                if cookie else b"AUTHENTICATE\r\n")
        with socket.socket() as s:
            s.settimeout(timeout)
            s.connect(("127.0.0.1", TOR_CTRL_PORT))
            s.sendall(auth)
            if not self._lire_reponse(s).startswith(b"250"):
                raise OSError("authentification ControlPort refusée")
            out = []
            for cmd in commands:
                s.sendall(cmd.encode() + b"\r\n")
                out.append(self._lire_reponse(s).decode(errors="ignore"))
            s.sendall(b"QUIT\r\n")
            return "\n".join(out)

    def _tor_bootstrap_progress(self) -> int:
        """Progression du bootstrap (0-100) via GETINFO, -1 si indisponible."""
        try:
            resp = self._tor_ctrl("GETINFO status/bootstrap-phase")
            for tok in resp.split():
                if tok.startswith("PROGRESS="):
                    return int(tok.split("=", 1)[1])
        except Exception:
            pass
        return -1

    def _tor_relay_ips(self) -> set:
        """IPs IPv4 des relais auxquels Tor est connecté, via le ControlPort
        (orconn-status → ns/id/<fingerprint>).  Ensemble vide en cas d'échec :
        l'appelant peut alors se replier sur l'inspection des sockets (ss)."""
        ips = set()
        try:
            resp = self._tor_ctrl("GETINFO orconn-status", timeout=5.0)
            fps = []
            for line in resp.splitlines():
                line = line.strip()
                # Deux formes : « 250+orconn-status= » puis une ligne par
                # connexion, ou — UNE seule connexion — tout sur une ligne,
                # « 250-orconn-status=$FP~nom CONNECTED ».  Cette seconde
                # forme n'était pas lue : liste vide, repli sur ss.
                if line[:4] in ("250-", "250+") and "=" in line:
                    line = line.split("=", 1)[1].strip()
                if line.startswith("$") and "CONNECTED" in line:
                    fps.append(line[1:].split("~")[0].split("=")[0].split()[0])
            if not fps:
                return ips
            # Toutes les requêtes en UNE seule connexion authentifiée : ouvrir
            # un socket + s'authentifier par relais (jusqu'à 32, toutes les
            # 30 s) surchargeait le ControlPort et provoquait des timeouts.
            ns = self._tor_ctrl(*[f"GETINFO ns/id/${fp}" for fp in fps[:32]],
                                timeout=8.0)
            # Ligne « r … <IP> <ORPort> <DirPort> » : l'IP est le 3e champ en
            # partant de la fin — valable pour les deux formats de consensus
            # (ns : 9 champs avec digest ; microdesc : 8 champs sans digest,
            # le défaut des clients Tor).
            for line in ns.splitlines():
                w = line.strip().split()
                if len(w) >= 8 and w[0] == "r":
                    ips.add(w[-3])
        except Exception as e:
            self._log(f"[tor-ctrl] relais indisponibles via ControlPort : {e}", "WARN")
        return ips

    def _stop_tor(self):
        self._stop_tor_flag = True
        if self.tor_process and self.tor_process.poll() is None:
            self.tor_process.terminate()
            try:
                self.tor_process.wait(timeout=5)   # reape le process, évite le zombie
            except Exception:
                self.tor_process.kill()            # SIGTERM ignoré → SIGKILL
                try:
                    self.tor_process.wait(timeout=3)
                except Exception:
                    pass
            self._tor_ready.clear()
        else:
            # Orphelin de ce daemon uniquement (voir TOR_PATTERN).
            _run("pkill", "-f", TOR_PATTERN)

    def _new_tor_circuit(self):
        """Demande à Tor de ne plus réutiliser ses circuits existants.

        NEWNYM ne modifie PAS le circuit d'une connexion déjà établie : il
        garantit que les PROCHAINES connexions partiront sur un circuit neuf.
        C'est exactement ce qu'il faut avant de relancer OpenVPN — sans lui,
        MaxCircuitDirtiness ferait réutiliser le même circuit, donc les mêmes
        relais lents."""
        try:
            resp = self._tor_ctrl("SIGNAL NEWNYM")
            if "250" in resp:
                self._log("[tor] Nouveau circuit demandé (NEWNYM).", "OK")
            else:
                self._log(
                    f"[tor] NEWNYM : réponse inattendue ({resp.strip()[:40]})",
                    "WARN")
        except Exception as e:
            self._log(f"[tor] NEWNYM : {e}", "WARN")
