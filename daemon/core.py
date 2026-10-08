"""
Daemon core : constantes, helpers, initialisation, run(), handle_signal().
"""

import base64
import copy
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

# ── Imports projet ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from constants import (                                        # noqa: E402
    CONFIG_DIR, CONFIG_FILE, AUTH_TMP, PROVIDERS_DIR, SCRIPT_DIR,
    DEFAULT_CONFIG, TORRC_FILE, VERSION, RUN_DIR, STATE_DIR,
)

# ── Constantes daemon ─────────────────────────────────────────────────────────
# Tout ce que le daemon écrit vit sous RUN_DIR ou STATE_DIR (root seul), jamais
# sous CONFIG_DIR (inscriptible par le groupe katakomba) — voir constants.py.
TOR_DATA_DIR      = STATE_DIR / "tor_data"
LEGACY_TOR_DATA   = CONFIG_DIR / "tor_data"          # avant la v3.7.0
TOR_COOKIE        = TOR_DATA_DIR / "control_auth_cookie"
TORRC_RUN         = RUN_DIR / "torrc"                # copie validée du torrc
OVPN_RUN          = RUN_DIR / "openvpn.conf"         # copie validée du .ovpn
TOR_USER          = "debian-tor"                     # Tor abandonne root
RESOLVED_DROP_IN  = Path("/etc/systemd/resolved.conf.d/katakomba-split.conf")
LAN_DNSMASQ_PID   = RUN_DIR / "dnsmasq.pid"
LEGACY_DNSMASQ_PID = CONFIG_DIR / "tor-vpn-dnsmasq.pid"
TOR_ROUTES_FILE   = STATE_DIR / "tor-routes.txt"

# Processus orphelins d'une session précédente, reconnus à leur ligne de
# commande.  Jamais « pkill -x openvpn » ni « pkill -x tor » : ce serait
# couper un autre VPN de la machine, ou le Tor de Tor Browser.
OPENVPN_PATTERN   = r"^openvpn .*--auth-user-pass [^ ]*katakomba/auth\.tmp"
TOR_PATTERN       = r"^tor .*katakomba/tor(rc|_data)"

# Sortie « aucun fournisseur configuré » : systemd ne relance pas
# (RestartPreventExitStatus), inutile de boucler toutes les 20 s sur une
# erreur de configuration.  78 = EX_CONFIG (sysexits.h).
EXIT_NO_PROVIDER  = 78

KS6_CHAIN         = "KATAKOMBA_KS6"
KS6_FWD_CHAIN     = "KATAKOMBA_KS6_FWD"
KS_LAN_CHAIN      = "KATAKOMBA_LAN_FWD"
# Blocage hors tunnel (kill switch) : (outil, chaîne parente, chaîne, IPv6,
# FORWARD).  Voir FirewallMixin._kill_switch_rules.
KILL_CHAINS = (
    ("iptables",  "OUTPUT",  "KATAKOMBA_KILL",      False, False),
    ("iptables",  "FORWARD", "KATAKOMBA_KILL_FWD",  False, True),
    ("ip6tables", "OUTPUT",  "KATAKOMBA_KILL6",     True,  False),
    ("ip6tables", "FORWARD", "KATAKOMBA_KILL6_FWD", True,  True),
)

TOR_CTRL_PORT     = 9051
RECONNECT_DELAY   = 15
RECONNECT_MAX     = 5
CONN_FAIL_MAX     = 2
# Quarantaine d'un compte après un refus d'authentification.  Ni exclusion ni
# oubli : le compte recule en fin d'ordre pendant ce délai.  Un refus ne dit pas
# si le mot de passe est faux ou si le quota de connexions simultanées est
# atteint — le fournisseur n'envoie qu'un « AUTH_FAILED » nu.  On traite donc le
# cas récupérable : 15 min, l'ordre de grandeur d'une session tierce.
AUTH_COOLDOWN     = 900
# Passes complètes sur des refus avant d'abandonner à systemd.  Une seconde
# passe, après temporisation, couvre le cas « tous les comptes occupés au même
# moment » sans laisser une boucle marteler l'authentification du fournisseur.
AUTH_PASS_MAX     = 2
AUTH_PASS_DELAY   = 60
REPAIR_THRESHOLD  = 3   # full_restarts consécutifs avant réparation d'urgence


# ── Helpers module-level (importables par les autres modules daemon) ───────────

# Délai maximal d'une commande système (ip, iptables, resolvectl, pkill…).
# Sans lui, une commande bloquée — verrou xtables tenu par un autre outil,
# D-Bus qui ne répond plus — gelait le thread appelant.  Dans la boucle de
# surveillance, c'était le daemon entier, jusqu'à ce que le watchdog systemd
# le tue au bout de 90 s.  30 s laisse une marge large aux commandes lentes
# mais saines (« systemctl stop tor »).
RUN_TIMEOUT = 30


def _run(*cmd) -> subprocess.CompletedProcess:
    """Commande système, sortie capturée, jamais bloquante plus de
    RUN_TIMEOUT secondes.  Sur dépassement, le processus est tué et un
    résultat en échec (code 124, comme timeout(1)) est renvoyé : les
    appelants testent déjà le code de retour."""
    argv = list(cmd)
    try:
        return subprocess.run(argv, capture_output=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [WARN ] Commande "
              f"interrompue après {RUN_TIMEOUT} s : {' '.join(argv)[:120]}",
              flush=True)
        return subprocess.CompletedProcess(argv, 124, b"", b"timeout")

def _ensure_private_dir(d: Path, mode: int = 0o700):
    """Crée `d` si besoin et vérifie qu'on peut y écrire en confiance.

    Refuse un lien symbolique, un répertoire d'un autre propriétaire, ou un
    répertoire inscriptible par le groupe ou par tous : dans chacun de ces
    cas, quelqu'un d'autre pourrait y préparer un lien vers un fichier
    système que le daemon écraserait en root."""
    try:
        os.mkdir(d, mode)
    except FileExistsError:
        pass
    st = os.lstat(d)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o022):
        raise PermissionError(
            f"{d} n'est pas un répertoire sûr (lien symbolique, propriétaire "
            "ou droits d'écriture de groupe)")


def _write_private(path: Path, data: str, mode: int = 0o600,
                   dir_mode: int = 0o700):
    """Écrit un fichier neuf, sans jamais suivre un lien symbolique.

    O_EXCL après suppression : le fichier est forcément créé par cet appel,
    avec ses droits définitifs dès la création (aucune fenêtre où il
    existerait avec les droits de l'umask)."""
    _ensure_private_dir(path.parent, dir_mode)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)


def _read_regular(path, limit: int) -> bytes:
    """Lit un fichier ordinaire d'au plus `limit` octets.

    Refuse un lien symbolique (O_NOFOLLOW), un périphérique ou un tube
    (O_NONBLOCK évite de rester bloqué sur un FIFO).  Le daemon lit ainsi en
    root des fichiers que le groupe katakomba choisit : sans ces garde-fous, un
    lien vers /etc/shadow ferait lire — et analyser — ce fichier."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path} n'est pas un fichier ordinaire")
        morceaux, total = [], 0
        while True:
            bloc = os.read(fd, 65536)
            if not bloc:
                break
            total += len(bloc)
            if total > limit:
                raise OSError(f"{path} dépasse {limit} octets")
            morceaux.append(bloc)
        return b"".join(morceaux)
    finally:
        os.close(fd)


def _deobf(s: str) -> str:
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s

def _sd_notify(msg: str):
    """Notification systemd (READY=1, WATCHDOG=1, STOPPING=1) sans dépendance.
    No-op silencieux hors systemd (NOTIFY_SOCKET absent) — le daemon reste
    lançable à la main pour le debug."""
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return
    try:
        if path.startswith("@"):          # socket abstrait
            path = "\0" + path[1:]
        # « with » plutôt qu'un close() en fin de bloc : sur exception, la
        # fermeture ne dépend plus du ramasse-miettes.  Appelé toutes les 3 s.
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(path)
            s.send(msg.encode())
    except Exception:
        pass


# ── DaemonCore ────────────────────────────────────────────────────────────────

class DaemonCore:
    """État partagé et méthodes d'orchestration principale."""

    def __init__(self):
        self.config = self._load_config()

        self.tor_process     = None
        self.openvpn_process = None
        self._tor_thread     = None

        self._tor_ready          = threading.Event()
        self._tor_bootstrap      = 0      # % du dernier « Bootstrapped N% » vu
        self._vpn_lock           = threading.Lock()
        self._vpn_loop_active    = False
        self._stop_flag          = False
        self._stop_vpn           = False
        self._stop_tor_flag      = False
        self._ipv6_blocked       = False
        self._kill_active        = False  # blocage hors tunnel en place
        self._lan_active         = False
        self._lan_tun            = ""    # interface tunnel figée dans les règles LAN
        self._dnsmasq_proc       = None

        self._current_provider_idx = 0
        self._current_account_idx  = 0
        # Ordre de passage des comptes du fournisseur courant : indices de
        # `accounts`, tirés au hasard si config["random_account"].  On garde un
        # ordre explicite plutôt qu'un tirage à chaque essai, sinon « tous les
        # comptes épuisés » n'aurait aucun sens — un tirage indépendant peut
        # redonner dix fois le même compte et ne jamais couvrir la liste.
        self._account_order        = []
        self._account_pos          = 0
        # Comptes ayant récemment essuyé un AUTH_FAILED : (idx_fournisseur,
        # idx_compte) → horodatage de fin de quarantaine.  Un compte en
        # quarantaine passe en FIN d'ordre, il n'est jamais exclu — un refus
        # signifie souvent « quota de connexions simultanées atteint », donc un
        # compte parfaitement valide qui remarchera plus tard.
        self._account_cooldown     = {}
        # Passes complètes (tous fournisseurs, tous comptes) épuisées sur des
        # refus d'authentification.
        self._auth_passes          = 0
        self._reconnect_vpn_count  = 0
        self._reconnect_tor_count  = 0

        self._conn_fail_count      = 0
        self._conn_restart_pending = False
        self._full_restart_count   = 0
        self._inert_ticks          = 0
        # Reprise graduée du watchdog : relance d'OpenVPN seul avant tout
        # redémarrage complet (voir WatchdogMixin._recover).
        self._light_restart_done   = False  # déjà tentée pour cette panne
        self._light_restart_at     = 0.0    # instant de la dernière tentative
        self._light_restart_count  = 0

        self._circuit_attempts = 0      # essais de re-tirage du circuit Tor
        self._circuit_retry    = False  # reconnexion pour circuit (pas un failover)
        self._auth_failed      = False  # dernière rupture = refus d'identifiants

        # Dernière mesure de débit du circuit courant.  0.0 signifie « aucune
        # mesure valide pour ce tunnel » : remis à zéro à chaque tunnel monté,
        # jamais hérité du tunnel précédent (ce serait trompeur).
        self._last_circuit_kbs = 0.0
        self._last_circuit_at  = 0.0

        self._vpn_dns_ips    = []

        self._tun_iface      = "tun0"
        self._tunnel_up      = False
        self._tunnel_up_time = 0.0
        # Tunnel absent : depuis quand, et pourquoi.  Exposé au statut pour
        # que `katakomba doctor` distingue une reconnexion en cours — voulue,
        # quelques secondes — d'une panne.  Raison vide : aucune connue.
        self._tunnel_down_at   = time.time()
        self._reconnect_reason = "démarrage du service"

        self._orig_gw    = None
        self._orig_iface = None

        self._protected_routes: set = set()

        # deque bornée : l'ajout chasse le plus ancien, sans recopier la liste
        # à chaque tick du watchdog (toutes les 3 s).
        self._rx_history = deque([0.0] * 60, maxlen=60)
        self._last_rx    = 0

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        # deepcopy et non dict() : les valeurs par défaut contiennent des
        # listes (providers, excluded_ips…).  Une copie superficielle les
        # partagerait avec DEFAULT_CONFIG, si bien qu'un ajout en place —
        # le GUI fait « providers.append(...) » — muterait la constante du
        # module pour tout le processus.
        defaults = copy.deepcopy(DEFAULT_CONFIG)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    loaded = json.load(f)
                if not isinstance(loaded, dict):
                    raise ValueError("config.json ne contient pas un objet JSON")
                return {**defaults, **loaded}
            except Exception as e:
                # config corrompue : la mettre de côté plutôt que de la perdre,
                # et le signaler dans le journal (sinon démarrage en défauts muet).
                bad = CONFIG_FILE.with_name(CONFIG_FILE.name + ".bad")
                try:
                    CONFIG_FILE.replace(bad)
                    self._log(f"config.json illisible ({e}) — sauvegardé dans {bad}, "
                              "démarrage avec les valeurs par défaut.", "ERROR")
                except Exception:
                    pass
        return defaults

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level:5s}] {msg}", flush=True)

    # ── Signal ────────────────────────────────────────────────────────────────

    def handle_signal(self, signum, _frame):
        _sd_notify("STOPPING=1")
        self._log(f"Signal {signum} reçu — arrêt propre …", "WARN")
        self._stop_flag     = True
        self._stop_vpn      = True
        self._stop_tor_flag = True
        self._stop_openvpn()
        self._stop_tor()
        self._revert_vpn_dns()
        self._cleanup_tor_routes()
        self._teardown_lan_sharing()
        self._ipv6_block_off()
        self._remove_dns_split()
        # En dernier : le service s'arrête, la connexion normale revient.
        self._kill_switch_off()
        self._stop_status_server()
        if AUTH_TMP.exists():
            AUTH_TMP.unlink()
        self._log("Daemon arrêté proprement.", "OK")
        sys.exit(0)

    # ── Nettoyage au démarrage ────────────────────────────────────────────────

    def cleanup_stale_rules(self):
        """Supprime toutes les règles/routes orphelines d'une session précédente."""
        self._log("Nettoyage des règles orphelines …")

        def _purge_jumps(tool, parent, chain, limit=25):
            # Des crashs répétés peuvent empiler plusieurs jumps identiques :
            # on supprime en boucle jusqu'à épuisement (comme repair_network.sh).
            for _ in range(limit):
                if _run(tool, "-D", parent, "-j", chain).returncode != 0:
                    break

        _purge_jumps("ip6tables", "OUTPUT",  KS6_CHAIN)
        _purge_jumps("ip6tables", "FORWARD", KS6_FWD_CHAIN)
        _purge_jumps("iptables",  "FORWARD", KS_LAN_CHAIN)
        for tool, parent, chain, _v6, _fwd in KILL_CHAINS:
            _purge_jumps(tool, parent, chain)
            _run(tool, "-F", chain)
            _run(tool, "-X", chain)
        for args in [
            ("ip6tables", "-F", KS6_CHAIN),
            ("ip6tables", "-X", KS6_CHAIN),
            ("ip6tables", "-F", KS6_FWD_CHAIN),
            ("ip6tables", "-X", KS6_FWD_CHAIN),
            ("iptables",  "-F", KS_LAN_CHAIN),
            ("iptables",  "-X", KS_LAN_CHAIN),
        ]:
            _run(*args)

        lan_subnet = self.config.get("lan_subnet", "")
        if lan_subnet:
            try:
                import ipaddress as _ip
                net = _ip.ip_network(lan_subnet, strict=False)
                for tun in {self._tun_iface, "tun0", "tun1"}:
                    _run("iptables", "-t", "nat", "-D", "POSTROUTING",
                         "-s", str(net), "-o", tun, "-j", "MASQUERADE")
            except Exception:
                pass

        # dnsmasq orphelin du partage LAN : ciblé via son argument --pid-file
        # unique (jamais « pkill dnsmasq » : cela tuerait ceux de libvirt).
        _run("pkill", "-f", str(LAN_DNSMASQ_PID))
        LAN_DNSMASQ_PID.unlink(missing_ok=True)
        # Emplacement d'avant la v3.7.0 : un dnsmasq lancé par l'ancienne
        # version peut encore tourner après la mise à jour.
        _run("pkill", "-f", str(LEGACY_DNSMASQ_PID))

        self._cleanup_tor_routes()
        self._log("Nettoyage terminé.", "OK")

    # ── Démarrage des services ────────────────────────────────────────────────

    def _wait_tor_ready(self, timeout: float) -> bool:
        """Attend le bootstrap Tor : événement posé par le parsing stdout,
        doublé d'un sondage du ControlPort (GETINFO status/bootstrap-phase),
        plus fiable que la seule détection de « Bootstrapped 100% »."""
        deadline  = time.time() + timeout
        last_prog = -1
        while time.time() < deadline and not self._stop_flag:
            # Le bootstrap peut durer plusieurs minutes : on maintient le
            # watchdog systemd pendant cette attente (sinon WatchdogSec
            # tuerait un démarrage parfaitement sain).
            _sd_notify("WATCHDOG=1")
            if self._tor_ready.wait(2):
                return True
            prog = self._tor_bootstrap_progress()
            self._tor_bootstrap = max(self._tor_bootstrap, prog)
            if prog >= 100:
                self._tor_ready.set()
                self._log("[tor-ctrl] Bootstrap 100 % (ControlPort).", "OK")
                return True
            if prog > last_prog >= 0 or (prog >= 0 and last_prog < 0):
                self._log(f"[tor-ctrl] Bootstrap {prog} % …")
            last_prog = max(last_prog, prog)
        return self._tor_ready.is_set()

    def _start_services(self) -> bool:
        self._start_tor()
        self._log("Attente du bootstrap Tor (max 240s) …")
        ready = self._wait_tor_ready(90)
        if not ready and self.tor_process and self.tor_process.poll() is None:
            self._log("Tor encore en bootstrap — attente prolongée (150s) …", "WARN")
            ready = self._wait_tor_ready(150)
        if not ready:
            self._log("Tor n'a pas démarré dans les temps.", "ERROR")
            return False
        threading.Thread(target=self._openvpn_loop, daemon=True).start()
        return True

    # ── Point d'entrée ────────────────────────────────────────────────────────

    def run(self):
        self._log(f"Katakomba daemon v{VERSION} démarré (PID {os.getpid()}).", "OK")
        # READY tout de suite (Type=notify) : le « prêt » systemd signifie
        # « le daemon orchestre », pas « le tunnel est monté ».
        _sd_notify("READY=1")
        if not self.config.get("providers"):
            self._log(
                "Aucun fournisseur configuré.\n"
                "Configurez via :  sudo python3 main.py\n"
                "Puis relancez :   katakomba restart", "ERROR")
            sys.exit(EXIT_NO_PROVIDER)
        try:
            _ensure_private_dir(RUN_DIR)
            _ensure_private_dir(STATE_DIR, 0o755)
        except OSError as e:
            self._log(f"Répertoires de travail inutilisables : {e}", "ERROR")
            sys.exit(1)
        self._check_dns_stack()
        self.cleanup_stale_rules()
        # Avant Tor : rien ne doit sortir à découvert, même pendant le
        # bootstrap ou la première connexion.
        self._kill_switch_on()
        self._start_status_server()
        if not self._start_services():
            sys.exit(1)
        self._monitor_loop()
        self._log("Daemon terminé.")
