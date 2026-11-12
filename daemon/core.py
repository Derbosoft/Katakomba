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
    CONFIG_DIR, CONFIG_FILE, AUTH_TMP,
    DEFAULT_CONFIG, VERSION, RUN_DIR, STATE_DIR,
    TUN_IFACE, TUN_SONDE, VPN_RUN_DIR,
)
# Inutilisés ici : réexportés pour les mixins (« from .core import … »).
from constants import PROVIDERS_DIR, SCRIPT_DIR, TORRC_FILE, VPN_USER  # noqa: E402, F401

# ── Constantes daemon ─────────────────────────────────────────────────────────
# Tout ce que le daemon écrit vit sous RUN_DIR ou STATE_DIR (root seul), jamais
# sous CONFIG_DIR (inscriptible par le groupe katakomba) — voir constants.py.
TOR_DATA_DIR      = STATE_DIR / "tor_data"
LEGACY_TOR_DATA   = CONFIG_DIR / "tor_data"          # avant la v3.7.0
TOR_COOKIE        = TOR_DATA_DIR / "control_auth_cookie"
TORRC_RUN         = RUN_DIR / "torrc"                # copie validée du torrc
OVPN_RUN          = VPN_RUN_DIR / "openvpn.conf"     # copie validée du .ovpn
# Configuration remise à « wg setconf », clé privée comprise : écrite en root,
# 0600, effacée dès que wg l'a lue.  Sous /etc/wireguard parce que le profil
# AppArmor de wg (Ubuntu) ne lui laisse lire que ce répertoire.
WG_CONF_RUN       = Path("/etc/wireguard") / "katakomba-wg.conf"
# Écoute UDP du pont WireGuard, que WireGuard prend pour son serveur.  Port
# peu courant : un WireGuard de la machine écoute souvent sur 51820.
PONT_ECOUTE       = "127.0.0.1:51871"
# Sonde du retour à la première étape (RetourMixin) : une seconde interface et
# un second pont, à côté du tunnel en service, qui n'en voit rien.
PONT_SONDE        = "127.0.0.1:51872"
WG_CONF_SONDE     = Path("/etc/wireguard") / "katakomba-sonde.conf"
# Ports UDP d'écoute des deux interfaces WireGuard (v4.7.0) : fixés, pour que
# chaque pont ne prenne que les paquets de la sienne.
WG_PORT, WG_PORT_SONDE = 51873, 51874
# MTU du tunnel WireGuard quand le .conf n'en donne pas.  Les paquets voyagent
# dans un flux TCP : la taille n'y est pas limitée, mais 1320 reste sûr
# partout (valeur du client tiers pvpn pour Proton Stealth).  Mesuré à travers
# Tor, de 1280 à 1420 : aucun écart de débit au-delà du bruit (v4.4.3).
WG_MTU_DEFAUT     = 1320
TOR_USER          = "debian-tor"                     # Tor abandonne root
RESOLVED_DROP_IN  = Path("/etc/systemd/resolved.conf.d/katakomba-split.conf")
LAN_DNSMASQ_PID   = RUN_DIR / "dnsmasq.pid"
LEGACY_DNSMASQ_PID = CONFIG_DIR / "tor-vpn-dnsmasq.pid"
TOR_ROUTES_FILE   = STATE_DIR / "tor-routes.txt"
# Reprises sans succès de la panne en cours (voir WatchdogMixin._noter_reprise) :
# gardées pour le daemon que systemd relance après la réparation d'urgence.
REPRISES_FILE     = STATE_DIR / "reprises.json"
REPRISES_MEMOIRE  = 900   # s : au-delà, une ancienne panne ne compte plus

# Processus orphelins d'une session précédente, reconnus à leur ligne de
# commande.  Jamais « pkill -x openvpn » ni « pkill -x tor » : ce serait
# couper un autre VPN de la machine, ou le Tor de Tor Browser.
OPENVPN_PATTERN   = r"^openvpn .*--auth-user-pass [^ ]*katakomba(-vpn)?/auth\.tmp"
PONT_PATTERN      = r"pont_wg\.py .*--ecoute 127\.0\.0\.1:51871"
PONT_SONDE_PATTERN = r"pont_wg\.py .*--ecoute 127\.0\.0\.1:51872"
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

# Garde du compte katakomba-vpn (v4.7.0) : (outil, chaîne parente, chaîne).
# Voir FirewallMixin._garde_vpn_on.
VPN_CHAINS = (
    ("iptables",  "OUTPUT", "KATAKOMBA_VPN"),
    ("ip6tables", "OUTPUT", "KATAKOMBA_VPN6"),
)

# Retour des connexions entrantes (v3.10.0) : une connexion arrivée par la
# carte réseau (SSH, serveur web…) repart par elle, jamais par le tunnel.
# Voir NetworkMixin._retour_entrant_on.  Un seul bit de marque, laissé libre
# par Docker, kube-proxy et les pare-feu courants.
RETOUR_MARQUE     = "0x1000000/0x1000000"
RETOUR_TABLE      = "19265"
RETOUR_PRIORITES  = ("30300", "30301")
# Tor hors du tunnel (v4.4.2).  Voir NetworkMixin._tor_hors_tunnel_on.
TOR_PRIORITES     = ("30302", "30303")
RETOUR_CHAINES    = (("PREROUTING", "KATAKOMBA_RETOUR"),
                     ("OUTPUT",     "KATAKOMBA_RETOUR_OUT"))
SRC_VALID_MARK    = Path("/proc/sys/net/ipv4/conf/all/src_valid_mark")

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


def _run(*cmd, entree=None) -> subprocess.CompletedProcess:
    """Commande système, sortie capturée, jamais bloquante plus de
    RUN_TIMEOUT secondes.  Sur dépassement, le processus est tué et un
    résultat en échec (code 124, comme timeout(1)) est renvoyé : les
    appelants testent déjà le code de retour.  entree : octets remis à
    l'entrée standard (iptables-restore)."""
    argv = list(cmd)
    try:
        return subprocess.run(argv, capture_output=True, timeout=RUN_TIMEOUT,
                              input=entree)
    except subprocess.TimeoutExpired:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [WARN ] Commande "
              f"interrompue après {RUN_TIMEOUT} s : {' '.join(argv)[:120]}",
              flush=True)
        return subprocess.CompletedProcess(argv, 124, b"", b"timeout")

def _ensure_private_dir(d: Path, mode: int = 0o700, gid=None):
    """Crée `d` si besoin et vérifie qu'on peut y écrire en confiance.

    Refuse un lien symbolique, un répertoire d'un autre propriétaire, ou un
    répertoire inscriptible par le groupe ou par tous : dans chacun de ces
    cas, quelqu'un d'autre pourrait y préparer un lien vers un fichier
    système que le daemon écraserait en root.

    gid : groupe autorisé à LIRE le répertoire (OpenVPN, sans privilège)."""
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
    if gid is not None and (st.st_gid != gid or stat.S_IMODE(st.st_mode) != mode):
        os.chown(d, -1, gid, follow_symlinks=False)
        os.chmod(d, mode)


def _write_private(path: Path, data: str, mode: int = 0o600,
                   dir_mode: int = 0o700, gid=None, uid=None):
    """Écrit un fichier neuf, sans jamais suivre un lien symbolique.

    O_EXCL après suppression : le fichier est forcément créé par cet appel,
    avec ses droits définitifs dès la création (aucune fenêtre où il
    existerait avec les droits de l'umask).  gid : groupe du répertoire (et
    du fichier), autorisé à le traverser.  uid : propriétaire du fichier.
    Les deux sont posés avant la moindre écriture."""
    _ensure_private_dir(path.parent, dir_mode, gid)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode)
    if gid is not None or uid is not None:
        os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
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
        self.pont_process    = None       # pont WireGuard → Tor
        self._pont_pret      = threading.Event()   # il écoute
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
        # Pose, retrait et vérification du pare-feu ne se croisent pas : la
        # surveillance (toutes les 30 s) reposerait sinon une chaîne que la
        # boucle VPN est en train de retirer.  Réentrant : la vérification
        # appelle la pose, et l'arrêt (signal) peut l'interrompre.
        self._pare_feu           = threading.RLock()
        self._kill_attendu       = {}     # chaîne → nombre de règles posées
        self._kill_echec         = ""     # dernier échec signalé (pas de redite)
        self._kill_renonce       = False  # levé exprès : Tor resté en root
        self._ks6_attendu        = {}     # idem, blocage IPv6
        self._garde_vpn          = False  # garde du compte katakomba-vpn posée
        self._ip_forward_avant   = None   # valeur d'origine, rendue à l'arrêt
        self._lan_active         = False
        self._lan_tun            = ""    # interface tunnel figée dans les règles LAN
        self._lan_iface          = ""    # carte et adresse posées, revérifiées
        self._lan_adresse        = ""    # par le watchdog (_verifier_lan)
        self._dnsmasq_proc       = None

        self._current_provider_idx = 0
        # Transport de l'étape en cours chez ce fournisseur : « wireguard » ou
        # « openvpn » (voir SessionMixin) ; vide si le fournisseur n'en a
        # aucun d'utilisable.
        self._transport            = ""
        self._current_account_idx  = 0
        # WireGuard géré (GestionWgMixin) : place de ce PC par service (en
        # mémoire, pour le statut), serveurs de l'étape, dernier serveur
        # utilisé, dernier code de l'API, pause des appels après un échec
        # (par service), clé reposée une fois par série d'échecs, ménage fait
        # au démarrage.
        self._wg_etats             = {}
        self._wg_hotes             = []
        self._wg_dernier           = ""
        self._wg_liste_douteuse    = False
        self._wg_code              = 0
        self._wg_cause             = ""     # code de raison pour le statut
        self._wg_verrou            = threading.Lock()   # boucle VPN et sonde
        self._wg_pauses            = {}
        self._wg_resynchro         = False
        self._wg_menage_fait       = False
        # Secours et retour à la première étape (RetourMixin) : première cause
        # d'un départ de l'étape 1, depuis quand on tourne plus bas, prochaine
        # sonde, sonde en cours, retour décidé par la sonde.
        self._cause_etape          = ""
        self._secours_depuis       = 0.0
        self._retour_prochain      = 0.0
        self._retour_en_cours      = False
        self._retour_vers          = None
        # Ordre de passage des comptes de l'étape courante : indices de
        # `accounts` (OpenVPN) ou de `wireguard`, tirés au hasard si
        # config["random_account"].  On garde un
        # ordre explicite plutôt qu'un tirage à chaque essai, sinon « tous les
        # comptes épuisés » n'aurait aucun sens — un tirage indépendant peut
        # redonner dix fois le même compte et ne jamais couvrir la liste.
        self._account_order        = []
        self._account_pos          = 0
        # Comptes ayant récemment essuyé un AUTH_FAILED (OpenVPN) ou sans
        # poignée de main (WireGuard) : clé de SessionMixin._cle_compte →
        # horodatage de fin de quarantaine.  Un compte en
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
        # Reprise graduée du watchdog : relance d'OpenVPN (ou du pont
        # WireGuard) seul avant tout redémarrage complet (voir
        # WatchdogMixin._recover).
        self._light_restart_done   = False  # déjà tentée pour cette panne
        self._light_restart_at     = 0.0    # instant de la dernière tentative
        self._light_restart_count  = 0
        # Reprises (légères ou complètes) depuis la dernière connectivité
        # VÉRIFIÉE, et instant avant lequel la suivante attend : chaque
        # reprise ouvre une session chez le fournisseur, qui limite les
        # connexions simultanées.  Voir WatchdogMixin._noter_reprise.
        self._reprises_sans_succes = 0
        self._reprise_pas_avant    = 0.0
        self._reprise_annoncee     = 0.0    # délai déjà signalé au journal

        self._circuit_attempts = 0      # essais de re-tirage du circuit Tor
        self._circuit_retry    = False  # reconnexion pour circuit (pas un failover)
        # Contrôle conclu (débit OK, mesure impossible ou plafond atteint) :
        # pas de nouvelle mesure avant le prochain démarrage du daemon.
        self._circuit_controle_fait = False
        self._circuit_conclu_at     = 0.0   # quand le dernier contrôle a conclu
        # Mesure en cours : elle sature le circuit, la surveillance ne la
        # prend pas pour une panne.
        self._mesure_en_cours  = False
        self._auth_failed      = False  # dernière rupture = refus d'identifiants

        # Dernière mesure de débit du circuit courant.  0.0 signifie « aucune
        # mesure valide pour ce tunnel » : remis à zéro à chaque tunnel monté,
        # jamais hérité du tunnel précédent (ce serait trompeur).
        self._last_circuit_kbs = 0.0
        self._last_circuit_at  = 0.0
        self._circuit_mesure_passee = False   # mesure d'un circuit précédent

        self._vpn_dns_ips    = []

        self._tun_iface      = TUN_IFACE
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
        self._routes_exclues = []      # posées par _monter_tunnel
        self._retour_actif   = False   # retour des connexions entrantes
        self._retour_local   = ""      # adresse du tunnel, pour le reposer
        self._retour_voulu   = False   # posé une fois pour ce tunnel : à tenir
        self._tor_hors_tunnel = False  # règles par utilisateur de Tor posées
        self._src_valid_mark = None    # valeur d'origine, rendue à l'arrêt
        self._ovpn_texte     = ""      # .ovpn validé (topologie, MTU)

        # deque bornée : l'ajout chasse le plus ancien, sans recopier la liste
        # à chaque tick du watchdog (toutes les 3 s).
        self._rx_history = deque([0.0] * 60, maxlen=60)
        self._last_rx    = 0
        self._last_tx    = 0
        # Ticks consécutifs où le tunnel émet sans rien recevoir : canal de
        # données mort, reconnu sans attendre la fin du délai de grâce.
        self._tx_sans_rx = 0

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
                return self._typer_config({**defaults, **loaded})
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

    def _typer_config(self, cfg: dict) -> dict:
        """Écarte de config.json ce qui n'a pas la forme attendue.  Le
        fichier est inscriptible par le groupe et s'édite à la main : un
        fournisseur qui n'est pas un objet, un nombre écrit entre guillemets,
        faisaient mourir la boucle VPN sur une exception, puis redémarrer le
        service sans fin.  Les messages nomment la clé, jamais la valeur."""
        for cle, defaut in DEFAULT_CONFIG.items():
            if defaut is None:
                continue
            v = cfg.get(cle)
            if isinstance(defaut, bool):
                ok = isinstance(v, bool)
            elif isinstance(defaut, int):
                ok = isinstance(v, (int, float)) and not isinstance(v, bool)
            else:
                ok = isinstance(v, type(defaut))
            if not ok:
                self._log(f"config.json : « {cle} » n'a pas la forme attendue — "
                          "valeur par défaut utilisée.", "ERROR")
                cfg[cle] = copy.deepcopy(defaut)
        fournisseurs = []
        for n, p in enumerate(cfg["providers"], 1):
            if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                self._log(f"config.json : fournisseur n° {n} illisible (objet avec "
                          "un nom attendu) — ignoré.", "ERROR")
                continue
            for cle in ("accounts", "wireguard"):
                liste = p.get(cle, [])
                if not (isinstance(liste, list) and all(isinstance(e, dict) for e in liste)):
                    self._log(f"config.json : fournisseur n° {n}, « {cle} » "
                              "illisible — ignoré.", "ERROR")
                    p = {**p, cle: []}
            for cle in ("ovpn_file",):
                if not isinstance(p.get(cle, ""), str):
                    p = {**p, cle: ""}
            fournisseurs.append(p)
        cfg["providers"] = fournisseurs
        return cfg

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
        self._stop_vpn_process()
        self._stop_tor()
        self._revert_vpn_dns()
        self._demonter_tunnel()
        self._cleanup_tor_routes()
        self._teardown_lan_sharing()
        self._ipv6_block_off()
        self._remove_dns_split()
        self._garde_vpn_off()
        # Le blocage hors tunnel en dernier — et, sous systemd, pas ici : le
        # script d'ExecStopPost le lève si le service s'ARRÊTE et le garde
        # s'il REDÉMARRE (réveil de veille, mise à jour).  Lui seul le sait ;
        # le lever ici ouvrait la connexion normale à chaque redémarrage.
        if not os.environ.get("NOTIFY_SOCKET"):
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
        # Pas les chaînes KATAKOMBA_KILL* : gardées exprès d'un lancement à
        # l'autre (sortie en échec, redémarrage), elles protègent jusqu'à ce
        # que _kill_switch_on les remplace, d'un seul tenant.
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
                for tun in {self._tun_iface, TUN_IFACE, "tun0", "tun1"}:
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
        # Pont WireGuard d'une session précédente (daemon tué sans nettoyage) :
        # il garderait son port, et le pont suivant ne pourrait pas démarrer.
        _run("pkill", "-f", PONT_PATTERN)
        _run("pkill", "-f", PONT_SONDE_PATTERN)
        # Clé privée WireGuard laissée par un arrêt brutal entre son écriture
        # et la lecture par wg.
        for fichier in (WG_CONF_RUN, WG_CONF_SONDE):
            try:
                fichier.unlink(missing_ok=True)
            except OSError:
                pass

        self._cleanup_tor_routes()
        # Interface tunnel d'une session précédente : la supprimer emporte
        # son adresse et ses routes.
        _run("ip", "link", "del", "dev", TUN_IFACE)
        _run("ip", "link", "del", "dev", TUN_SONDE)
        self._retour_entrant_off(force=True)
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
            # Le port de contrôle n'est cru que si NOTRE Tor tourne : avant
            # son démarrage, tout compte local peut occuper 9051 et répondre
            # « 100 % » à sa place.
            if not (self.tor_process and self.tor_process.poll() is None):
                prog = -1
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
        threading.Thread(target=self._vpn_loop, daemon=True).start()
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
        self._garde_vpn_on()
        if not self._kill_switch_on():
            # Rien ne reste d'un lancement précédent (réglage désactivé
            # entre-temps, ou pose impossible : jamais de blocage à moitié).
            self._kill_switch_off(force=True)
            if self.config.get("kill_switch", True):
                self._log("Le service continue SANS blocage hors tunnel ; "
                          "nouvel essai toutes les 30 s.", "ERROR")
        self._start_status_server()
        if not self._start_services():
            sys.exit(1)
        self._monitor_loop()
        self._log("Daemon terminé.")
