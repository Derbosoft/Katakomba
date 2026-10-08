from pathlib import Path

VERSION       = "3.7.2"
SCRIPT_DIR    = Path(__file__).resolve().parent
PROVIDERS_DIR = SCRIPT_DIR / "providers"
CONFIG_DIR    = Path("/etc/katakomba")
CONFIG_FILE   = CONFIG_DIR / "config.json"
TORRC_FILE    = CONFIG_DIR / "torrc"

# Fichiers que le daemon ÉCRIT en root.  Jamais dans CONFIG_DIR : ce dernier
# est inscriptible par le groupe katakomba (2770, sans sticky bit), qui pourrait
# y remplacer un fichier par un lien symbolique — le daemon écrirait alors, en
# root, là où le lien pointe (/etc/sudoers.d/… par exemple).  fs.protected_
# symlinks ne couvre que les répertoires sticky ouverts à tous.
RUN_DIR       = Path("/run/katakomba")        # 0700 root, volatil
STATE_DIR     = Path("/var/lib/katakomba")    # 0755 root, persistant
AUTH_TMP      = RUN_DIR / "auth.tmp"

# Clés de config.json laissées par d'anciennes versions (surveillance de débit
# supprimée, mode unique).  Sans effet ; le GUI les retire à la sauvegarde.
OBSOLETE_CONFIG_KEYS = ("mode", "tor_min_speed_kbs", "vpn_min_speed_kbs",
                        "speed_fail_count")

SERVICE_NAME  = "katakomba"
STATUS_SOCKET = Path("/run/katakomba.sock")

DEFAULT_CONFIG = {
    "providers":         [],
    "auto_reconnect":    True,
    # Ordre de passage des comptes d'un fournisseur.  True : tiré au hasard à
    # chaque entrée dans le fournisseur.  False : ordre de la liste, utile pour
    # reproduire un incident (un refus d'identifiants intermittent devient
    # déterministe).  L'ordre des FOURNISSEURS n'est jamais mélangé : il reste
    # l'ordre de priorité défini dans la configuration.
    "random_account":    True,
    "block_ipv6":        False,
    "excluded_ips":      [],
    "excluded_domains":  [],
    "local_dns":         "",
    # Contrôle qualité du circuit Tor, une seule fois après l'établissement
    # du tunnel : si le débit mesuré est sous le seuil, on force un circuit
    # neuf (NEWNYM) et on retente, dans la limite de circuit_max_retries.
    "circuit_check":      True,
    "circuit_min_kbs":    250,   # 250 KB/s ≈ 2 Mbps
    "circuit_max_retries": 3,
    "lan_iface":         "",
    "lan_gateway":       "10.0.0.1",
    "lan_subnet":        "10.0.0.0/24",
    "lan_dhcp":          True,
    "lan_auto":          False,
    "autostart":         False,
    # Interface : onglets techniques (exclusions, partage LAN, torrc, qualité
    # du circuit) masqués en mode simple.  None = pas encore choisi : déduit
    # de la configuration, pour ne rien cacher à qui s'en sert déjà.
    "advanced_mode":     None,
}
