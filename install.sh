#!/usr/bin/env bash
# Katakomba — Installation (Ubuntu/Debian)
# Usage : sudo bash install.sh
#
# Deux modes :
#  - installation depuis les sources (usage ci-dessus) : copie le code dans
#    /opt/katakomba, installe le CLI et le lanceur ;
#  - KATAKOMBA_PAQUET=1 : appelé par le postinst du paquet .deb.  Le code, le
#    CLI et le lanceur sont déjà posés par dpkg ; seule la configuration du
#    système reste à faire (groupe, droits, unité systemd, hook de veille).
#    Une seule logique d'installation pour les deux voies.

set -e
PAQUET="${KATAKOMBA_PAQUET:-0}"
if [ "$PAQUET" = "1" ]; then
    KATAKOMBA_SKIP_APT=1       # dépendances garanties par le champ Depends
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(python3 -B -c "import sys; sys.path.insert(0,'$SCRIPT_DIR'); from constants import VERSION; print(VERSION)" 2>/dev/null || echo "?")"
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
SERVICE_FILE="/etc/systemd/system/katakomba.service"
CLEANUP_SCRIPT="/usr/local/lib/katakomba-cleanup.sh"
SLEEP_HOOK="/lib/systemd/system-sleep/katakomba-sleep"
CLI_BIN="/usr/local/bin/katakomba"
if [ "$PAQUET" = "1" ]; then
    # Un paquet n'écrit pas dans /usr/local (réservé à l'administrateur).
    CLEANUP_SCRIPT="/usr/lib/katakomba/katakomba-cleanup.sh"
    CLI_BIN="/usr/bin/katakomba"
fi
CONFIG_DIR="/etc/katakomba"
# Le code est déployé ici, propriété de root : le service l'exécute en root.
INSTALL_DIR="/opt/katakomba"
STATE_DIR="/var/lib/katakomba"
# Nommé comme l'application GTK : GNOME n'affiche les notifications d'une
# application que si un lanceur porte son identifiant.
DESKTOP_FILE="/usr/share/applications/org.katakomba.Katakomba.desktop"
POLKIT_RULES="/usr/share/polkit-1/rules.d/50-katakomba.rules"
POLKIT_ACTIONS="/usr/share/polkit-1/actions/org.katakomba.policy"
ICON_FILE="/usr/share/icons/hicolor/scalable/apps/katakomba.svg"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Katakomba v$VERSION — Installation                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Source     : $SCRIPT_DIR"
echo "  Déploiement: $INSTALL_DIR"
echo "  Utilisateur: $REAL_USER"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERREUR : ce script doit être lancé en root."
    echo "  sudo bash install.sh"
    exit 1
fi

# Écrire en root dans $CONFIG_DIR (inscriptible par le groupe katakomba) : jamais
# à travers un lien symbolique.  « [ -f ] » suit les liens et un lien pendant
# le trompe ; on teste donc aussi « -L ».
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }

# ── Migration : Tor-VPN Manager → Katakomba ─────────────────────────────────
# Jusqu'à la v3.7.0, le programme s'appelait « Tor-VPN Manager » : service
# tor-vpn-manager, groupe torvpn, commande tor-vpn.  Réglages, comptes,
# fournisseurs et données Tor sont repris tels quels ; l'ancien service est
# retiré — laissé en place, il se disputerait le port 9050 et le tunnel avec
# le nouveau.
ANCIEN_ACTIF=false
if [ -e /etc/systemd/system/tor-vpn-manager.service ] || [ -d /etc/tor-vpn-manager ] \
        || [ -d /opt/tor-vpn-manager ] || getent group torvpn >/dev/null; then
    echo "[0/7] Migration depuis Tor-VPN Manager …"
    if [ "$PAQUET" != "1" ] && dpkg-query -W -f='${Status}' tor-vpn-manager 2>/dev/null \
            | grep -q "ok installed"; then
        echo "ERREUR : l'ancien paquet tor-vpn-manager est installé."
        echo "  Retirez-le d'abord (vos réglages sont conservés) :"
        echo "    sudo apt remove tor-vpn-manager"
        exit 1
    fi
    systemctl is-active tor-vpn-manager &>/dev/null && ANCIEN_ACTIF=true
    # L'arrêt exécute l'ExecStopPost de l'ancienne unité : règles iptables,
    # dnsmasq du partage LAN et drop-in DNS de l'ancien daemon disparaissent.
    systemctl disable --now tor-vpn-manager 2>/dev/null || true
    for c in /usr/local/lib/tor-vpn-cleanup.sh /usr/lib/tor-vpn-manager/tor-vpn-cleanup.sh; do
        if [ -x "$c" ] && [ ! -L "$c" ]; then "$c" || true; fi
    done

    # Même GID sous un nouveau nom : les membres restent membres, et les
    # sessions déjà ouvertes gardent l'accès sans se reconnecter.
    if getent group torvpn >/dev/null; then
        if getent group katakomba >/dev/null; then
            for U in $(getent group torvpn | cut -d: -f4 | tr ',' ' '); do
                usermod -aG katakomba "$U"
            done
            groupdel torvpn 2>/dev/null || true
        else
            groupmod -n katakomba torvpn
        fi
        echo "    Groupe torvpn → katakomba (membres conservés)"
    fi

    # Répertoires déplacés d'un bloc (mv ne suit pas les liens qu'ils
    # contiennent), seulement si la cible n'existe pas encore.
    for PAIRE in "/etc/tor-vpn-manager:$CONFIG_DIR" "/var/lib/tor-vpn-manager:$STATE_DIR"; do
        ANCIEN="${PAIRE%%:*}"; NOUVEAU="${PAIRE#*:}"
        if [ -d "$ANCIEN" ] && [ ! -L "$ANCIEN" ] && absent "$NOUVEAU"; then
            mv "$ANCIEN" "$NOUVEAU"
            echo "    $ANCIEN → $NOUVEAU"
        fi
    done
    if [ -f "$STATE_DIR/tor-vpn-routes.txt" ] && absent "$STATE_DIR/tor-routes.txt"; then
        mv "$STATE_DIR/tor-vpn-routes.txt" "$STATE_DIR/tor-routes.txt"
    fi
    # Fournisseurs : copiés sans rien écraser (le paquet a pu créer la cible).
    if [ -d /opt/tor-vpn-manager/providers ] && [ ! -L /opt/tor-vpn-manager/providers ]; then
        install -d -m 755 -o root -g root "$INSTALL_DIR"
        mkdir -p "$INSTALL_DIR/providers"
        cp -a -n /opt/tor-vpn-manager/providers/. "$INSTALL_DIR/providers/"
        echo "    /opt/tor-vpn-manager/providers → $INSTALL_DIR/providers"
    fi

    # Chemins écrits en dur par l'ancienne version : .ovpn absolus dans
    # config.json, DataDirectory dans le torrc.  Réécriture sans jamais
    # suivre un lien déposé par le groupe.
    python3 - "$CONFIG_DIR" << 'MIGRATION_EOF'
import json, os, sys
rep = sys.argv[1]

def lire(chemin):
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd) as f:
        return f.read()

def ecrire(chemin, texte):
    tmp = chemin + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
    with os.fdopen(fd, "w") as f:
        f.write(texte)
    os.replace(tmp, chemin)

cfg_txt = lire(os.path.join(rep, "config.json"))
if cfg_txt:
    cfg = json.loads(cfg_txt)
    modif = False
    for p in cfg.get("providers", []):
        ov = p.get("ovpn_file", "")
        if ov.startswith("/opt/tor-vpn-manager/providers/"):
            p["ovpn_file"] = ov[len("/opt/tor-vpn-manager/"):]
            modif = True
    if modif:
        ecrire(os.path.join(rep, "config.json"),
               json.dumps(cfg, indent=2, ensure_ascii=False))
        print("    Chemins .ovpn de config.json mis à jour")

torrc = lire(os.path.join(rep, "torrc"))
if torrc and "tor-vpn-manager/" in torrc:
    torrc = (torrc.replace("/var/lib/tor-vpn-manager/", "/var/lib/katakomba/")
                  .replace("/etc/tor-vpn-manager/", "/etc/katakomba/"))
    ecrire(os.path.join(rep, "torrc"), torrc)
    print("    Chemins du torrc mis à jour")
MIGRATION_EOF

    # Fichiers système de l'ancienne version.  Le CLI de /usr/local/bin
    # n'est retiré que s'il est bien le nôtre.
    if grep -qs "Tor-VPN Manager — CLI wrapper" /usr/local/bin/tor-vpn; then
        rm -f /usr/local/bin/tor-vpn
    fi
    rm -f /etc/systemd/system/tor-vpn-manager.service \
          /lib/systemd/system-sleep/tor-vpn-sleep \
          /usr/local/lib/tor-vpn-cleanup.sh \
          /etc/systemd/resolved.conf.d/tor-vpn-split.conf \
          /usr/share/applications/tor-vpn-gui.desktop \
          /etc/xdg/autostart/tor-vpn-gui.desktop \
          /run/tor-vpn-manager.sock
    rm -rf /usr/lib/tor-vpn-manager /run/tor-vpn-manager
    systemctl daemon-reload 2>/dev/null || true
    echo "    Ancien service, commande tor-vpn et lanceur retirés"
fi

# ── [1/7] Dépendances ────────────────────────────────────────────────────────
echo "[1/7] Installation des dépendances …"

# KATAKOMBA_SKIP_APT=1 : rejouer l'installeur sans réseau.  C'est le besoin réel
# quand seule l'unité systemd ou le CLI a changé sur une machine déjà
# installée — d'autant que le seul chemin réseau disponible peut être le
# tunnel que ce daemon est justement en train de monter.
#
# Le garde n'est pas une simple dérogation : il VÉRIFIE que tout est déjà là
# et refuse sinon.  Sauter apt sur une machine incomplète produirait une
# installation à moitié fonctionnelle, plus difficile à diagnostiquer qu'un
# échec franc.
DEPS_BIN=(tor openvpn python3 curl)
# Interface graphique : GTK 4 et libadwaita 1.5 ou plus (Ubuntu 24.04+, Debian 13+).
DEPS_GUI=(python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 librsvg2-common)
gui_disponible() {
    python3 - << 'GUI_EOF' 2>/dev/null
import sys, gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_foreign("cairo")
from gi.repository import Adw
sys.exit(0 if (Adw.get_major_version(), Adw.get_minor_version()) >= (1, 5) else 1)
GUI_EOF
}
if [ "${KATAKOMBA_SKIP_APT:-0}" = "1" ]; then
    echo "    KATAKOMBA_SKIP_APT=1 — vérification des dépendances sans apt …"
    manquants=()
    for bin in "${DEPS_BIN[@]}"; do
        command -v "$bin" &>/dev/null || manquants+=("$bin")
    done
    gui_disponible || manquants+=("${DEPS_GUI[@]}")
    if [ ${#manquants[@]} -gt 0 ]; then
        echo "ERREUR : dépendances absentes : ${manquants[*]}"
        echo "  KATAKOMBA_SKIP_APT=1 suppose une machine déjà installée."
        echo "  Relancez sans ce garde, avec un accès réseau."
        exit 1
    fi
    echo "    Toutes les dépendances sont présentes."
else
    apt-get update -qq
    apt-get install -y tor openvpn python3 curl "${DEPS_GUI[@]}"
fi

# dnsmasq ne sert QU'au partage LAN (fonction optionnelle, désactivée par
# défaut).  On ne l'installe donc pas systématiquement pour le désactiver
# aussitôt : uniquement s'il est déjà présent ou si le partage est configuré.
LAN_CONFIGURED=false
if [ -f "$CONFIG_DIR/config.json" ] && python3 -c "
import json,sys
d = json.load(open('$CONFIG_DIR/config.json'))
sys.exit(0 if d.get('lan_auto') or d.get('lan_iface') else 1)
" 2>/dev/null; then
    LAN_CONFIGURED=true
fi
if command -v dnsmasq &>/dev/null; then
    echo "    dnsmasq déjà présent (partage LAN disponible)"
elif [ "$LAN_CONFIGURED" = true ] && [ "${KATAKOMBA_SKIP_APT:-0}" != "1" ]; then
    echo "    Partage LAN configuré — installation de dnsmasq …"
    apt-get install -y dnsmasq || true
else
    echo "    dnsmasq non installé (inutile : partage LAN désactivé)"
    echo "    Si vous activez le partage LAN : sudo apt install dnsmasq"
fi

# ── [2/7] Répertoire de configuration ───────────────────────────────────────
echo "[2/7] Répertoire de configuration …"

# Groupe katakomba : permet au GUI de tourner SANS root (config + providers
# accessibles en écriture, actions systemctl via pkexec/polkit).
groupadd -f katakomba
if [ "$PAQUET" = "1" ]; then
    # Installation graphique (logithèque) : pas de SUDO_USER.  Les
    # administrateurs de la machine (groupes sudo/admin) reçoivent l'accès —
    # ils ont déjà plus de droits que le groupe katakomba n'en donne.  Les
    # autres comptes : « sudo katakomba autoriser <utilisateur> ».
    for U in $(getent group sudo admin | cut -d: -f4 | tr ',' ' '); do
        usermod -aG katakomba "$U" && echo "    Utilisateur '$U' ajouté au groupe katakomba"
    done
fi
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ] && id "$REAL_USER" &>/dev/null; then
    usermod -aG katakomba "$REAL_USER"
    echo "    Utilisateur '$REAL_USER' ajouté au groupe katakomba"
    echo "    (déconnexion/reconnexion nécessaire pour prise d'effet)"
fi

mkdir -p "$CONFIG_DIR"
chown root:katakomba "$CONFIG_DIR"
chmod 2770 "$CONFIG_DIR"            # setgid : fichiers créés → groupe katakomba
# « -type f » écarte les liens symboliques : le groupe peut en déposer ici,
# et root ne doit jamais agir à travers eux.
find "$CONFIG_DIR" -maxdepth 1 -type f -exec chgrp katakomba {} + 2>/dev/null || true
find "$CONFIG_DIR" -maxdepth 1 -type f -exec chmod g+rw {} + 2>/dev/null || true
# install_dir n'est plus lu (le CLI connaît $INSTALL_DIR) : un fichier que le
# groupe peut remplacer ne doit pas désigner le code à exécuter.
rm -f "$CONFIG_DIR/install_dir"
echo "    Créé : $CONFIG_DIR (root:katakomba, 2770)"

# Migration depuis une installation précédente (avant la v3.2, la config
# vivait aussi dans /opt/tor-vpn-manager — lu AVANT le déploiement du code).
for OLD in "/root/.config/tor-vpn-manager" "/home/$REAL_USER/.config/tor-vpn-manager" \
           "/opt/tor-vpn-manager"; do
    if [ -f "$OLD/config.json" ] && absent "$CONFIG_DIR/config.json"; then
        echo "    Migration config : $OLD → $CONFIG_DIR"
        cp "$OLD/config.json" "$CONFIG_DIR/config.json"
    fi
done

# L'ancien code (fournisseurs et config.json déjà repris) : plus rien à lire.
if [ -d /opt/tor-vpn-manager ] && [ ! -L /opt/tor-vpn-manager ] \
        && [ "$SCRIPT_DIR" != /opt/tor-vpn-manager ]; then
    rm -rf /opt/tor-vpn-manager
fi

# Répertoire d'état (root seul) : données Tor, routes /32 persistées.
install -d -m 755 -o root -g root "$STATE_DIR"
if [ -d "$CONFIG_DIR/tor_data" ] && [ ! -L "$CONFIG_DIR/tor_data" ] \
        && [ "$(stat -c %u "$CONFIG_DIR/tor_data")" = 0 ] \
        && absent "$STATE_DIR/tor_data"; then
    mv "$CONFIG_DIR/tor_data" "$STATE_DIR/tor_data"
    echo "    Données Tor déplacées : $CONFIG_DIR/tor_data → $STATE_DIR/tor_data"
fi

# torrc par défaut (circuits longs et stables, mêmes valeurs que les défauts
# de l'onglet Tor du GUI).  Créé UNIQUEMENT s'il n'existe pas : une
# réinstallation ne doit jamais écraser un torrc personnalisé.
TORRC_FILE="$CONFIG_DIR/torrc"
if absent "$TORRC_FILE"; then
    cat > "$TORRC_FILE" << 'TORRC_EOF'
# === Paramètres obligatoires — ne pas supprimer ===
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/katakomba/tor_data

# === Paramètres personnalisés ===
AvoidDiskWrites 1
SafeLogging 1
ClientUseIPv6 0
TestSocks 1
LongLivedPorts 1194,443
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 3600
CircuitBuildTimeout 60
NewCircuitPeriod 60
KeepalivePeriod 60
NumEntryGuards 3
GuardLifetime 2 months
TORRC_EOF
    chown root:katakomba "$TORRC_FILE"
    chmod 660 "$TORRC_FILE"
    echo "    torrc par défaut créé : $TORRC_FILE"
else
    echo "    torrc existant conservé : $TORRC_FILE"
fi

# ── [3/7] Code du programme ──────────────────────────────────────────────────
echo "[3/7] Déploiement du code dans $INSTALL_DIR …"

# Le service tourne en root : son code ne doit être modifiable QUE par root.
# Jusqu'à la v3.6.4, il s'exécutait depuis le clone de l'utilisateur —
# n'importe quel programme lancé sous ce compte pouvait réécrire le daemon et
# obtenir root au redémarrage suivant, sans mot de passe.
FICHIERS_CODE=(constants.py main.py validation.py adaptation.py i18n.py daemon gui assets polkit po
               repair_network.sh katakomba-cli.sh install.sh uninstall.sh template.ovpn
               LICENSE README.md README.fr.md)
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    install -d -m 755 -o root -g root "$INSTALL_DIR"
    rm -rf "$INSTALL_DIR/daemon" "$INSTALL_DIR/gui" "$INSTALL_DIR/assets" \
           "$INSTALL_DIR/polkit" "$INSTALL_DIR/po"               # rien de périmé
    for f in "${FICHIERS_CODE[@]}"; do
        cp -r "$SCRIPT_DIR/$f" "$INSTALL_DIR/"
    done
    # Fournisseurs de l'ancien emplacement : repris sans rien écraser.
    if [ -d "$SCRIPT_DIR/providers" ]; then
        mkdir -p "$INSTALL_DIR/providers"
        cp -rn "$SCRIPT_DIR/providers/." "$INSTALL_DIR/providers/"
    fi
fi
find "$INSTALL_DIR" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$INSTALL_DIR"
find "$INSTALL_DIR" -path "$INSTALL_DIR/providers" -prune -o -type d -exec chmod 755 {} +
find "$INSTALL_DIR" -path "$INSTALL_DIR/providers" -prune -o -type f -exec chmod 644 {} +
chmod 755 "$INSTALL_DIR/repair_network.sh" "$INSTALL_DIR/katakomba-cli.sh" \
          "$INSTALL_DIR/install.sh" "$INSTALL_DIR/uninstall.sh"
# providers/ : seul endroit inscriptible par le groupe (import via le GUI).
# Le daemon contrôle chaque .ovpn avant usage (validation.py).
mkdir -p "$INSTALL_DIR/providers"
chown -R root:katakomba "$INSTALL_DIR/providers"
find "$INSTALL_DIR/providers" -type d -exec chmod 2770 {} +
find "$INSTALL_DIR/providers" -type f -exec chmod 660 {} +
echo "    Code : $INSTALL_DIR (root:root, lecture seule pour les autres)"

# Chemins .ovpn absolus pointant sur l'ancien clone → relatifs (providers/…),
# résolus désormais depuis $INSTALL_DIR.
if [ -f "$CONFIG_DIR/config.json" ] && [ ! -L "$CONFIG_DIR/config.json" ] \
        && [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    python3 - "$CONFIG_DIR/config.json" "$SCRIPT_DIR" << 'PYEOF'
import json, os, sys
chemin, ancien = sys.argv[1], sys.argv[2].rstrip("/") + "/"
cfg = json.load(open(chemin))
modif = False
for p in cfg.get("providers", []):
    ov = p.get("ovpn_file", "")
    if ov.startswith(ancien + "providers/"):
        p["ovpn_file"] = ov[len(ancien):]
        modif = True
if modif:
    tmp = chemin + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    # O_EXCL | O_NOFOLLOW : jamais à travers un lien déposé par le groupe.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, chemin)
    print("    Chemins .ovpn rendus relatifs à", ancien)
PYEOF
fi

# ── [4/7] Services système ───────────────────────────────────────────────────
echo "[4/7] Configuration des services système …"

# Sur Debian 12+, systemd-resolved est un paquet séparé non installé par défaut.
if ! systemctl list-unit-files systemd-resolved.service --no-legend 2>/dev/null | grep -q systemd-resolved; then
    if [ "${KATAKOMBA_SKIP_APT:-0}" = "1" ]; then
        echo "    systemd-resolved absent — non installé (KATAKOMBA_SKIP_APT=1)"
    else
        echo "    systemd-resolved absent — tentative d'installation …"
        apt-get install -y systemd-resolved || true
    fi
fi
systemctl enable systemd-resolved 2>/dev/null || true
# Doit exister : l'unité le déclare en ReadWritePaths (reste de /etc en lecture seule).
mkdir -p /etc/systemd/resolved.conf.d
systemctl start  systemd-resolved 2>/dev/null || true

# Tor géré en subprocess par le daemon — évite le conflit sur le port 9050
systemctl disable tor 2>/dev/null || true
systemctl stop    tor 2>/dev/null || true

# dnsmasq système désactivé (lancé à la demande par le daemon pour le partage LAN)
systemctl disable dnsmasq 2>/dev/null || true
systemctl stop    dnsmasq 2>/dev/null || true

# ── [5/7] Service systemd ────────────────────────────────────────────────────
echo "[5/7] Création du service systemd …"

# Script de nettoyage des règles iptables (appelé avant démarrage et après arrêt)
mkdir -p "$(dirname "$CLEANUP_SCRIPT")"
cat > "$CLEANUP_SCRIPT" << 'CLEANUP_EOF'
#!/bin/bash
# Suppression en boucle : des crashs répétés peuvent empiler plusieurs jumps
# Blocage hors tunnel : le service s'arrête, la connexion normale revient.
for c in "iptables OUTPUT KATAKOMBA_KILL" "iptables FORWARD KATAKOMBA_KILL_FWD" \
         "ip6tables OUTPUT KATAKOMBA_KILL6" "ip6tables FORWARD KATAKOMBA_KILL6_FWD"; do
    set -- $c
    while $1 -D "$2" -j "$3" 2>/dev/null; do :; done
    $1 -F "$3" 2>/dev/null
    $1 -X "$3" 2>/dev/null
done
while ip6tables -D OUTPUT  -j KATAKOMBA_KS6     2>/dev/null; do :; done
ip6tables -F KATAKOMBA_KS6                 2>/dev/null
ip6tables -X KATAKOMBA_KS6                 2>/dev/null
while ip6tables -D FORWARD -j KATAKOMBA_KS6_FWD 2>/dev/null; do :; done
ip6tables -F KATAKOMBA_KS6_FWD            2>/dev/null
ip6tables -X KATAKOMBA_KS6_FWD            2>/dev/null
while iptables  -D FORWARD -j KATAKOMBA_LAN_FWD 2>/dev/null; do :; done
iptables  -F KATAKOMBA_LAN_FWD            2>/dev/null
iptables  -X KATAKOMBA_LAN_FWD            2>/dev/null
# dnsmasq du partage LAN uniquement, ciblé via son --pid-file unique
# (jamais « pkill dnsmasq » : cela tuerait aussi ceux de libvirt/virbr0).
# Second motif : emplacement d'avant la v3.7.0.
pkill -f /run/katakomba/dnsmasq.pid 2>/dev/null
pkill -f /etc/katakomba/tor-vpn-dnsmasq.pid 2>/dev/null
# NAT masquerade du partage LAN
CONFIG_JSON="/etc/katakomba/config.json"
if [ -f "$CONFIG_JSON" ]; then
    LAN_SUBNET=$(python3 -c "import json; d=json.load(open('$CONFIG_JSON')); print(d.get('lan_subnet',''))" 2>/dev/null)
    if [ -n "$LAN_SUBNET" ]; then
        iptables -t nat -D POSTROUTING -s "$LAN_SUBNET" -o tun0 -j MASQUERADE 2>/dev/null
        iptables -t nat -D POSTROUTING -s "$LAN_SUBNET" -o tun1 -j MASQUERADE 2>/dev/null
    fi
fi
# DNS split drop-in
rm -f /etc/systemd/resolved.conf.d/katakomba-split.conf
systemctl reload-or-restart systemd-resolved 2>/dev/null || true
exit 0
CLEANUP_EOF
chmod +x "$CLEANUP_SCRIPT"

cat > "$SERVICE_FILE" << SERVICE_EOF
[Unit]
Description=Katakomba — Daemon (Tor + OpenVPN headless)
After=network-online.target
Wants=network-online.target
# Pas de plafond de redémarrage : le daemon doit toujours retenter
# (sinon une série d'échecs au boot laisserait le service mort).
StartLimitIntervalSec=0

[Service]
# Type=notify + WatchdogSec : le daemon envoie READY=1 au démarrage puis
# WATCHDOG=1 toutes les ~3s depuis sa boucle de monitoring.  Si le processus
# gèle (plus de pings pendant 90s), systemd le tue et le relance.
Type=notify
NotifyAccess=main
WatchdogSec=90
User=root
WorkingDirectory=$INSTALL_DIR
ExecStartPre=$CLEANUP_SCRIPT
ExecStart=/usr/bin/python3 -m daemon
ExecStopPost=$CLEANUP_SCRIPT
Restart=on-failure
RestartSec=20
# 78 = aucun fournisseur configuré : une erreur de configuration, pas une
# panne.  Relancer toutes les 20 s ne ferait que remplir le journal.
RestartPreventExitStatus=78
# /run/katakomba (0700 root) : auth.tmp, copies validées du .ovpn et du
# torrc, pid de dnsmasq.  Supprimé par systemd à l'arrêt, même après un crash.
RuntimeDirectory=katakomba
RuntimeDirectoryMode=0700
# Durcissement : le daemon n'a besoin d'écrire que dans ces répertoires-là.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=$CONFIG_DIR -/etc/systemd/resolved.conf.d
StandardOutput=journal
StandardError=journal
SyslogIdentifier=katakomba
KillMode=control-group
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable katakomba
echo "    Service  : $SERVICE_FILE"
echo "    Activé   : démarrage automatique au boot"

# ── [6/7] Hook veille/réveil ─────────────────────────────────────────────────
echo "[6/7] Hook veille/réveil (résolution VPN-sans-Tor après suspend) …"

# Après un réveil, les circuits Tor sont périmés mais le port 9050 peut rester
# ouvert → OpenVPN se reconnecte sans passer par Tor. Le hook force un redémarrage
# complet du daemon après chaque réveil pour reconstruire les circuits Tor.
cat > "$SLEEP_HOOK" << 'SLEEP_EOF'
#!/bin/bash
# Katakomba — hook systemd-sleep
# Redémarre le daemon après chaque réveil — s'il tournait.  « try-restart » et
# non « restart » : ce dernier démarrait aussi un service arrêté exprès.
case "$1" in
    post)
        sleep 3
        systemctl try-restart katakomba 2>/dev/null || true
        ;;
esac
exit 0
SLEEP_EOF
chmod +x "$SLEEP_HOOK"
echo "    Hook     : $SLEEP_HOOK"

# ── [7/7] CLI + Lanceur GUI ──────────────────────────────────────────────────
echo "[7/7] Création du CLI katakomba et du lanceur GUI …"

# Lanceur de la v3.7.0 et d'avant, remplacé par $DESKTOP_FILE.
rm -f /usr/share/applications/katakomba.desktop

if [ "$PAQUET" = "1" ]; then
    # CLI et lanceur appartiennent au paquet.  Une copie laissée par une
    # installation depuis les sources masquerait /usr/bin/katakomba (PATH) :
    # on la retire si c'est bien la nôtre.
    if grep -qs "Katakomba — CLI wrapper" /usr/local/bin/katakomba; then
        rm -f /usr/local/bin/katakomba
        echo "    Ancien CLI /usr/local/bin/katakomba retiré (remplacé par $CLI_BIN)"
    fi
    rm -f /usr/local/lib/katakomba-cleanup.sh
    echo "    CLI et lanceur fournis par le paquet"
else
cp "$INSTALL_DIR/katakomba-cli.sh" "$CLI_BIN"
chmod +x "$CLI_BIN"
echo "    CLI : $CLI_BIN"

# Exec via le wrapper katakomba : il retrouve le répertoire d'installation
# et lance le GUI en utilisateur normal (groupe katakomba).
install -D -m 644 "$INSTALL_DIR/assets/katakomba.svg" "$ICON_FILE"
gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
cat > "$DESKTOP_FILE" << DESKTOP_EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Katakomba
Comment=Faire passer tout le trafic par un VPN à travers Tor
Comment[en]=Route all traffic through a VPN tunnelled over Tor
Comment[es]=Hacer pasar todo el tráfico por una VPN, a través de Tor
Comment[de]=Den gesamten Verkehr über ein VPN leiten, durch Tor
Comment[it]=Far passare tutto il traffico da una VPN, attraverso Tor
Comment[pt]=Fazer todo o tráfego passar por uma VPN, através do Tor
Exec=$CLI_BIN gui
Icon=katakomba
StartupWMClass=org.katakomba.Katakomba
X-GNOME-UsesNotifications=true
Terminal=false
Categories=Network;Security;
DESKTOP_EOF
echo "    Lanceur : $DESKTOP_FILE (menu applications, sans autostart)"

# polkit : connexion/déconnexion sans mot de passe pour le groupe katakomba,
# invites explicites pour le reste (relu aussitôt par polkitd).
install -D -m 644 "$INSTALL_DIR/polkit/50-katakomba.rules" "$POLKIT_RULES"
install -D -m 644 "$INSTALL_DIR/polkit/org.katakomba.policy" "$POLKIT_ACTIONS"
echo "    polkit  : $POLKIT_RULES"
fi

# ── Vérification ──────────────────────────────────────────────────────────────
echo ""
echo "── Vérification ────────────────────────────────────────"
all_ok=true

for bin in tor openvpn python3 curl; do
    if command -v "$bin" &>/dev/null; then
        echo "  OK  $bin"
    else
        echo "  KO  $bin  MANQUANT"
        all_ok=false
    fi
done

# Optionnel : son absence ne doit pas faire échouer l'installation.
if command -v dnsmasq &>/dev/null; then
    echo "  OK  dnsmasq  (partage LAN disponible)"
else
    echo "  --  dnsmasq  absent — optionnel, requis seulement pour le partage LAN"
fi

gui_disponible \
    && echo "  OK  interface graphique (GTK 4, libadwaita)" \
    || { echo "  KO  interface graphique : GTK 4 / libadwaita 1.5+ MANQUANT"; all_ok=false; }

if systemctl is-active systemd-resolved &>/dev/null; then
    echo "  OK  systemd-resolved actif"
else
    echo "  KO  systemd-resolved inactif"
    all_ok=false
fi

systemctl is-enabled tor &>/dev/null \
    && echo "  KO  tor.service encore activé (conflit port 9050)" \
    || echo "  OK  tor.service désactivé"

[ -f "$SERVICE_FILE" ]             && echo "  OK  service systemd créé"
[ -x "$SLEEP_HOOK" ]               && echo "  OK  hook veille/réveil installé"
systemctl is-enabled katakomba &>/dev/null && echo "  OK  démarrage auto activé"
[ -x "$CLI_BIN" ]                  && echo "  OK  commande katakomba disponible"
[ -f "$POLKIT_RULES" ] && [ -f "$POLKIT_ACTIONS" ] \
    && echo "  OK  polkit : connexion sans mot de passe (groupe katakomba)" \
    || { echo "  KO  règles polkit absentes"; all_ok=false; }
[ -f "$INSTALL_DIR/daemon/core.py" ] && [ "$(stat -c %U "$INSTALL_DIR/daemon/core.py")" = root ] \
                                   && echo "  OK  code déployé : $INSTALL_DIR (root)"
id debian-tor &>/dev/null \
    && echo "  OK  utilisateur debian-tor (Tor abandonne root)" \
    || echo "  --  debian-tor absent — Tor restera en root"
[ -f "$CONFIG_DIR/torrc" ]         && echo "  OK  torrc présent"

echo "────────────────────────────────────────────────────────"
echo ""

if [ "$all_ok" = true ]; then
    echo "  Installation terminée avec succès."
else
    echo "  Installation terminée avec des avertissements (voir ci-dessus)."
fi

# Le tunnel tournait avant la migration : on ne laisse pas la machine sans.
if [ "$ANCIEN_ACTIF" = true ]; then
    systemctl start katakomba 2>/dev/null \
        && echo "  Service katakomba démarré (l'ancien service tournait)."
fi

if [ "$PAQUET" = "1" ]; then
    echo ""
    echo "  Ouvrez « Katakomba » depuis le menu des applications :"
    echo "  un assistant vous guide jusqu'à la connexion."
    echo ""
    exit 0
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PROCHAINE ÉTAPE                                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Ouvrir l'interface de configuration :"
echo ""
echo "       katakomba gui        (sans sudo — un assistant vous guide)"
echo "    ou python3 $INSTALL_DIR/main.py"
echo ""
echo "  Après une modification du code source : relancez « sudo bash install.sh »"
echo "  (le service exécute la copie de $INSTALL_DIR, pas le clone)."
echo ""
echo "  Démarrer le service :"
echo ""
echo "       sudo katakomba start"
echo ""
echo "  Surveillance :"
echo "    katakomba status    # état complet"
echo "    katakomba follow    # logs en direct"
echo ""
