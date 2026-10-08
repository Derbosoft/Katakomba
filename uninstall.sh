#!/usr/bin/env bash
# Katakomba — Désinstallation
#
#   sudo katakomba uninstall            retire le programme, garde vos réglages
#   sudo katakomba uninstall --purge    retire aussi réglages, fournisseurs,
#                                     comptes et données Tor
#
# Installé par paquet : « sudo apt remove katakomba » (ou « purge »)
# appelle ce script avec --paquet — dpkg retire lui-même ses propres fichiers.

set -u

PURGE=0
PAQUET=0
for a in "$@"; do
    case "$a" in
        --purge)  PURGE=1 ;;
        --paquet) PAQUET=1 ;;
        *) echo "Option inconnue : $a" >&2; exit 2 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo "Relancez avec : sudo katakomba uninstall"
    exit 1
fi

INSTALL_DIR="/opt/katakomba"

echo "Arrêt du service …"
systemctl disable --now katakomba 2>/dev/null || true

# Le script de nettoyage défait exactement ce que le daemon installe
# (règles ip6tables/iptables, NAT du partage LAN, dnsmasq, drop-in DNS).
for c in /usr/lib/katakomba/katakomba-cleanup.sh /usr/local/lib/katakomba-cleanup.sh; do
    if [ -x "$c" ]; then
        "$c" || true
    fi
done

echo "Retrait des fichiers système …"
rm -f /etc/systemd/system/katakomba.service \
      /lib/systemd/system-sleep/katakomba-sleep \
      /usr/local/lib/katakomba-cleanup.sh \
      /etc/systemd/resolved.conf.d/katakomba-split.conf \
      /etc/xdg/autostart/katakomba.desktop
rm -rf /usr/lib/katakomba /run/katakomba
systemctl daemon-reload 2>/dev/null || true
systemctl reload-or-restart systemd-resolved 2>/dev/null || true

if [ "$PAQUET" = "0" ]; then
    rm -f /usr/local/bin/katakomba /usr/share/applications/katakomba.desktop \
          /usr/share/applications/org.katakomba.Katakomba.desktop \
          /usr/share/icons/hicolor/scalable/apps/katakomba.svg \
          /usr/share/polkit-1/rules.d/50-katakomba.rules \
          /usr/share/polkit-1/actions/org.katakomba.policy
    if [ -d "$INSTALL_DIR" ]; then
        if [ "$PURGE" = "1" ]; then
            rm -rf "$INSTALL_DIR"
        else
            # Le code part ; vos fichiers de fournisseurs restent.
            find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name providers \
                 -exec rm -rf {} +
        fi
    fi
fi

if [ "$PURGE" = "1" ]; then
    echo "Effacement des réglages, fournisseurs, comptes et données Tor …"
    rm -rf /etc/katakomba /var/lib/katakomba \
           "$INSTALL_DIR/providers"
    groupdel katakomba 2>/dev/null || true
fi

echo ""
echo "Katakomba est désinstallé."
if [ "$PURGE" = "0" ]; then
    echo "Réglages conservés : /etc/katakomba et $INSTALL_DIR/providers"
    echo "(tout effacer : --purge, ou « sudo apt purge katakomba »)."
fi
echo "Le service tor du système avait été désactivé à l'installation ;"
echo "pour le réactiver : sudo systemctl enable --now tor"
