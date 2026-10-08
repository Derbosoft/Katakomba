#!/usr/bin/env bash
set -euo pipefail

# ── Mode d'appel ──────────────────────────────────────────────────────────────
# Sans argument  : usage manuel — arrête le service, répare, affiche conseils
# --internal     : appelé par le daemon — skip systemctl stop, le daemon
#                  se charge de son propre arrêt puis de sys.exit(1) pour
#                  que systemd le relance via Restart=on-failure

INTERNAL=0
if [[ "${1:-}" == "--internal" ]]; then
  INTERNAL=1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Relancez avec : sudo bash repair_network.sh"
  exit 1
fi

KS6_CHAIN="KATAKOMBA_KS6"
KS6_FWD_CHAIN="KATAKOMBA_KS6_FWD"
RESOLVED_DROP_IN="/etc/systemd/resolved.conf.d/katakomba-split.conf"
CONFIG_JSON="/etc/katakomba/config.json"
TOR_ROUTES_FILE="/var/lib/katakomba/tor-routes.txt"
# Emplacements d'avant la v3.7.0, encore nettoyés après une mise à jour.
LEGACY_ROUTES_FILE="/etc/katakomba/tor-routes.txt"
# Les .ovpn utilisent « dev tun » : le tunnel peut être tun0 comme tun1.
TUNS=(tun0 tun1)

if [[ $INTERNAL -eq 0 ]]; then
  echo "[1/8] Arrêt du service katakomba si actif..."
  systemctl stop katakomba.service 2>/dev/null || true
  sleep 1
fi

echo "[2/8] Arrêt des processus OpenVPN/Tor restants..."
# Uniquement ceux de ce programme, reconnus à leur ligne de commande :
# « pkill -x openvpn » couperait un autre VPN, « pkill -x tor » Tor Browser.
pkill -f -- "^openvpn .*--auth-user-pass [^ ]*katakomba/auth\.tmp" 2>/dev/null || true
pkill -f -- "^tor .*katakomba/tor(rc|_data)" 2>/dev/null || true

echo "[3/8] Nettoyage du blocage hors tunnel et des règles IPv6..."
# Blocage hors tunnel (KATAKOMBA_KILL*) : sans tunnel, il couperait tout.
for c in "iptables OUTPUT KATAKOMBA_KILL" "iptables FORWARD KATAKOMBA_KILL_FWD" \
         "ip6tables OUTPUT KATAKOMBA_KILL6" "ip6tables FORWARD KATAKOMBA_KILL6_FWD"; do
  set -- $c
  while $1 -D "$2" -j "$3" 2>/dev/null; do :; done
  $1 -F "$3" 2>/dev/null || true
  $1 -X "$3" 2>/dev/null || true
done
while ip6tables -D OUTPUT  -j "${KS6_CHAIN}" 2>/dev/null; do :; done
ip6tables -F "${KS6_CHAIN}" 2>/dev/null || true
ip6tables -X "${KS6_CHAIN}" 2>/dev/null || true
# Le jump FORWARD pointe vers la chaîne _FWD (pas KS6_CHAIN)
while ip6tables -D FORWARD -j "${KS6_FWD_CHAIN}" 2>/dev/null; do :; done
ip6tables -F "${KS6_FWD_CHAIN}" 2>/dev/null || true
ip6tables -X "${KS6_FWD_CHAIN}" 2>/dev/null || true

echo "[4/8] Nettoyage règles iptables LAN (KATAKOMBA_LAN_FWD + NAT)..."
while iptables -D FORWARD -j KATAKOMBA_LAN_FWD 2>/dev/null; do :; done
iptables -F KATAKOMBA_LAN_FWD 2>/dev/null || true
iptables -X KATAKOMBA_LAN_FWD 2>/dev/null || true
# dnsmasq du partage LAN uniquement (jamais « pkill dnsmasq » : libvirt en dépend)
pkill -f /run/katakomba/dnsmasq.pid 2>/dev/null || true
pkill -f /etc/katakomba/tor-vpn-dnsmasq.pid 2>/dev/null || true
# MASQUERADE du partage LAN : sous-réseau lu dans la config, les deux tun testés
if [[ -f "${CONFIG_JSON}" ]]; then
  LAN_SUBNET=$(python3 -c "import json;print(json.load(open('${CONFIG_JSON}')).get('lan_subnet',''))" 2>/dev/null || true)
  if [[ -n "${LAN_SUBNET}" ]]; then
    for T in "${TUNS[@]}"; do
      while iptables -t nat -D POSTROUTING -s "${LAN_SUBNET}" -o "$T" -j MASQUERADE 2>/dev/null; do :; done
    done
  fi
fi

echo "[5/8] Nettoyage DNS systemd-resolved..."
for T in "${TUNS[@]}"; do
  resolvectl revert "$T" 2>/dev/null || true
done
rm -f "${RESOLVED_DROP_IN}"
systemctl restart systemd-resolved 2>/dev/null || true

echo "[6/8] Suppression des routes /32 des relais Tor..."
# Sans cela, le trafic vers ces IPs continue de contourner le tunnel après
# la réparation.  Le daemon les nettoie à son démarrage, mais ce script doit
# pouvoir rendre la main sur un système sain sans le relancer.
N=0
TROUVE=0
for F in "${TOR_ROUTES_FILE}" "${LEGACY_ROUTES_FILE}"; do
  # Fichier ordinaire uniquement : l'ancien emplacement est inscriptible par
  # le groupe katakomba, root ne lit pas à travers un lien qu'il y aurait posé.
  [[ -f "$F" && ! -L "$F" ]] || continue
  TROUVE=1
  while read -r IP; do
    # Adresses IPv4 seulement : jamais un argument arbitraire passé à « ip ».
    [[ "$IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || continue
    ip route del "${IP}/32" 2>/dev/null && N=$((N+1))
  done < "$F"
  rm -f "$F"
done
if [[ $TROUVE -eq 1 ]]; then
  echo "    ${N} route(s) /32 supprimée(s)."
else
  echo "    Aucune route persistée."
fi

echo "[7/8] Suppression des routes OpenVPN def1 bloquées..."
for T in "${TUNS[@]}"; do
  ip route del 0.0.0.0/1   dev "$T" 2>/dev/null || true
  ip route del 128.0.0.0/1 dev "$T" 2>/dev/null || true
  ip route del default     dev "$T" 2>/dev/null || true
done

echo "[8/8] Vérification rapide de la connectivité..."
ip route get 1.1.1.1 2>/dev/null || true
getent ahosts example.com 2>/dev/null | head -n 3 || true

echo
echo "=== Réparation réseau terminée. ==="

if [[ $INTERNAL -eq 0 ]]; then
  echo
  echo "Le service katakomba est arrêté."
  echo "Relancez-le avec :  sudo katakomba start"
  echo
  echo "Si Internet ne revient toujours pas :"
  echo "  sudo systemctl restart NetworkManager"
fi
