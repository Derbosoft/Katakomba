#!/usr/bin/env bash
# Essai réel, sans root : WireGuard → pont_wg.py → Tor → serveur Proton (TCP 443).
#
# Tout se passe dans un espace réseau neuf (« unshare -rnm ») qui n'a qu'une
# sortie : l'interface WireGuard.  Le pont y joint Tor par un socket Unix ;
# Tor, lui, tourne normalement, sous l'utilisateur.  Aucune fuite possible
# vers la connexion de la machine, aucune modification du système.
#
#   bash essai/essai_wg_tor.sh fichier.conf [port TCP]
#
# Emballage et serveur : lus comme le daemon les lit (validation.analyser_wg).
# Proton et Mullvad sont reconnus d'eux-mêmes (TCP 443 sur l'IP du serveur ;
# le port en argument le remplace) ; un fichier créé par ivpn.py porte ses
# réglages en commentaires « # Katakomba-… ».
# SOCKS=unix:/chemin : utiliser un Tor déjà lancé au lieu d'en démarrer un.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1

CONF=${1:?usage : $0 fichier.conf [port]}
PORT=${2:-}
[ -r "$CONF" ] || { echo "Illisible : $CONF" >&2; exit 1; }
for c in tor wg ip curl unshare python3; do
    command -v "$c" >/dev/null || { echo "Introuvable : $c" >&2; exit 1; }
done

# Champs de la configuration (la clé privée n'est jamais affichée).
# Les fichiers de Proton ont des fins de ligne Windows : « \r » retiré.
champ() {
    # Tout ce qui suit le premier « = » : une clé base64 finit par « = ».
    tr -d '\r' < "$CONF" | awk -v k="$1" '{
        i = index($0, "="); if (!i) next
        nom = substr($0, 1, i - 1); gsub(/[ \t]/, "", nom)
        if (tolower(nom) == tolower(k)) { print substr($0, i + 1); exit }
    }' | tr -d ' \t'
}
CLE_PUBLIQUE=$(champ PublicKey)
ADRESSE=$(champ Address | cut -d, -f1)
DNS=$(champ DNS | cut -d, -f1)
SERVEUR=$(champ Endpoint | sed -E 's/:[0-9]+$//')
# Arguments du pont, d'après les réglages (aucun secret parmi eux).
mapfile -t PONT_ARGS < <(python3 -I - "$CONF" "$PORT" <<'PY'
import sys
sys.path.insert(0, ".")
from validation import analyser_wg
reglages, refus, _ = analyser_wg(open(sys.argv[1], encoding="utf-8").read())
if reglages is None:
    sys.exit("Configuration refusée : " + " ; ".join(refus))
serveur = reglages["serveur"]
if sys.argv[2] and reglages["emballage"] != "ivpn":
    serveur = serveur.rpartition(":")[0] + ":" + sys.argv[2]
print("--emballage", reglages["emballage"], "--serveur", serveur, sep="\n")
if reglages["emballage"] == "ivpn":
    print("--cible", reglages["cible"], "--uuid", reglages["uuid"], sep="\n")
PY
)
[ "${#PONT_ARGS[@]}" -ge 4 ] || exit 1
EMBALLAGE=${PONT_ARGS[1]}
if [ -z "$CLE_PUBLIQUE" ] || [ -z "$ADRESSE" ] || [ -z "$SERVEUR" ]; then
    echo "Configuration incomplète : $CONF" >&2; exit 1
fi

# Dossier court : un chemin de socket Unix ne dépasse pas 107 octets.
TRAVAIL=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/essai-wg.XXXXXX")
chmod 700 "$TRAVAIL"
TOR_PID=
nettoyer() {
    if [ -n "$TOR_PID" ]; then kill "$TOR_PID" 2>/dev/null || true; fi
    rm -rf "$TRAVAIL"
}
trap nettoyer EXIT
( umask 077; champ PrivateKey > "$TRAVAIL/cle" )
# wg recopie une clé mal formée dans son message d'erreur : on vérifie avant.
grep -qxE '[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=' "$TRAVAIL/cle" \
    || { echo "Clé privée absente ou mal formée dans $CONF (non affichée)." >&2; exit 1; }

if [ -n "${SOCKS:-}" ]; then
    echo "── Tor déjà lancé : $SOCKS"
else
echo "── Tor privé (sans root) ────────────────────────────────────────"
SOCKS="unix:$TRAVAIL/socks"
tor --quiet --SocksPort "unix:$TRAVAIL/socks" --DataDirectory "$TRAVAIL/tor" \
    --Log "notice file $TRAVAIL/tor.log" --ControlPort 0 &
TOR_PID=$!
for _ in $(seq 120); do
    grep -q "Bootstrapped 100%" "$TRAVAIL/tor.log" 2>/dev/null && break
    kill -0 "$TOR_PID" 2>/dev/null || { cat "$TRAVAIL/tor.log"; exit 1; }
    sleep 1
done
grep -q "Bootstrapped 100%" "$TRAVAIL/tor.log" \
    || { echo "Tor n'a pas fini de démarrer." >&2; tail "$TRAVAIL/tor.log"; exit 1; }
echo "Tor prêt."
fi

echo "── Espace isolé : WireGuard → pont ($EMBALLAGE) → Tor → serveur ──"
echo "nameserver $DNS" > "$TRAVAIL/resolv.conf"
export TRAVAIL CLE_PUBLIQUE ADRESSE SOCKS
export PONT_ARGS_TXT="${PONT_ARGS[*]}"
# shellcheck disable=SC2016  # développé par le bash de l'espace isolé
unshare -rnm bash -euo pipefail -c '
    mount --bind "$TRAVAIL/resolv.conf" /etc/resolv.conf
    # Le profil AppArmor de wg (Ubuntu) ne lui laisse lire que /etc/wireguard.
    mount --bind "$TRAVAIL" /etc/wireguard
    ip link set lo up
    ip link add wgkt type wireguard
    wg set wgkt private-key /etc/wireguard/cle \
        peer "$CLE_PUBLIQUE" endpoint 127.0.0.1:51820 \
        allowed-ips 0.0.0.0/0 persistent-keepalive 25
    ip addr add "$ADRESSE" dev wgkt
    ip link set wgkt mtu 1280 up
    ip route add default dev wgkt

    read -ra PONT_ARGS <<< "$PONT_ARGS_TXT"
    python3 pont_wg.py "${PONT_ARGS[@]}" --socks "$SOCKS" \
        > >(sed "s/^/  [pont] /") 2>&1 &
    PONT=$!
    trap "kill $PONT 2>/dev/null || true" EXIT

    echo "Attente de la poignée de main WireGuard (60 s au plus)…"
    for _ in $(seq 60); do
        [ "$(wg show wgkt latest-handshakes | cut -f2)" != 0 ] && break
        sleep 1
    done
    if [ "$(wg show wgkt latest-handshakes | cut -f2)" = 0 ]; then
        echo "ÉCHEC : aucune poignée de main."
        exit 1
    fi
    echo "Poignée de main réussie."
    echo "IP vue depuis Internet :"
    curl -sS --max-time 30 https://api.ipify.org; echo
    echo "Débit (descente de 10 Mo) :"
    curl -sS --max-time 120 -o /dev/null \
        -w "  %{size_download} octets en %{time_total} s\n" \
        https://proof.ovh.net/files/10Mb.dat || true
    wg show wgkt | grep -E "handshake|transfer" | sed "s/^ */  /"
'
