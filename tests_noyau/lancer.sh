#!/usr/bin/env bash
# Vérifications sur un vrai noyau : vraies routes, vraies règles iptables,
# vraies connexions, vrai binaire OpenVPN — dans un espace réseau neuf, jamais
# celui de la machine.  En root (CI) : « unshare -n ».  Sans root : espace
# utilisateur en plus (« unshare -rn »), si le noyau le permet.
#
#   bash tests_noyau/lancer.sh            # tout
#   bash tests_noyau/lancer.sh -v         # détail
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1

if ! command -v unshare >/dev/null; then
    echo "unshare introuvable (paquet util-linux)." >&2
    exit 1
fi
if [ "$(id -u)" = 0 ]; then
    ISOLER=(unshare -n)
else
    ISOLER=(unshare -rn)
fi
# L'espace réseau d'où l'on part : les tests refusent de tourner dedans.
KATAKOMBA_NS_HOTE=$(readlink /proc/self/ns/net) \
KATAKOMBA_NOYAU=1 \
    exec "${ISOLER[@]}" python3 -m unittest discover -s tests_noyau -t . "$@"
