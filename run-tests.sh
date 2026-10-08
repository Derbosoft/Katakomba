#!/usr/bin/env bash
# Katakomba — suite de tests
#
# Usage :  bash run-tests.sh            (tout)
#          bash run-tests.sh -v         (détail test par test)
#          bash run-tests.sh tests.test_openvpn
#
# La suite n'exécute AUCUNE commande système : iptables, ip, resolvectl,
# systemctl, openvpn et tor sont interceptés.  Elle est donc sans danger sur
# la machine de production, tunnel monté.  Une empreinte réseau est relevée
# avant et après pour le prouver.
set -uo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

if ! command -v python3 &>/dev/null; then
    echo "python3 introuvable." >&2
    exit 1
fi

empreinte() {
    {
        ip -4 route show 2>/dev/null
        ip -4 rule show 2>/dev/null
        ip -br link show 2>/dev/null
        resolvectl status 2>/dev/null | grep -E 'DNS Servers|DNS Domain|Default Route'
    } | sort
}

echo "── Empreinte réseau avant ──────────────────────────────"
AVANT="$(empreinte)"
echo "$AVANT" | wc -l | xargs printf "  %s lignes d'état relevées\n"
echo

ARGS=("$@")
if [ ${#ARGS[@]} -eq 0 ]; then
    ARGS=("discover" "-s" "tests" "-t" ".")
fi

echo "── Exécution ───────────────────────────────────────────"
python3 -W ignore::ResourceWarning -m unittest "${ARGS[@]}"
RC=$?

echo
echo "── Empreinte réseau après ──────────────────────────────"
APRES="$(empreinte)"
if [ "$AVANT" == "$APRES" ]; then
    echo "  Identique : la suite n'a rien modifié sur la machine."
else
    echo "  ⚠  L'ÉTAT RÉSEAU A CHANGÉ pendant les tests :"
    diff <(echo "$AVANT") <(echo "$APRES") | sed 's/^/    /'
    echo "  (un changement d'IP de tunnel ou de compteur peut être normal si"
    echo "   le daemon a reconnecté pendant l'exécution — vérifiez le diff)"
    RC=1
fi

echo
if [ $RC -eq 0 ]; then
    echo "═══ SUITE VERTE ═══"
else
    echo "═══ ÉCHEC (code $RC) ═══"
fi
exit $RC
