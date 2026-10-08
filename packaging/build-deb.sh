#!/usr/bin/env bash
# Construit le paquet Debian/Ubuntu :
#
#     bash packaging/build-deb.sh
#     → dist/katakomba_<version>_all.deb
#
# Aucun droit root nécessaire.  Installation :
#     sudo apt install ./dist/katakomba_<version>_all.deb
#
# Le champ Maintainer vient de DEB_MAINTAINER, sinon de git config
# (user.name / user.email) — il est visible de quiconque inspecte le paquet.
set -euo pipefail
umask 022

RACINE="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(python3 -B -c "import sys; sys.path.insert(0, '$RACINE'); from constants import VERSION; print(VERSION)")"
MAINTAINER="${DEB_MAINTAINER:-$(git -C "$RACINE" config user.name 2>/dev/null || echo "Katakomba") <$(git -C "$RACINE" config user.email 2>/dev/null || echo "root@localhost")>}"

# Mêmes fichiers que le déploiement d'install.sh (vérifié par les tests).
FICHIERS_CODE=(constants.py main.py validation.py adaptation.py i18n.py daemon gui assets polkit po
               repair_network.sh katakomba-cli.sh install.sh uninstall.sh template.ovpn
               LICENSE README.md README.fr.md)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
P="$TMP/katakomba"
OPT="$P/opt/katakomba"

install -d "$P/DEBIAN" "$OPT" "$P/usr/bin" "$P/usr/share/applications" \
           "$P/usr/share/doc/katakomba"
for f in "${FICHIERS_CODE[@]}"; do
    cp -r "$RACINE/$f" "$OPT/"
done
find "$OPT" -name __pycache__ -prune -exec rm -rf {} +
find "$OPT" -type d -exec chmod 755 {} +
find "$OPT" -type f -exec chmod 644 {} +
chmod 755 "$OPT/repair_network.sh" "$OPT/katakomba-cli.sh" "$OPT/install.sh" \
          "$OPT/uninstall.sh"

install -m 755 "$RACINE/katakomba-cli.sh" "$P/usr/bin/katakomba"
install -m 644 "$RACINE/packaging/org.katakomba.Katakomba.desktop" "$P/usr/share/applications/"
# Fiche des centres d'applications (description, captures, versions).
install -D -m 644 "$RACINE/packaging/org.katakomba.Katakomba.metainfo.xml" \
        "$P/usr/share/metainfo/org.katakomba.Katakomba.metainfo.xml"
install -D -m 644 "$RACINE/polkit/50-katakomba.rules" \
        "$P/usr/share/polkit-1/rules.d/50-katakomba.rules"
install -D -m 644 "$RACINE/polkit/org.katakomba.policy" \
        "$P/usr/share/polkit-1/actions/org.katakomba.policy"
install -D -m 644 "$RACINE/assets/katakomba.svg" \
        "$P/usr/share/icons/hicolor/scalable/apps/katakomba.svg"
install -m 644 "$RACINE/LICENSE" "$P/usr/share/doc/katakomba/copyright"

for s in postinst prerm postrm; do
    install -m 755 "$RACINE/packaging/$s" "$P/DEBIAN/$s"
done
# Répertoires en 755, quel que soit l'umask de qui construit le paquet.
find "$P" -type d -exec chmod 755 {} +
TAILLE="$(du -sk --exclude=DEBIAN "$P" | cut -f1)"
sed -e "s|@VERSION@|$VERSION|" -e "s|@MAINTAINER@|$MAINTAINER|" \
    -e "s|@TAILLE@|$TAILLE|" "$RACINE/packaging/control.in" > "$P/DEBIAN/control"

mkdir -p "$RACINE/dist"
SORTIE="$RACINE/dist/katakomba_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$P" "$SORTIE" >/dev/null
echo "Paquet construit : $SORTIE"
echo "Installation     : sudo apt install $SORTIE"
