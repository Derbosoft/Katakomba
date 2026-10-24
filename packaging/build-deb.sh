#!/usr/bin/env bash
# Construit les deux paquets Debian/Ubuntu, depuis le même code :
#
#     bash packaging/build-deb.sh
#     → dist/katakomba_<version>_all.deb           avec interface graphique
#     → dist/katakomba-headless_<version>_all.deb  sans interface (serveurs)
#
# Les deux s'excluent (Conflicts/Replaces) : installer l'un remplace l'autre,
# réglages conservés.  Aucun droit root nécessaire.  Installation :
#     sudo apt install ./dist/katakomba_<version>_all.deb
#
# Construction reproductible (v3.11.0) : le même commit donne, avec les mêmes
# outils, des paquets identiques à l'octet près — dates fixées à celle du
# commit (SOURCE_DATE_EPOCH), propriétaires et droits normalisés, taille
# calculée sur le contenu.  Les versions publiées sont construites par la CI
# (.github/workflows/publication.yml) ; chacun peut les reconstruire et
# comparer.
#
# Le champ Maintainer est visible de quiconque inspecte le paquet (apt show) :
# fixe, sous pseudonyme, et jamais repris de l'auteur du commit — une
# identité git mal réglée finirait sinon dans un paquet publié.
# DEB_MAINTAINER le remplace au besoin.
set -euo pipefail
umask 022

RACINE="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(python3 -B -c "import sys; sys.path.insert(0, '$RACINE'); from constants import VERSION; print(VERSION)")"
MAINTAINER="${DEB_MAINTAINER:-Derbo <200386924+Derbosoft@users.noreply.github.com>}"
# Date du commit : celle de chaque fichier du paquet et de l'archive.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$RACINE" log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH

# Mêmes fichiers que le déploiement d'install.sh (vérifié par les tests).
FICHIERS_CODE=(constants.py main.py console.py validation.py adaptation.py i18n.py daemon gui
               assets polkit po repair_network.sh katakomba-cli.sh install.sh uninstall.sh
               template.ovpn LICENSE README.md README.fr.md)

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
mkdir -p "$RACINE/dist"

# Contrôle et archive d'un paquet : $1 = arborescence, $2 = modèle de contrôle.
emballer() {
    local racine="$1" modele="$2" nom
    nom="$(sed -n 's/^Package: //p' "$modele")"
    # Répertoires en 755, quel que soit l'umask de qui construit le paquet.
    find "$racine" -type d -exec chmod 755 {} +
    # Taille installée calculée comme dpkg-gencontrol : Kio arrondis par
    # fichier, 1 par entrée non régulière.  « du » dépendait du système de
    # fichiers de construction (tmpfs, ext4) : paquets différents.
    local taille
    taille="$(find "$racine" -path "$racine/DEBIAN" -prune -o -mindepth 1 -printf '%y %s\n' \
              | awk '{ t += ($1 == "f") ? int(($2 + 1023) / 1024) : 1 } END { print t + 0 }')"
    sed -e "s|@VERSION@|$VERSION|" -e "s|@MAINTAINER@|$MAINTAINER|" \
        -e "s|@TAILLE@|$taille|" "$modele" > "$racine/DEBIAN/control"
    find "$racine" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    local sortie="$RACINE/dist/${nom}_${VERSION}_all.deb"
    dpkg-deb --root-owner-group -Zxz --build "$racine" "$sortie" >/dev/null
    echo "Paquet construit : $sortie"
}

# Sans interface : même arborescence, privée de tout ce qui ne sert qu'à
# l'interface (GTK, lanceur, fiche AppStream, icône, polkit).  Du dossier
# gui/, seul le modèle reste : la console (console.py) s'en sert.  Même
# contenu qu'une installation « install.sh --sans-interface ».
H="$TMP/katakomba-headless"
cp -a "$P" "$H"
rm -rf "$H/opt/katakomba/main.py" "$H/opt/katakomba/assets" "$H/opt/katakomba/polkit" \
       "$H/usr/share/applications" "$H/usr/share/metainfo" "$H/usr/share/polkit-1" \
       "$H/usr/share/icons"
find "$H/opt/katakomba/gui" -mindepth 1 -maxdepth 1 ! -name modele.py ! -name __init__.py \
     -exec rm -rf {} +
install -d "$H/usr/share/doc/katakomba-headless"
mv "$H/usr/share/doc/katakomba/copyright" "$H/usr/share/doc/katakomba-headless/"
rmdir "$H/usr/share/doc/katakomba"

emballer "$P" "$RACINE/packaging/control.in"
emballer "$H" "$RACINE/packaging/control-headless.in"
echo "Installation     : sudo apt install ./dist/katakomba_${VERSION}_all.deb"
echo "Sans interface   : sudo apt install ./dist/katakomba-headless_${VERSION}_all.deb"
