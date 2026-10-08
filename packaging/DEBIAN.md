# Entrer dans Debian (puis Ubuntu)

Un paquet accepté dans Debian est recopié automatiquement dans Ubuntu
(dépôt *universe*) à la version suivante. Il apparaît alors dans le Centre
d'applications d'Ubuntu et dans GNOME Software, grâce à la fiche AppStream
déjà livrée (`packaging/org.katakomba.Katakomba.metainfo.xml`).

Le `.deb` actuel (`packaging/build-deb.sh`) fonctionne, mais il ne respecte
pas la *Debian Policy* : il ne peut pas être proposé tel quel. Ce document
liste ce qu'il faut changer, puis la démarche.

---

## 1. Changements nécessaires dans Katakomba

Ce ne sont pas que des fichiers d'empaquetage : la façon dont Katakomba
s'installe doit changer. Chaque point doit garder la migration automatique
des installations existantes (depuis `/opt/katakomba`).

| # | Aujourd'hui | Exigence Debian | À faire |
|---|---|---|---|
| 1 | Code déployé dans `/opt/katakomba` | `/opt` est interdit aux paquets de la distribution (FHS, Policy §9.1.1) | Code dans `/usr/share/katakomba` ; `katakomba-cli.sh`, l'unité systemd et `install.sh` suivent |
| 2 | `providers/` inscriptible par le groupe, **dans** le répertoire du code | `/usr` est en lecture seule ; les données vont dans `/etc` ou `/var/lib` | `providers/` vers `/etc/katakomba/providers` (`PROVIDERS_DIR` dans `constants.py`) |
| 3 | Le `postinst` lance `install.sh`, qui **génère** l'unité systemd, le hook de veille, le nettoyage iptables | Les fichiers sont livrés par le paquet ; les scripts de maintenance restent minimaux | Unité `katakomba.service`, hook de veille et script de nettoyage livrés tels quels, installés par `dh_installsystemd` |
| 4 | `install.sh` **désactive le service `tor`** du système (conflit sur le port 9050) | Un paquet ne modifie jamais la configuration d'un autre paquet | Tor du daemon sur des ports dédiés (par exemple 9060/9061) : il cohabite avec le `tor` du système, plus rien à désactiver |
| 5 | Groupe `katakomba` et répertoires créés par `install.sh` | Mécanismes déclaratifs | `debian/katakomba.sysusers` (groupe), `debian/katakomba.tmpfiles` (`/etc/katakomba` en 2770, `/var/lib/katakomba`) |
| 6 | `postrm` efface `/opt/katakomba` | Plus de `/opt` | Purge limitée à `/etc/katakomba` et `/var/lib/katakomba` |
| 7 | Pas de page de manuel | Chaque commande de `/usr/bin` devrait en avoir une (lintian) | `katakomba.1`, par exemple généré depuis l'aide du CLI |
| 8 | `Comment=` du lanceur en français par défaut | La valeur par défaut est en anglais | `Comment=` en anglais, `Comment[fr]=` en français |

La migration depuis l'ancien nom reste dans `install.sh` (installation
depuis les sources) : aucune version de Debian n'a jamais contenu l'ancien
paquet, le paquet Debian n'en a pas besoin.

## 2. Le dossier `debian/`

À créer une fois les changements ci-dessus faits :

- `debian/control` : `debhelper-compat (= 13)`, `Rules-Requires-Root: no`,
  `Standards-Version` courante, mêmes dépendances que `packaging/control.in`
- `debian/rules` : `dh $@`, tests lancés par `dh_auto_test`
  (`python3 -m unittest discover -s tests -t .`)
- `debian/copyright` au format DEP-5 (GPL-3.0-or-later)
- `debian/changelog` (`dch --create`), `debian/watch` sur les tags GitHub,
  `debian/upstream/metadata`
- `debian/tests/control` : autopkgtest qui relance la suite de tests sur
  le paquet installé
- Construction propre dans un environnement isolé (`sbuild` ou `pbuilder`),
  puis `lintian -I --pedantic` sans erreur ni avertissement

## 3. La démarche

1. **Déclarer l'intention** : envoyer la demande ITP ci-dessous (`reportbug
   wnpp`, ou un e-mail à `submit@bugs.debian.org`). Elle reçoit un numéro de
   bogue, à citer dans `debian/changelog` (`Closes: #NNNNNN`).
2. **Trouver une équipe** : l'équipe *Debian Privacy Maintainers*
   (`pkg-privacy-team` sur salsa.debian.org) maintient déjà des outils autour
   de Tor. Y entrer facilite la relecture et le parrainage.
3. **Publier sur mentors.debian.net**, puis ouvrir une demande de parrainage
   (bogue *RFS* contre le pseudo-paquet `sponsorship-requests`).
4. **Relecture par un développeur Debian** (*sponsor*), corrections, puis
   envoi dans la file *NEW* : les *ftpmasters* vérifient surtout les licences.
   Comptez des semaines à quelques mois.
5. **Ubuntu** : la synchronisation est automatique jusqu'au gel des imports
   d'Ubuntu (environ deux mois avant chaque version d'avril et d'octobre).
   Une version LTS déjà sortie ne le reçoit pas, sauf par les *backports*.

**À anticiper** : l'association de Tor et d'un VPN est souvent discutée dans
la communauté Tor. La description du paquet et la demande ITP doivent dire
clairement pour quel usage c'est conçu (cacher l'adresse réelle au
fournisseur VPN, sortir sur Internet par une adresse VPN stable plutôt que
par un nœud de sortie Tor).

---

## Brouillon de la demande ITP

À envoyer **depuis votre propre adresse**, une fois les points 1 à 8
avancés. Remplacer `<ADRESSE>`.

```
To: submit@bugs.debian.org
Subject: ITP: katakomba -- route all traffic through OpenVPN tunnelled inside Tor

Package: wnpp
Severity: wishlist
Owner: Sévag Derboghossian <ADRESSE>
X-Debbugs-Cc: debian-devel@lists.debian.org

* Package name    : katakomba
  Version         : 3.7.2
  Upstream Contact: Sévag Derboghossian <ADRESSE>
* URL             : https://github.com/Derbosoft/Katakomba
* License         : GPL-3.0+
  Programming Lang: Python, Bash
  Description     : route all traffic through OpenVPN tunnelled inside Tor

 Katakomba routes all of the machine's traffic through OpenVPN, whose
 connection itself travels through the Tor network: the VPN provider sees a
 Tor exit node, never the user's real address, while websites see a stable
 VPN address instead of a Tor exit node.
 .
 A systemd service manages Tor, OpenVPN, DNS (through systemd-resolved),
 IPv6 blocking and reconnection, with failover between accounts and
 providers. A GTK 4 / libadwaita interface includes a setup wizard that
 adapts the provider's OpenVPN configuration for Tor, and a CLI provides
 status and read-only diagnostics.

Why this package: to my knowledge, no package in Debian sets up OpenVPN
over Tor; doing it by hand requires protecting the routes to the Tor guards,
handling DNS on the tunnel and recovering from circuit failures, which
Katakomba automates. The
OpenVPN and torrc files it consumes as root go through allowlists, and Tor
runs unprivileged.

Upstream ships a test suite of over 600 unit tests that never touch the
system, run as autopkgtest. I am the upstream author and intend to maintain
the package, ideally within the Debian Privacy Maintainers team; I am
looking for a sponsor.
```
