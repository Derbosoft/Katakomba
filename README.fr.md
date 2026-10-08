<p align="center"><img src="assets/katakomba-banniere.png" alt="Katakomba — Svb terra liberi" width="720"></p>

# Katakomba — v3.7.1

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-orange?logo=linux)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue)](LICENSE)
![Version](https://img.shields.io/badge/Version-3.7.1-blue)
[![Tests](https://github.com/Derbosoft/Katakomba/actions/workflows/tests.yml/badge.svg)](https://github.com/Derbosoft/Katakomba/actions/workflows/tests.yml)
[![Download](https://img.shields.io/github/v/release/Derbosoft/Katakomba?label=Download%20.deb&logo=debian)](https://github.com/Derbosoft/Katakomba/releases/latest)
![Systemd](https://img.shields.io/badge/Systemd-service-lightgrey?logo=linux)

> [English documentation](README.md)

Daemon + interface graphique pour router **tout le trafic réseau via OpenVPN tunnelé dans Tor** sur Ubuntu/Debian. Le daemon tourne en arrière-plan en tant que service systemd et gère automatiquement Tor, OpenVPN, le blocage IPv6, le partage LAN et la surveillance de connectivité.

*Katakomba s'appelait auparavant « Tor-VPN Manager » : une installation existante est migrée automatiquement (voir [Migration depuis Tor-VPN Manager](#migration-depuis-tor-vpn-manager)).*

---

## Table des matières

1. [Architecture globale](#architecture-globale)
2. [Prérequis](#prérequis)
3. [Installation](#installation)
4. [Structure du projet](#structure-du-projet)
5. [Interface graphique](#interface-graphique)
6. [CLI `katakomba`](#cli-katakomba)
7. [Fonctionnement détaillé du daemon](#fonctionnement-détaillé-du-daemon)
8. [Chaînes iptables](#chaînes-iptables)
9. [Failover et watchdog](#failover-et-watchdog)
10. [Partage LAN](#partage-lan)
11. [DNS split — Domaines locaux](#dns-split--domaines-locaux)
12. [Configuration Tor (torrc)](#configuration-tor-torrc)
13. [Réparation réseau automatique](#réparation-réseau-automatique)
14. [Format config.json](#format-configjson)
15. [Tests](#tests)
16. [Traductions](#traductions)
17. [Sécurité](#sécurité)
18. [Premiers pas](#premiers-pas)
19. [Désinstallation](#désinstallation)

---

## Architecture globale

```
Utilisateur
    │
    ├── katakomba gui          ──►  GUI (main.py → gui/app.py)
    │                              • Lit/écrit config.json et torrc
    │                              • Pilote le service via polkit
    │                              • Veille en arrière-plan, notifie les coupures
    │                              • Ne touche jamais aux processus réseau
    │
    ├── katakomba <commande>   ──►  CLI wrapper (/usr/local/bin/katakomba)
    │                              • Appelle systemctl
    │
    └── systemd              ──►  katakomba.service
                                   │
                                   └── daemon/  (root)
                                         │
                                         ├── Tor  (subprocess, port 9050/9051)
                                         │         └── torrc optionnel
                                         │
                                         ├── OpenVPN ──► SOCKS5 127.0.0.1:9050 ──► Tor ──► Internet
                                         │              (tunX, redirect-gateway)
                                         │
                                         ├── iptables  (IPv6 block, LAN sharing)
                                         │
                                         └── Watchdog  (connectivité)


Flux réseau complet :
  Application → tunX → OpenVPN → SOCKS5:9050 → Tor → Relais Tor → Serveur VPN → Internet
```

Le GUI et le daemon sont **entièrement découplés** : le GUI écrit uniquement des fichiers de configuration et invoque systemd. Il ne surveille aucun processus et ne peut pas interférer avec la connexion active.

---

## Prérequis

| Composant | Version minimale | Rôle |
|-----------|-----------------|------|
| Ubuntu / Debian | 24.04 / 13 | Système de base |
| Python | 3.8+ | Daemon + GUI |
| GTK 4 + libadwaita | 1.5+ | Interface graphique (`python3-gi`, `python3-gi-cairo`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, `librsvg2-common`) |
| tor | — | Proxy SOCKS5 et réseau Tor |
| openvpn | 2.4+ | Tunnel chiffré vers le fournisseur VPN |
| dnsmasq | — | **Optionnel** — serveur DHCP, uniquement pour le partage LAN |
| curl | — | Mesure de débit et tests de connectivité |
| systemd + systemd-resolved | — | Gestion du service et DNS |

---

## Installation

### Par paquet `.deb` (recommandé)

Téléchargez `katakomba_<version>_all.deb` depuis la **[dernière version publiée](https://github.com/Derbosoft/Katakomba/releases/latest)**, puis :

```bash
sudo apt install ./katakomba_<version>_all.deb
```

`apt` installe les dépendances et configure tout. Ouvrez ensuite « Katakomba » dans le menu des applications : l'assistant prend le relais (voir *Premiers pas*). Les administrateurs de la machine (groupe `sudo`) reçoivent l'accès à l'interface. Pour un autre compte : `sudo katakomba autoriser <utilisateur>`.

> **Juste après l'installation**, fermez puis rouvrez votre session : elle a été ouverte avant que votre compte reçoive l'accès. L'interface le signale si besoin. Sur les distributions qui fournissent `sg` (Debian notamment), `katakomba gui` s'en charge sans reconnexion.

**Construire le paquet** depuis les sources, sans root :
```bash
bash packaging/build-deb.sh          # → dist/katakomba_<version>_all.deb
```
Le champ `Maintainer` vient de `DEB_MAINTAINER`, ou à défaut de `git config user.name` / `user.email`. Il est visible de quiconque inspecte le paquet.

Le paquet réutilise `install.sh` en « mode paquet » (`KATAKOMBA_PAQUET=1`, appelé par le `postinst`). Il n'existe donc qu'une seule procédure d'installation, et les deux voies configurent le système à l'identique.

### Depuis les sources

```bash
sudo bash install.sh
```

L'installateur effectue **7 étapes** :

**1. Dépendances**
```bash
apt install tor openvpn python3 curl python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 librsvg2-common
```
`dnsmasq` ne sert qu'au partage LAN (désactivé par défaut) : depuis la v3.6.1 il n'est installé que s'il est déjà présent ou si le partage est configuré, plutôt qu'installé puis désactivé aussitôt. Pour l'ajouter plus tard : `sudo apt install dnsmasq`.

> **`KATAKOMBA_SKIP_APT=1` — rejouer l'installeur sans réseau (v3.6.3).** Utile quand seule l'unité systemd ou le CLI a changé sur une machine déjà installée, d'autant que le seul chemin réseau disponible peut être le tunnel que ce daemon est justement en train de monter.
>
> ```bash
> sudo KATAKOMBA_SKIP_APT=1 bash install.sh
> ```
>
> Le garde n'est pas une simple dérogation : il **vérifie que toutes les dépendances sont présentes** (`tor`, `openvpn`, `python3`, `curl`, GTK 4 et libadwaita 1.5+) et **refuse de continuer** sinon. Sauter `apt` sur une machine incomplète produirait une installation à moitié fonctionnelle, plus difficile à diagnostiquer qu'un échec franc.

**2. Répertoire de configuration**
- Crée `/etc/katakomba/` en `root:katakomba 2770` (groupe katakomba : GUI sans root)
- Crée `/var/lib/katakomba/` (`root`, 0755) et y déplace les données Tor d'une version antérieure (guards conservés)
- Installe un **torrc par défaut** (circuits longs et stables) s'il n'en existe pas déjà un — un torrc personnalisé n'est jamais écrasé
- Migration automatique si une config d'avant la v3.2 existe dans `/root/.config/tor-vpn-manager/` ou `/opt/tor-vpn-manager/`
- Aucune écriture en root à travers un lien symbolique posé dans ce répertoire (que le groupe peut modifier)

**3. Code du programme (v3.7.0)**
- Copie le programme dans `/opt/katakomba`, propriété de `root:root` ; seul `providers/` y reste inscriptible par le groupe `katakomba`
- Reprend les `.ovpn` de l'ancien `providers/` sans rien écraser, et rend relatifs les chemins `.ovpn` absolus de `config.json`

> **Pourquoi.** Jusqu'à la v3.6.4, le service exécutait le code **depuis le clone de l'utilisateur**. N'importe quel programme lancé sous ce compte pouvait réécrire `daemon/*.py` et obtenir root au redémarrage suivant, sans mot de passe. **Après une modification du code source, relancez `sudo bash install.sh`** : le service exécute la copie de `/opt`, pas le clone.

**4. Services système**
- Active et démarre `systemd-resolved`
- **Désactive** et **arrête** le service `tor` système — le daemon gère Tor directement en subprocess pour contrôler précisément son démarrage, ses logs et son redémarrage

**5. Service systemd**
Crée `/etc/systemd/system/katakomba.service` :
- `ExecStartPre` : script de nettoyage iptables (efface les règles orphelines d'une session précédente)
- `ExecStart` : `python3 -m daemon` lancé depuis `/opt/katakomba`
- `ExecStopPost` : même script de nettoyage
- `Restart=on-failure` avec un délai de 20s, tentatives illimitées (`StartLimitIntervalSec=0`)
- `Type=notify` + `WatchdogSec=90` : le daemon signale sa vivacité toutes les ~3s ; s'il gèle (deadlock), systemd le tue et le relance
- `KillMode=control-group` : systemd tue tout le groupe (Tor, OpenVPN, dnsmasq inclus)
- `TimeoutStopSec=30`
- `RestartPreventExitStatus=78` : sans fournisseur configuré, le daemon sort en 78 et n'est pas relancé toutes les 20 s
- `RuntimeDirectory=katakomba` (0700) : `auth.tmp`, copies validées du `.ovpn` et du torrc, pid de dnsmasq — supprimé par systemd à l'arrêt, même après un crash
- Durcissement : `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=full` avec `ReadWritePaths` limité à `/etc/katakomba` et `/etc/systemd/resolved.conf.d`

**6. Hook veille/réveil**
Installe `/lib/systemd/system-sleep/katakomba-sleep` : redémarre automatiquement le daemon 3 secondes après chaque réveil de veille ou hibernation — **s'il tournait** (`try-restart` depuis la v3.7.0 ; `restart` démarrait aussi un service arrêté exprès). Sans ce hook, les circuits Tor sont périmés au réveil mais le port 9050 reste ouvert, ce qui amène OpenVPN à se reconnecter sans passer par Tor.

**7. CLI et lanceur GUI**
- Installe `/usr/local/bin/katakomba` (copie de `katakomba-cli.sh`)
- Installe l'icône et crée `/usr/share/applications/org.katakomba.Katakomba.desktop` (menu des applications, sans démarrage automatique). Il porte l'identifiant de l'application : sans cela, GNOME n'afficherait pas ses notifications. L'ancien `katakomba.desktop` est retiré
- Installe la règle polkit `/usr/share/polkit-1/rules.d/50-katakomba.rules` (connexion et déconnexion sans mot de passe pour le groupe `katakomba`) et les invites de `/usr/share/polkit-1/actions/org.katakomba.policy`

### Migration depuis Tor-VPN Manager

Katakomba s'appelait « Tor-VPN Manager » jusqu'à la v3.7.0. `install.sh` (et le paquet `.deb`, qui remplace l'ancien paquet `tor-vpn-manager`) reprend une installation existante sans rien perdre :

| Ancien | Nouveau |
|---|---|
| service `tor-vpn-manager` | service `katakomba` (redémarré si l'ancien tournait) |
| commande `tor-vpn` | commande `katakomba` |
| groupe `torvpn` | groupe `katakomba` — **même GID** : membres conservés, sessions ouvertes sans reconnexion |
| `/etc/tor-vpn-manager` | `/etc/katakomba` (réglages, comptes, torrc) |
| `/var/lib/tor-vpn-manager` | `/var/lib/katakomba` (données Tor : les guards sont conservés) |
| `/opt/tor-vpn-manager/providers` | `/opt/katakomba/providers` |
| sauvegardes `.tvpn` | sauvegardes `.katakomba` (les `.tvpn` restent importables) |

L'ancien service est arrêté en premier : son nettoyage retire ses règles iptables, son DNS split et son dnsmasq. Les chemins écrits en dur (`.ovpn` absolus dans `config.json`, `DataDirectory` du torrc) sont réécrits, sans jamais suivre un lien symbolique. L'ancienne unité, le hook de veille, la commande `tor-vpn` (seulement si c'est bien la nôtre) et le lanceur sont retirés.

> **Pare-feu en amont qui bloque tout trafic hors tunnel :** pendant la migration, le tunnel est coupé, donc `apt` ne peut rien télécharger. Les dépendances étant déjà installées, lancez : `sudo KATAKOMBA_SKIP_APT=1 bash install.sh`

---

## Structure du projet

```
katakomba/
├── main.py              Point d'entrée de l'interface (lance gui/app.py)
├── constants.py         Constantes partagées interface + daemon (chemins, config par défaut)
├── validation.py        Listes blanches des directives .ovpn et des options torrc (daemon + GUI)
├── adaptation.py        Adaptation automatique d'un .ovpn de fournisseur (GUI)
├── i18n.py              Traductions : choix de la langue, lecture des catalogues po/
├── install.sh           Script d'installation Ubuntu/Debian (sources, ou mode paquet)
├── uninstall.sh         Désinstallation (katakomba uninstall, prerm du paquet)
├── packaging/           Paquet .deb : build-deb.sh, control, postinst/prerm/postrm, lanceur
├── repair_network.sh    Script de réparation réseau (nettoyage iptables, routes, DNS)
├── katakomba-cli.sh     Source du CLI — copié dans /usr/local/bin/katakomba par install.sh
├── template.ovpn        Modèle commenté pour créer un fichier .ovpn compatible
├── run-tests.sh         Lanceur de la suite de tests (+ empreinte réseau avant/après)
├── assets/              Logo (SVG + PNG), emblème, bannière, icônes symboliques (icones/)
├── polkit/              Règle polkit (connexion sans mot de passe) et invites des actions privilégiées
├── po/                  Catalogues de traduction (en, es, de, it, pt) et modèle katakomba.pot
├── outils/              Outils de développement : catalogues (traductions.py), icônes (icones.py)
│
├── daemon/              Package daemon (lancé par systemd via python3 -m daemon)
│   ├── __init__.py      Classe Daemon (agrège tous les mixins) + fonction main()
│   ├── __main__.py      Point d'entrée python3 -m daemon
│   ├── core.py          DaemonCore — état partagé, config, log, signaux, orchestration
│   ├── tor.py           TorMixin — démarrage/arrêt Tor, torrc optionnel, ControlPort
│   ├── network.py       NetworkMixin — gateway, SOCKS, protection routes Tor /32
│   ├── firewall.py      FirewallMixin — iptables/ip6tables, blocage IPv6, partage LAN, dnsmasq
│   ├── dns.py           DNSMixin — split DNS via systemd-resolved drop-in
│   ├── openvpn.py       OpenVPNMixin — boucle OpenVPN, failover fournisseurs
│   └── watchdog.py      WatchdogMixin — surveillance connectivité, redémarrage complet
│
├── gui/                 Interface graphique (GTK 4 + libadwaita)
│   ├── app.py           Application : thème, icônes, contrôle d'accès
│   ├── fenetre.py       Fenêtre : barre latérale, suivi du service, mode avancé
│   ├── modele.py        Logique sans interface (config, torrc, sauvegardes, service)
│   ├── veilleur.py      Quand prévenir d'une coupure (sans interface)
│   ├── outils.py        Dialogues, tâches de fond, choix de fichiers
│   ├── page_*.py        Pages : connexion, fournisseurs, réglages, diagnostic,
│   │                    journal, exclusions, partage LAN, Tor
│   ├── assistant.py     Assistant de configuration (premier lancement)
│   └── style.css        Couleurs Katakomba
│
├── tests/               Suite de tests (unittest, aucune dépendance externe)
│   ├── helpers.py       Daemon factice + interception des commandes système
│   ├── test_network.py      routes exclues, passerelle, protection des guards
│   ├── test_tor.py          parsing ControlPort, bootstrap, NEWNYM
│   ├── test_dns.py          DNS du VPN, split DNS, revérification périodique
│   ├── test_firewall.py     blocage IPv6, partage LAN, plage DHCP
│   ├── test_openvpn.py      identifiants, qualité de circuit, reconnexion
│   ├── test_watchdog.py     connectivité, filet anti-inertie, redémarrage
│   ├── test_config_status.py  chargement de config, socket de statut
│   ├── test_core_lifecycle.py ControlPort réel, nettoyage, arrêt propre
│   ├── test_modele.py       saisies, torrc, sauvegardes, état affiché, événements
│   ├── test_interface.py    vraie fenêtre GTK sur un faux système (ignoré sans écran)
│   ├── test_veilleur.py     notifications : coupures, reprises, arrêts, silences
│   ├── test_polkit.py       règle polkit exécutée contre un faux polkit, invites
│   ├── test_i18n.py         catalogues complets, choix de la langue, textes jamais figés
│   ├── test_validation.py   listes blanches .ovpn / torrc
│   ├── test_adaptation.py   adaptation automatique des fichiers de fournisseur
│   ├── test_scripts.py      syntaxe shell, unité systemd, cohérence des versions
│   └── test_safety.py       garde-fou : la suite ne touche pas au système
│
└── providers/           Dossier des fichiers .ovpn par fournisseur (non versionné)
    └── <NomFournisseur>/
        └── <fichier>.ovpn
```

**Fichiers générés à l'installation / à l'usage :**
```
/opt/katakomba/         Code déployé (root:root) ; providers/ en root:katakomba 2770

/etc/katakomba/         Écrit par le GUI (root:katakomba 2770) — jamais par le daemon
├── config.json               Configuration principale (mode 660)
└── torrc                     Configuration Tor personnalisée (mode 660, optionnel)

/run/katakomba/         Écrit par le daemon (root, 0700, volatil)
├── auth.tmp                  Credentials OpenVPN temporaires (créé/supprimé à chaque connexion)
├── openvpn.conf              Copie validée du .ovpn, lue par OpenVPN
├── torrc                     Copie validée du torrc, lue par Tor
└── dnsmasq.pid               Partage LAN

/var/lib/katakomba/     Écrit par le daemon (root, 0755, persistant)
├── tor-routes.txt        Routes /32 Tor actives (persistance inter-redémarrages)
└── tor_data/                 Données de Tor (debian-tor, 0700)

/etc/systemd/system/katakomba.service
/etc/systemd/resolved.conf.d/katakomba-split.conf   (si DNS split activé)
/lib/systemd/system-sleep/katakomba-sleep
/usr/local/bin/katakomba
/usr/local/lib/katakomba-cleanup.sh
/usr/share/applications/org.katakomba.Katakomba.desktop
/usr/share/icons/hicolor/scalable/apps/katakomba.svg
/usr/share/polkit-1/rules.d/50-katakomba.rules
/usr/share/polkit-1/actions/org.katakomba.policy

~/.config/katakomba/interface.json          Préférences de l'interface (propres au compte)
~/.config/autostart/org.katakomba.Katakomba.desktop   (si « Lancer à l'ouverture de session »)
```

---

## Interface graphique

<p align="center"><img src="assets/captures/connexion.png" alt="Écran Connexion de Katakomba" width="720"></p>

### Lancement

```bash
katakomba gui                  # avec votre utilisateur (groupe katakomba) — jamais avec sudo
katakomba gui --arriere-plan   # sans ouvrir la fenêtre (utilisé à l'ouverture de session)
python3 main.py                # lancement direct, depuis les sources
```

L'interface est écrite en **GTK 4 et libadwaita** et suit la présentation des applications GNOME : une barre latérale mène aux pages, et tout se replie en une seule colonne quand la fenêtre est étroite. Elle est toujours sombre et volontairement sobre : des gris neutres, avec une couleur par étape du trajet (vert, violet, bleu, ambre). Le mouvement ne montre que ce qui se passe vraiment : les étapes établies brillent doucement ; pendant une connexion, l'étape en cours tourne et respire (pour Tor, un anneau suit la progression de son démarrage) et chaque étape s'illumine au moment où elle s'établit ; connecté, un paquet parcourt le trajet de temps en temps. Les animations s'arrêtent quand la fenêtre est cachée et suivent le réglage « Réduire les animations » de GNOME.

**Six langues :** français, anglais, espagnol, allemand, italien et portugais (du Brésil). L'interface suit la langue du système ; **Réglages → Interface → Langue** en impose une autre, appliquée aussitôt, sans relancer. Une langue que Katakomba ne connaît pas donne l'anglais. Le diagnostic (`katakomba doctor`) suit la même langue. Le journal du service, lui, reste en français : c'est un document technique, cité tel quel dans un rapport. Les traductions ont été faites depuis le français ; une relecture par des locuteurs natifs est la bienvenue (voir [Traductions](#traductions)).

**Tout est enregistré aussitôt :** il n'y a plus de bouton « Sauvegarder ». Quand un réglage ne s'applique qu'au prochain démarrage du service, un bandeau propose **Redémarrer maintenant**. **Se connecter, se déconnecter et redémarrer ne demandent aucun mot de passe** aux membres du groupe `katakomba`, depuis leur session locale (règle polkit, voir [Sécurité](#sécurité)). La connexion au démarrage de l'ordinateur et la réparation du réseau demandent toujours le mot de passe administrateur. L'invite dit alors ce que Katakomba veut faire, au lieu d'un générique « exécuter … en superutilisateur ». Une invite annulée n'est pas une erreur.

Sans aucun fournisseur configuré, l'**assistant de configuration** s'ouvre d'office : fichier du fournisseur, identifiants, puis connexion suivie en direct. Il reste accessible par le bouton **Ajouter** de la page Fournisseurs et par le menu principal (☰).

**Mode simple / avancé :** par défaut, la barre latérale montre *Connexion*, *Fournisseurs*, *Réglages*, *Diagnostic* et *Journal*. **Mode avancé**, dans le menu principal, ajoute *Exclusions*, *Partage LAN*, *Tor* et les réglages de qualité du circuit. Le choix est mémorisé. Une installation qui utilise déjà ces réglages (exclusions, DNS local, partage LAN, seuil de circuit modifié) démarre en mode avancé : rien n'est caché à qui s'en sert.

### Arrière-plan et notifications

**Fermer la fenêtre ne quitte pas Katakomba** : l'interface continue de suivre la connexion et prévient par une notification du bureau :

| Situation | Notification |
|---|---|
| Tunnel coupé plus de 20 s | **Connexion perdue**, avec la raison (« perte de connectivité, relance d'OpenVPN »…), mise à jour si la raison change |
| Tunnel revenu après une alerte | **Connexion rétablie**, avec la durée de la coupure, à la place de l'alerte |
| Service arrêté sans que vous l'ayez demandé | **Katakomba est arrêté**, avec un bouton **Se connecter** |
| Première connexion, fenêtre fermée | **Katakomba est connecté**, avec le fournisseur |
| Pas de tunnel 2 min après le démarrage | **Connexion toujours en cours**, avec la raison |

Toutes les notifications occupent **le même emplacement** : chacune remplace la précédente, jamais de pile de messages périmés. Les reprises rapides (la médiane mesurée est de 12 s) restent silencieuses, tout comme ce que vous venez de demander vous-même (connexion, arrêt, redémarrage, réparation). Rien n'est notifié tant que vous regardez la fenêtre. Cliquer une notification rouvre la fenêtre.

Pour quitter vraiment : menu principal → **Quitter**. Rouvrir Katakomba depuis le menu des applications ramène la fenêtre cachée. Trois réglages, propres à chaque compte, se trouvent dans **Réglages → Interface** : continuer en arrière-plan, notifications, lancement caché à l'ouverture de session.

L'interface ne mesure rien elle-même : elle lit toutes les 3 s l'état que le daemon publie déjà sur son socket, sans aucun trafic réseau.

### Page Connexion

Une carte d'état en tête : **Connecté**, **Reconnexion…** avec sa raison (circuit trop lent, relance d'OpenVPN, redémarrage complet, compte refusé), **Déconnecté**, et un seul bouton pour se connecter ou se déconnecter.

Dans la carte, **le trajet du trafic** en quatre étapes : *Cet ordinateur* → *Réseau Tor* → *le VPN* (nommé d'après le fournisseur, avec le compte utilisé) → *Internet*. Chaque étape prend la couleur de son état : cyan quand elle fonctionne, violet pendant une connexion ou une reconnexion, gris à l'arrêt, rouge en erreur. Pendant une reconnexion, on voit donc d'un coup d'œil où ça coince : Tor encore prêt, VPN en cours. Dans une fenêtre étroite, le trajet passe à la verticale et le bouton sous l'état.

Dessous, quatre chiffres : **durée de connexion**, **débit du circuit Tor** (mesuré à la connexion, avec son âge), **reprises** depuis le démarrage du service (relances légères et redémarrages complets) et **IPv6** (bloqué ou non). Puis les **derniers événements**, traduits du journal. Rien de tout cela ne génère de trafic : c'est l'état que le daemon publie déjà.

Le point de couleur à côté de *Connexion*, dans la barre latérale, résume l'état depuis n'importe quelle page.

### Page Fournisseurs

<p align="center"><img src="assets/captures/fournisseurs.png" alt="Page Fournisseurs" width="720"></p>

Gère la liste des fournisseurs VPN et leurs comptes. L'ordre de la liste définit la priorité de connexion et de failover ; chaque fournisseur se déplie pour montrer son fichier et ses comptes.

**Fournisseur :**
- Nom libre (ex : ProtonVPN, Mullvad)
- Fichier `.ovpn` associé — **adapté automatiquement** puis enregistré dans `providers/<NomFournisseur>/` (voir ci-dessous)
- Numéro de priorité ; le menu ⋯ du fournisseur le monte, le descend ou le supprime

**Adaptation automatique du fichier du fournisseur (v3.7.0) :** « Choisir… » (ou « Remplacer… ») accepte le fichier **tel que téléchargé** chez le fournisseur : un `.ovpn`, un `.conf`, plusieurs fichiers, ou le `.zip` complet. Le programme applique les règles qui le rendent utilisable à travers Tor, sans rien connaître du fournisseur. Chaque règle répond à un blocage vérifié sur OpenVPN 2.7 :

| Règle | Pourquoi |
|---|---|
| Passage en TCP (`proto tcp`, y compris quand le fichier ne précise rien) | Tor ne transporte que du TCP ; OpenVPN utilise l'UDP par défaut |
| Fichiers annexes (`ca ca.crt`, `tls-auth ta.key 1`…) intégrés au `.ovpn` | OpenVPN lit une copie depuis `/run` : les chemins relatifs n'y mènent plus |
| Scripts retirés (`up`, `down`, `script-security`…) | Refusés par le daemon, qui applique le DNS du VPN lui-même |
| Options Windows retirées (`block-outside-dns`, `register-dns`…) | « Unrecognized option » sous Linux : connexion impossible |
| Options disparues retirées (`ncp-disable`, `keysize`, `key-method`, `tls-remote`) | Fatales depuis OpenVPN 2.6/2.7 |
| `fragment`, `mtu-test` retirés | Réservés à l'UDP |
| `route-nopull` retiré | Empêcherait le VPN de pousser ses serveurs DNS |
| `client`, `dev tun` ajoutés s'ils manquent | Minimum d'un tunnel client (`redirect-gateway` n'est jamais ajouté : le serveur l'envoie, et le doublon fait avertir OpenVPN) |
| `data-ciphers …:X` ajouté quand `cipher X` n'est pas dans la liste par défaut | OpenVPN ignore `cipher` seul depuis la 2.6 (avertissement `DEPRECATED OPTION`) ; X reste négociable en dernier recours. Jamais pour un chiffrement non pris en charge comme `BF-CBC`, qui rendrait le fichier refusé |

- **Fusion :** plusieurs fichiers d'un même fournisseur (un par serveur, cas fréquent dans les archives) deviennent un seul `.ovpn` regroupant tous les `remote`, doublons retirés — à condition que tout le reste soit identique. Sinon, l'import l'explique et demande de les importer séparément.
- **Archives mêlant TCP et UDP :** seules les variantes TCP sont gardées. Un fournisseur qui ne fournit que de l'UDP est converti en TCP **sur les mêmes ports**, avec un avertissement : si la connexion échoue, c'est que ses serveurs n'acceptent pas le TCP sur ces ports.
- **Rien n'est effacé :** chaque ligne retirée reste dans le fichier, en commentaire, avec sa raison. Le résumé des modifications s'affiche avant l'enregistrement et figure aussi en tête du fichier.
- **Choix des serveurs :** aucun serveur n'est retiré. Faites le tri (pays, ports) **avant** l'import, en ne sélectionnant que les fichiers voulus.
- **Refusé :** configuration de serveur, interface TAP, fichier sans `remote`, fichier annexe introuvable. Le fichier produit passe ensuite par la même liste blanche que le daemon au démarrage du tunnel (voir *Gestion d'OpenVPN*).

**Comptes par fournisseur :**
- Chaque fournisseur peut avoir plusieurs comptes (identifiant + mot de passe)
- Stockés en base64 dans `config.json` (obfuscation simple, voir [Sécurité](#sécurité))
- Menu ⋯ de chaque compte pour l'essayer plus tôt, plus tard, ou le supprimer ; l'ordre ne sert que si `random_account` est désactivé, le daemon tirant sinon un ordre au hasard (voir [Choix du compte](#choix-du-compte--aléatoire-par-fournisseur))

**Failover automatique :** si les identifiants d'un compte sont refusés, le daemon passe au compte suivant du même fournisseur. Sur une coupure réseau, il réessaie le même compte avant de changer de fournisseur — voir [Failover et watchdog](#failover-et-watchdog).

### Page Exclusions (mode avancé)

#### DNS split — domaines locaux

Permet de router les requêtes DNS pour des domaines spécifiques vers votre serveur DNS local, tout en laissant le reste passer par le DNS du VPN.

| Champ | Description |
|-------|-------------|
| **Serveur DNS local** | IP de votre serveur DNS (ex : `192.168.50.10`) |
| **Domaines** | Domaines à router vers ce DNS (ex : `.lan`, `.local`, `.home`) |

> **Important :** le réseau contenant votre serveur DNS doit figurer dans les **IPs/Réseaux exclus** ci-dessous.

#### IPs / Réseaux exclus du tunnel

CIDRs et IPs qui contournent le tunnel et passent par la passerelle locale. Le daemon injecte `--route <ip> <mask> net_gateway` dans la commande OpenVPN.

> **IPv4 uniquement.** `--route` est une option IPv4 ; une entrée IPv6 serait acceptée puis ignorée par OpenVPN, en laissant croire à tort que le réseau est exclu. Depuis la v3.6.1, le GUI refuse la saisie et le daemon écarte ces entrées avec un avertissement dans le journal.

**Cas d'usage typiques :**
- Réseaux joignables **via un routeur** (autres VLAN, sites distants : `10.0.20.0/24`…)
- Sous-réseau du serveur DNS s'il est derrière un routeur — **obligatoire si DNS split activé**
- **Sous-réseau d'un VPN d'accès distant** (WireGuard/OpenVPN d'administration) : sans cette exclusion, les réponses vers votre client partiraient dans le tunnel Tor et **votre session SSH/RDP serait coupée** dès l'activation du service
- NAS, imprimante réseau, serveurs locaux situés derrière le routeur

> **Les réseaux directement connectés n'ont pas à être exclus — et ne doivent pas l'être.**
>
> Le réseau de votre propre carte (ex. `192.168.50.0/24` sur `eth0`) possède déjà une route kernel `scope link` en `/24`, plus spécifique que le `redirect-gateway` du VPN (`0.0.0.0/1`) : par *longest prefix match*, il reste **de toute façon hors tunnel**.
>
> L'exclure superposerait une route `via <passerelle>` de métrique 0 qui **supplanterait la route directe** : tout le trafic vers votre propre LAN ferait alors un détour par le routeur (*hairpin*), souvent refusé — ce qui casse notamment l'accès à un serveur VPN hébergé sur ce même segment.
>
> Le daemon **détecte et ignore automatiquement** ces exclusions inutiles, avec un message dans le journal.

### Page Réglages

| Réglage | Par défaut | Description |
|---------|-----------|-------------|
| **Reconnexion automatique** | activé | Rétablit le tunnel dès qu'il tombe |
| **Choisir un compte au hasard** | activé | Parmi les comptes du fournisseur ; l'ordre des fournisseurs reste celui de la liste |
| **Se connecter au démarrage de l'ordinateur** | désactivé | `systemctl enable/disable katakomba` (mot de passe demandé) |
| **Langue** | langue du système | Français, English, Español, Deutsch, Italiano, Português ; appliquée aussitôt |
| **Continuer en arrière-plan** | activé | Fermer la fenêtre la cache ; l'interface veille sur la connexion |
| **Prévenir en cas de coupure** | activé | Notifications du bureau (voir [Arrière-plan et notifications](#arrière-plan-et-notifications)) |
| **Lancer à l'ouverture de session** | désactivé | `~/.config/autostart/org.katakomba.Katakomba.desktop`, fenêtre cachée |
| **Bloquer IPv6 pendant la connexion** | désactivé | DROP ip6tables sur OUTPUT + FORWARD |
| **Mesurer le débit à la connexion** *(avancé)* | activé | Re-tire un circuit s'il est trop lent |
| **Débit minimum** *(avancé)* | 250 KB/s | Seuil de re-tirage (≈ 2 Mbps ; l'équivalent en Mbps est affiché sous le champ) |
| **Nouveaux tirages au plus** *(avancé)* | 3 | Re-tirages avant de conserver le circuit tel quel |

Les trois réglages d'**Interface** sont propres à chaque compte (`~/.config/katakomba/interface.json`), hors de la configuration du service, et ne demandent aucun mot de passe.

**Sauvegarde :** *Exporter* écrit une archive `.katakomba` (ZIP : `config.json`, fichiers `.ovpn`, torrc) ; *Importer* la restaure, avec les mêmes contrôles que le daemon. Les anciennes sauvegardes `.tvpn` restent lisibles. Les identifiants n'y sont pas chiffrés.

**Réparer le réseau :** lance `repair_network.sh` — arrête le service, nettoie toutes les règles iptables, routes et DNS bloqués. Utile quand la connexion est totalement bloquée malgré un redémarrage du service.

### Page Partage LAN (mode avancé)

Partage le tunnel Tor+VPN avec des appareils connectés sur une deuxième interface réseau.

| Réglage | Description |
|---------|-------------|
| **Activer le partage LAN** | Interrupteur principal ; pris en compte au prochain démarrage du service |
| **Carte réseau** | Carte à utiliser (la carte qui porte l'accès Internet n'est jamais proposée, ni lo, tun*, docker*…) |
| **Adresse de la carte** | Passerelle des appareils (ex : `10.0.0.1`), vérifiée dans le sous-réseau |
| **Sous-réseau** | Plage DHCP (ex : `10.0.0.0/24`) |
| **Distribuer les adresses automatiquement** | Lance dnsmasq |

### Page Tor (mode avancé)

Permet de personnaliser la configuration de Tor via un fichier `torrc` dédié. `install.sh` en installe un par défaut (valeurs ci-dessous) ; s'il est supprimé, Tor démarre avec les paramètres minimaux intégrés au daemon.

Les valeurs par défaut privilégient des circuits longs et stables, adaptés à
un tunnel OpenVPN persistant. Chaque option reste ajustable individuellement
ci-dessous, ou via le mode expert (édition directe du torrc).

**Options configurables :**

| Option | Description |
|--------|-------------|
| `LongLivedPorts 1194,443` | Préfère des relais stables pour les ports OpenVPN |
| `LearnCircuitBuildTimeout 0` | Timeout de circuit fixe (plus prévisible) |
| `MaxCircuitDirtiness` | Durée max d'un circuit avant renouvellement (s) |
| `CircuitBuildTimeout` | Délai max de construction d'un circuit (s) |
| `NewCircuitPeriod` | Fréquence de construction de nouveaux circuits (s) |
| `KeepalivePeriod` | Envoi de cellules keepalive pour maintenir les circuits NAT |
| `NumEntryGuards` | Nombre de nœuds d'entrée (guards) |
| `GuardLifetime` | Durée de conservation des guards |
| `AvoidDiskWrites 1` | Réduit les écritures disque |
| `SafeLogging 1` | Masque les IPs dans les logs Tor |
| `ClientUseIPv6 0` | Désactive IPv6 pour Tor |
| `TestSocks 1` | Avertit si une requête DNS locale est détectée |
| `ConnectionPadding 1` | Résistance à l'analyse de trafic (↑ bande passante) |
| `ExcludeExitNodes` | Exclure des nœuds de sortie par pays (format `{us},{gb}`) |
| `StrictNodes` | Strict sur les exclusions (peut couper si aucun nœud disponible) |

**Mode expert :** zone de texte éditable affichant le torrc complet. Se met à jour en temps réel quand les options changent. Peut être édité directement pour des paramètres avancés.

**La page reflète le fichier.** À l'ouverture, les options sont lues dans le torrc (elles montraient auparavant les défauts du GUI). Une ligne qu'aucune option ne sait représenter (`ExcludeNodes`, `Bridge`, `ConnectionPadding 0`…) est **conservée telle quelle** quand on touche une option. Avant, toucher une seule option réécrivait tout le texte et effaçait ces lignes. Quitter la zone de texte recale les options sur ce qui a été tapé.

**Appliquer et redémarrer** → vérifie le torrc avec les règles du daemon (voir *Configuration Tor*), écrit `/etc/katakomba/torrc` + redémarre le service.
**Réinitialiser** → supprime le torrc + redémarre avec la config minimale du daemon.

> Les paramètres obligatoires (`SocksPort`, `ControlPort`, `CookieAuthentication`, `DataDirectory`) sont de toute façon **imposés par le daemon en ligne de commande**, qui l'emporte sur le fichier.


### Pages Diagnostic et Journal

**Diagnostic** lance `katakomba doctor` en un clic, dans la langue de l'interface (sortie `--json`), et présente un verdict en tête (« Tout est conforme », « 2 problèmes à corriger », « Reconnexion en cours ») puis chaque contrôle : routage, DNS, fuites, relais protégés, sortie réelle. **Copier le rapport** le met dans le presse-papiers, prêt à coller. Rien n'est modifié, aucun mot de passe n'est demandé.

**Journal** affiche les dernières lignes du service, rafraîchies en direct (bouton pause), une heure par ligne et les avertissements en couleur. Une **recherche**, un filtre de **gravité** (tout, avertissements et erreurs, erreurs seules) et un bouton qui **masque la routine** (connexions de contrôle de Tor, vérification des certificats, masquée par défaut) ; **Exporter** enregistre les lignes affichées dans un fichier texte.

---

## CLI `katakomba`

```bash
# Contrôle du service (requiert root)
sudo katakomba start       # Démarre le daemon
sudo katakomba stop        # Arrête le daemon
sudo katakomba restart     # Redémarre le daemon
sudo katakomba enable      # Active le démarrage automatique au boot
sudo katakomba disable     # Désactive le démarrage automatique

# Interface graphique
katakomba gui

# Surveillance
katakomba status           # État complet : service, Tor, VPN, circuit, DNS split, IP publique
katakomba doctor           # Diagnostic des invariants — verdict OK/WARN/KO
katakomba logs [n]         # n dernières lignes de journal (défaut : 60)
katakomba follow           # Logs en direct (Ctrl+C pour quitter)
katakomba ip               # IP publique actuelle
```


### `katakomba doctor` — diagnostic

Vérifie en une commande les invariants qui doivent tenir quand la connexion est saine. **Entièrement en lecture seule et sans root** : aucune commande ne modifie quoi que ce soit, aucune invite de mot de passe.

```
  [OK  ] Service                    actif
  [OK  ] Version du daemon          3.7.0
  [OK  ] Tor                        bootstrap terminé
  [OK  ] Tunnel                     tun0 depuis 17h27 (vpn-a, compte 1)
  [OK  ] Qualité du circuit         592 KB/s (~4.7 Mbps), mesuré il y a 0h03
  [OK  ] Route par défaut           default via 192.168.50.1 dev eth0 (hors tunnel)
  [OK  ] Protection des guards Tor  3/3 relais routé(s) hors tunnel
  [OK  ] Redirection du trafic      2/2 routes def1 présentes
  [OK  ] Réseaux locaux             2 réseau(x) en accès direct
  [OK  ] DNS du tunnel              10.8.0.1 · ~. · default-route
  [OK  ] DNS split                  drop-in en place
  [OK  ] Chemin des requêtes DNS    128 ms (résolveur local via eth0 : 7 ms)
  [OK  ] IPv6                       bloqué
  [OK  ] Sortie Internet            IP publique 203.0.113.42

  Tout est conforme.
```

Ce que chaque contrôle attrape :

| Contrôle | Panne détectée |
|----------|----------------|
| Route par défaut | pointe sur le tunnel → boucle de routage |
| Protection des guards | relais protégés par le daemon absents de la table de routage → Tor joint ses relais par le tunnel dont ils sont le support (depuis la v3.7.0, les routes `/32` d'exclusion ne sont plus comptées comme des guards) |
| Réseaux locaux | un réseau directement connecté supplanté par une route `via` (piège scope-link) → accès au segment cassé |
| DNS du tunnel | serveur, `~.` ou `default-route` manquant → requêtes publiques hors tunnel |
| Chemin des requêtes DNS | résolution trop rapide pour passer par Tor → fuite probable |
| Qualité du circuit | mesure de plus de 6 h → le circuit a pu se dégrader depuis |
| Sortie Internet | pas de réponse via le tunnel, ou adresse privée |

**Reconnexion en cours.** Quand le daemon reconstruit volontairement le tunnel (circuit trop lent remplacé, OpenVPN relancé après une perte de connectivité, redémarrage complet, compte refusé), le tunnel est absent quelques secondes par construction. `doctor` affiche alors la raison au lieu de faux KO, reporte les contrôles du tunnel et ne conseille **pas** de redémarrer, ce qui interromprait la reconnexion :

```
  [....] Tunnel                     reconnexion en cours depuis 3 s (circuit Tor trop lent, nouveau tirage)
  [--  ] Sortie Internet            reporté — le tunnel se reconnecte

  Reconnexion en cours (…) : les contrôles du tunnel sont reportés.
  C'est normal et passager : relancez « katakomba doctor » dans 30 s.
```

Un tunnel toujours absent au bout de 2 minutes est signalé comme une panne (KO), avec la dernière cause connue.

Code de sortie **0** si aucun KO, **1** sinon, **2** pendant une reconnexion si rien d'autre ne bloque — utilisable dans un script ou une tâche planifiée.

---

## Fonctionnement détaillé du daemon

### Séquence de démarrage complète

```
1.  Nettoyage des règles iptables orphelines (session précédente)
2.  Démarrage de Tor en subprocess (avec torrc si présent)
3.  Attente du bootstrap Tor 100% (timeout 240s max)
4.  Démarrage de la boucle OpenVPN dans un thread dédié
5.  Démarrage de la boucle de monitoring dans le thread principal
```

### Gestion de Tor

Tor est lancé directement en subprocess (pas via le service système) :
```
tor --torrc-file /run/katakomba/torrc
    --SocksPort 9050  --ControlPort 9051  --CookieAuthentication 1
    --DataDirectory /var/lib/katakomba/tor_data  --Log notice stdout
    --User debian-tor
```

- **`--torrc-file`** désigne une **copie validée** du torrc (vide s'il est absent ou refusé), jamais le fichier que le groupe `katakomba` peut modifier.
- **Les paramètres vitaux viennent après**, en ligne de commande : pour Tor, elle remplace les valeurs du fichier. C'est vérifié : un torrc déclarant d'autres `ControlPort`, `DataDirectory` et `Log` est ignoré sur ces trois points. Le daemon garantit ainsi ses ports, un journal sur stdout (qu'il analyse) et un `DataDirectory` hors de portée du groupe.
- **`--User debian-tor`** (v3.7.0) : Tor démarre en root puis abandonne ses droits. Il analyse des données reçues du réseau, et une faille de son analyseur ne doit pas donner la machine entière. Le daemon attribue `tor_data/` à `debian-tor` à chaque démarrage. Si cet utilisateur manque, Tor reste en root et le journal le signale.

Si Tor crash, il est redémarré automatiquement (jusqu'à 5 fois avec délai de 15s).

### Gestion d'OpenVPN

```
openvpn
  --config            /run/katakomba/openvpn.conf   ← copie validée du .ovpn
  --auth-user-pass    /run/katakomba/auth.tmp
  --verb              3          ← requis pour net_addr_v4_add dans les logs
  --ping              10
  --ping-exit         60
  --connect-timeout   60         ← allongé car les circuits Tor peuvent être lents
  --connect-retry     1
  --connect-retry-max 1
  --socks-proxy       127.0.0.1 9050
  [--route <ip> <mask> net_gateway ...]
```

> **`--script-security 1` imposé, après `--config` (v3.6.4).** Aucun fichier `.ovpn` n'a besoin de scripts — le daemon applique lui-même le DNS du VPN via `resolvectl`. Autoriser l'exécution de scripts permet en revanche à quiconque peut écrire un `.ovpn` (le groupe `katakomba`) de faire exécuter du code **par le daemon, en root**, via une simple directive `up`.
>
> **La v3.6.1 se contentait de ne pas passer l'option — c'était insuffisant.** Un `.ovpn` peut déclarer `script-security 2` lui-même, et OpenVPN la prend. Le cas s'est présenté en production : un `.ovpn` de fournisseur contenait cette ligne, absente de ses configurations de référence. La protection annoncée n'était donc pas en vigueur.
>
> Vérifié empiriquement, avec une configuration contenant `script-security 2` et une directive `up` :
>
> | Invocation | Résultat |
> |---|---|
> | `openvpn --config fichier.ovpn` | **code exécuté en root** |
> | `openvpn --config fichier.ovpn --script-security 1` | bloqué |
>
> **C'est la position qui fait la sécurité** : OpenVPN traite les options dans l'ordre et inline le fichier à l'emplacement de `--config`. Une occurrence placée avant serait écrasée par le fichier. Le niveau 1 laisse passer les exécutables intégrés d'OpenVPN, dont `dns-updown`.
>
> Le daemon signale en outre toute directive `script-security` rencontrée dans un `.ovpn` : elle est désormais sans effet, mais sa présence est anormale.
>
> Les exécutables **intégrés** d'OpenVPN restent autorisés au niveau 1 : sur OpenVPN 2.6+, le hook natif `/usr/libexec/openvpn/dns-updown` continue donc de fonctionner normalement.

> **v3.7.0 — `--script-security 1` ne suffisait pas.** La directive `plugin /x.so` **charge une bibliothèque, donc exécute du code, quel que soit ce niveau**. Vérifié sur OpenVPN 2.7.0 : le constructeur de la bibliothèque s'exécute avant toute connexion. D'autres directives ont le même effet (`pkcs11-providers`, `providers`, `engine`) ou écrivent un fichier arbitraire en root (`log`, `status`, `writepid`…).
>
> Le `.ovpn` passe donc par une **liste blanche** (`validation.py`) avant chaque lancement. Une directive absente de la liste fait **refuser le fichier** : le fournisseur est ignoré et le suivant prend le relais. Les directives de script (`up`, `down`, `route-up`, `tls-verify`…) sont refusées de la même façon. Les formes détournées sont couvertes : `--plugin`, `"plugin"`, `setenv opt plugin …`, directive dans un bloc `<connection>`. Le GUI applique les mêmes règles au choix d'un `.ovpn` et à l'import d'une sauvegarde `.katakomba`.
>
> OpenVPN lit ensuite une **copie** de ce qui a été contrôlé (`/run/katakomba/openvpn.conf`), jamais le fichier d'origine, qui pourrait changer entre le contrôle et la lecture. Celui-ci est lu **sans suivre de lien symbolique**. Un lien vers `/etc/shadow` aurait sinon fait recopier ce fichier, ligne à ligne, dans les messages d'erreur d'OpenVPN, donc dans le journal. Pour la même raison, les messages du daemon ne citent jamais le contenu d'une ligne refusée.
>
> `script-security N` dans un `.ovpn` reste toléré (sans effet, signalé dans le journal).

**Protection des routes Tor :**
Dès qu'OpenVPN assigne une IP au tunnel (`net_addr_v4_add`, visible grâce à `--verb 3`), le daemon ajoute de façon **synchrone** des routes `/32` statiques vers toutes les IP de guards Tor actifs via la passerelle locale originale. Cela doit s'exécuter *avant* que le script `up` n'installe les routes `redirect-gateway`. Sans cette protection, Tor tenterait de joindre ses guards via le tunnel, créant une boucle qui coupe la connexion. Les routes sont persistées dans `/var/lib/katakomba/tor-routes.txt` et supprimées proprement à chaque arrêt.

Les IP des relais viennent du ControlPort (`GETINFO orconn-status`), avec `ss` en repli. **v3.7.0 :** deux défauts de lecture corrigés. Avec une seule connexion, Tor répond sur une ligne (`250-orconn-status=$FP~nom CONNECTED`), forme qui n'était pas lue. Et une erreur `552` en première ligne (relais absent du consensus) n'était pas reconnue comme fin de réponse : la lecture attendait le timeout (8 s, pendant qu'OpenVPN installe ses routes) puis perdait toute la liste.

**DNS split timing :**
Le DNS du VPN est géré nativement par le daemon : les serveurs poussés par le VPN (`PUSH_REPLY`, `dhcp-option DNS`) sont extraits de la sortie d'OpenVPN et appliqués sur l'interface tunnel via `resolvectl` (aucun script `update-resolv-conf` requis). Le DNS split est ensuite appliqué **après** `Initialization Sequence Completed` ; son drop-in systemd-resolved garde la priorité sur les domaines exclus.

**Robustesse du DNS :**
- Au démarrage, le daemon vérifie que `resolvectl` est présent et que `systemd-resolved` est actif — sinon il avertit clairement dans le journal (sans lui, la résolution DNS peut échouer ou fuir hors Tor).
- Toutes les ~30 s, il **revérifie** que la configuration DNS de l'interface tunnel est toujours en place. Si un outil tiers a redémarré `systemd-resolved` (ce qui efface la config *runtime* par interface), elle est **réappliquée automatiquement**. En temps normal c'est une simple lecture : aucune réécriture, aucun `reload` inutile.

  Depuis la v3.6.1, le contrôle porte sur les **trois** attributs posés (serveurs DNS, domaine `~.`, `default-route`) et non plus sur les seuls serveurs.

  **v3.6.3 — lecture du `default-route` à trois états.** Le format de `resolvectl status` varie selon la version de systemd : le drapeau `+DefaultRoute` de la ligne `Protocols` est présent partout, mais l'étiquette `Default Route: yes` **n'existe pas sur systemd 255** (Ubuntu 24.04). Le daemon ne lisait que l'étiquette : il en concluait que le réglage manquait et **réappliquait le DNS à chaque tick du watchdog** — 19 fois en 10 minutes sur une configuration saine, avec un `WARN` à chaque passage, et un `[KO]` permanent dans `doctor`.

  La lecture renvoie désormais **trois** états : posé, retiré, ou `None` quand aucune des deux formes n'est reconnue. L'appelant teste `is False` et non `not …` : sur `None` il **s'abstient** au lieu de conclure à l'absence. C'est cette distinction qui empêche la boucle de revenir si le format change encore ; `doctor` rend alors un `WARN` explicite plutôt qu'un `KO`. Motif : lors d'une reconnexion interne (`SIGUSR1`), le hook natif `dns-updown` d'OpenVPN 2.6+ réinstalle les serveurs mais pas nécessairement le reste — et sans `~.`, l'interface tunnel cesse d'être la destination DNS par défaut, si bien que les requêtes publiques peuvent repartir vers le DNS local, hors tunnel, sans que rien ne le signale.

**Séquence à la connexion :**
Quand `Initialization Sequence Completed` est détecté — y compris sous la forme `… With Errors`, émise quand une route ou l'interface n'a pu être posée. Jusqu'à la v3.6.4, cette variante contenait « error » et tombait dans la branche d'erreur : le tunnel fonctionnait mais n'était jamais déclaré actif (ni DNS du VPN, ni blocage IPv6, ni watchdog).
1. DNS split appliqué (après le script up d'OpenVPN)
2. Blocage IPv6 activé (si configuré)
3. Partage LAN démarré (si `lan_auto = true`)

### Hook veille/réveil

`/lib/systemd/system-sleep/katakomba-sleep` est appelé par le noyau à chaque événement de veille/réveil. Au réveil (`post`), il attend 3 secondes puis exécute `systemctl try-restart katakomba` : un service arrêté volontairement le reste. Ce délai laisse le temps aux interfaces réseau de se reconnecter avant que le daemon ne relance Tor.

---

## Chaînes iptables

Le daemon crée des **chaînes nommées dédiées** pour un nettoyage propre sans interférer avec d'autres règles.

### Blocage IPv6 — `KATAKOMBA_KS6` / `KATAKOMBA_KS6_FWD`

```
OUTPUT/FORWARD :
RETURN  → lo
RETURN  → tunX
RETURN  → ESTABLISHED,RELATED
DROP    → tout le reste (IPv6)
```

Protège contre les fuites IPv6 quand le fournisseur VPN ne le supporte pas.

### Partage LAN — `KATAKOMBA_LAN_FWD` (FORWARD)

```
RETURN  → ESTABLISHED,RELATED
RETURN  → <iface_lan> → tunX
DROP    → <iface_lan> → tout le reste

NAT POSTROUTING : MASQUERADE source=<subnet_lan> out=tunX
```

---

## Failover et watchdog

### Reconnexion : deux causes, deux réponses

Quand le processus OpenVPN se termine, le daemon distingue **la nature de la rupture** avant de décider (comportement de la v3.6.1) :

| Cause détectée | Réponse | Délai |
|----------------|---------|-------|
| **Identifiants refusés** (`AUTH_FAILED` ou `SIGTERM[soft,auth-failure]`) | Compte mis en quarantaine 15 min, puis compte suivant | 3 s |
| **Tout le reste** (coupure réseau, TLS expiré, `ping-exit`) | **Même compte**, jusqu'à `RECONNECT_MAX` (5) fois | 15 s |
| Le même compte échoue 5 fois de suite | **Fournisseur suivant** | 3 s |
| Tous les comptes refusés, 1re passe | Nouvelle passe complète | 60 s |
| Tous les comptes refusés, 2e passe | Abandon → filet anti-inertie → relance systemd | — |

Le point clé : **changer de compte ne sert que si le compte est en cause.** Tous les comptes d'un fournisseur partagent le même fichier `.ovpn`, donc la même liste de serveurs — en changer n'a aucun effet sur une panne réseau ou côté serveur. Seul le changement de *fournisseur* en a.

> **Avant la v3.6.1**, toute rupture déclenchait un failover de compte. Une simple coupure réseau brûlait tous les comptes du premier fournisseur (dix, dans le cas observé) puis ceux du suivant en une trentaine de secondes (3 s d'écart), sans que la temporisation de 15 s n'entre jamais en jeu : jusqu'à 65 tentatives d'authentification en rafale sur une panne prolongée. La logique actuelle en fait 12, espacées de 15 s — moins agressif pour le fournisseur, et bien plus susceptible de réussir puisqu'une coupure réseau se répare d'elle-même.

Un défaut qui touche le fournisseur entier (`.ovpn` introuvable) fait aussi passer directement au fournisseur suivant, sans parcourir ses comptes un à un.

### Détection de panne

Le watchdog vérifie la connectivité toutes les **9 secondes** (après un délai de grâce de **30 secondes** post-connexion) :

1. `ip link show tunX` — l'interface existe-t-elle ?
2. Connexion TCP via `SO_BINDTODEVICE tunX` vers `1.1.1.1:443` **et** `9.9.9.9:443`, lancées **en parallèle** (5 s d'attente pour les deux ensemble) — le tunnel route-t-il vraiment ? Deux endpoints indépendants : la panne ponctuelle de l'un ne déclenche rien.

Un échec est **confirmé 3 s plus tard** (et non au cycle suivant, 9 s après). Deux échecs de suite déclenchent une **reprise graduée** (v3.7.0) :

1. **Relance d'OpenVPN seul**, sur le même compte et un circuit Tor neuf (`NEWNYM`), si le ControlPort indique que Tor est sain (`status/circuit-established=1`).
2. **Redémarrage complet** (`_full_restart()` : arrêt de Tor et d'OpenVPN, nettoyage des routes `/32`, relance) si Tor n'est pas sain, si la connectivité manque encore après la relance légère, ou si le tunnel n'est pas remonté **45 s** après elle.

> **Pourquoi.** Sur cinq semaines de production, les redémarrages complets représentaient **83 % du temps de coupure** (médiane 28 s), alors que Tor allait bien : il était de nouveau prêt 2 s après sa relance. C'est le tunnel qui était mort, pas Tor. Le temps partait dans la détection (deux vérifications séquentielles de 10 s, espacées de 9 s), dans l'arrêt et la relance inutiles de Tor, et dans une attente fixe de 6 s, remplacée par l'attente effective de la libération du port SOCKS. Le socket de statut expose `light_restarts` à côté de `full_restarts`.

**Commandes système bornées :** chaque appel à `ip`, `iptables`, `resolvectl`, `pkill`… est interrompu au bout de **30 s** (code 124). Une commande bloquée — verrou `xtables` tenu par un autre outil, D-Bus muet — ne gèle plus le daemon jusqu'au watchdog systemd.

**Filet anti-inertie :** les boucles Tor/OpenVPN abandonnent après un nombre borné de tentatives. Si plus aucune boucle VPN ne tourne pendant **2 minutes** (reconnexion auto active), le daemon quitte volontairement (`exit 1`) : systemd le relance intégralement (`Restart=on-failure`, tentatives illimitées). Aucune panne, même longue, ne laisse le daemon dans un état inerte définitif.

**Watchdog systemd :** la boucle de monitoring envoie `WATCHDOG=1` à systemd toutes les ~3s (`sd_notify`, également pendant l'attente du bootstrap Tor). Si le processus Python lui-même gèle — deadlock, appel système suspendu — les pings cessent et systemd tue puis relance le daemon après 90s (`WatchdogSec=90`). Chaîne de survie complète : boucles internes → filet anti-inertie → watchdog systemd.

Si la connectivité revient après un redémarrage, le compteur est remis à zéro.

### Réparation automatique d'urgence

Si **3 redémarrages complets consécutifs** échouent tous (compteur `_full_restart_count`), le watchdog déclenche `_emergency_repair()` :

```
1. Lance repair_network.sh --internal
   → nettoie iptables (IPv6 + LAN), routes OpenVPN bloquées, DNS systemd-resolved
   → ne touche pas au service systemd (le daemon reste maître)
2. sys.exit(1)
   → systemd détecte le crash et relance automatiquement le daemon (Restart=on-failure)
```

**Séquence type en cas de blocage total :**
```
[WARN] Watchdog : pas de connectivité (1/2) …
[WARN] Watchdog : pas de connectivité (2/2) …
[ERROR] Watchdog : redémarrage complet (1/3) …
[WARN] Watchdog : pas de connectivité (1/2) …
[ERROR] Watchdog : redémarrage complet (2/3) …
[WARN] Watchdog : pas de connectivité (1/2) …
[ERROR] Watchdog : redémarrage complet (3/3) …
[ERROR] 3 redémarrages échoués — lancement de repair_network.sh …
[WARN]  Réparation terminée — sortie pour relance systemd.
← systemd relance le daemon automatiquement
```

### Contrôle qualité du circuit Tor

Le circuit Tor est **tiré au sort à chaque connexion** : sa qualité varie fortement d'un tirage à l'autre (de ~100 KB/s à plusieurs Mo/s). Juste après l'établissement du tunnel, le daemon mesure le débit réel *à travers* le tunnel :

```
Tunnel actif → 5 s de stabilisation → mesure du débit
   ├─ ≥ seuil  → circuit conservé, aucune autre mesure
   └─ < seuil  → SIGNAL NEWNYM  (force un circuit neuf)
                 → reconnexion OpenVPN (même fournisseur/compte)
                 → nouvelle mesure … jusqu'à « essais maximum »
                 → au-delà : circuit conservé (jamais de boucle)
```

Deux points de conception importants :

- **La mesure crée elle-même la demande qu'elle mesure.** Une lecture passive des compteurs d'interface serait ininterprétable : un débit faible signifierait aussi bien « le lien est lent » que « rien n'est demandé ». Ici, un résultat faible signifie sans ambiguïté que le circuit est mauvais.
- **`NEWNYM` est envoyé *avant* la reconnexion.** Il ne change pas le circuit d'une connexion déjà établie — il garantit que la *prochaine* connexion partira sur un circuit neuf. Sans lui, `MaxCircuitDirtiness` ferait réutiliser le même circuit, donc les mêmes relais lents.

**Aucune surveillance continue** : ce test ne tourne pas en tâche de fond et ne consomme rien après la connexion.

#### Comment la mesure est prise (v3.6.3)

Une requête unique mesurait le **coût d'établissement de la connexion**, pas la capacité du circuit. Relevé en conditions réelles, mesure du daemon rejouée trois fois de suite sur un circuit vieux de 9 h :

```
essai 1 : 344 KB/s        ← ouverture du flux TCP/TLS à travers Tor
essai 2 : 985 KB/s
essai 3 : 979 KB/s
```

Le premier échantillon est 2,9 × plus bas — sur un circuit parfaitement mûr. Des circuits sains étaient donc rejetés, et le démarrage s'allongeait de plusieurs minutes en re-tirages inutiles.

La mesure procède désormais ainsi :

1. **Une requête d'échauffement de 500 Ko, dont le résultat est jeté.** Elle ouvre la fenêtre de contrôle de flux du circuit Tor.
2. **Deux échantillons de 2 Mo**, dont on retient le **maximum**.

Trois choix méritent d'être explicités :

- **Le maximum, pas la moyenne.** La question posée est « ce circuit peut-il aller assez vite ? ». Un bon échantillon prouve la capacité ; la contention ne tire les mesures que vers le bas, si bien qu'une moyenne pénaliserait un circuit correct momentanément gêné.
- **Les échantillons restent à 2 Mo.** C'est contre-intuitif, mais **les réduire fausserait la mesure** : chaque `curl` ouvre une connexion TCP neuve, et un transfert court passe l'essentiel de sa vie en *slow-start*. Mesuré ici, après échauffement, sur le même circuit :

  | Échantillon | Débit mesuré |
  |---|---|
  | 500 Ko | 383 KB/s |
  | 1 Mo | 652 KB/s |
  | 2 Mo | 1061 KB/s |
  | 5 Mo | 1520 KB/s |

  Descendre à 500 Ko diviserait la mesure par ~2,8 et ferait rejeter des circuits sains — exactement le défaut corrigé. Le seuil `circuit_min_kbs` est calibré sur 2 Mo.
- **Un budget de durée total** (`_SPEED_BUDGET`, 75 s) borne l'ensemble. Sans lui, deux salves de requêtes lentes atteindraient 165 s : le contrôle durerait plus longtemps que la reconnexion qu'il est censé décider.

Empreinte réseau : **4,5 Mo par tunnel monté** (500 Ko + 2 × 2 Mo), contre 2 Mo auparavant. Le contrôle n'a lieu qu'une fois par connexion.

Résultat mesuré, même tunnel : **981 et 982 KB/s en 5,3 s**, là où la mesure à froid donnait 456 KB/s.

Exemple réel :
```
[WARN] [circuit] Débit faible : 127 KB/s (~1.0 Mbps) < 250 KB/s — nouveau tirage (1/3) …
[OK  ] [tor] Nouveau circuit demandé (NEWNYM).
[WARN] Reconnexion sur un circuit Tor neuf …
[OK  ] [circuit] Débit OK : 568 KB/s (~4.5 Mbps).
```

### Logique de failover

```
Fournisseur 1, compte tiré → autre compte de 1 → ... → Fournisseur 2, compte tiré → ...
Tous épuisés → retour au début → abandon après 5 tentatives
```

### Choix du compte : aléatoire par fournisseur

Depuis la v3.6.2, `random_account` (activé par défaut) tire **l'ordre de passage des comptes au hasard** à chaque entrée dans un fournisseur :

```
[INFO] [provider] vpn-a : ordre des comptes tiré au hasard → 7 2 9 1 5 10 3 8 4 6
[INFO] Fournisseur : vpn-a  (compte 7)
```

**L'ordre des fournisseurs n'est jamais mélangé** : il reste l'ordre de priorité de la liste. Seuls les comptes *à l'intérieur* d'un fournisseur sont tirés, et le fournisseur suivant n'est atteint qu'une fois **tous** ses comptes essayés.

Ce qui est tiré est un **ordre complet** (une permutation), pas un compte à chaque essai. La différence importe : avec un tirage indépendant à chaque tentative, « tous les comptes épuisés » n'aurait aucun sens — on pourrait retomber dix fois sur le même compte sans jamais couvrir la liste.

Deux bénéfices :

- **Répartition de l'usage.** Le compte 1 n'est plus systématiquement celui qui se connecte, ce qui évite de buter sur la limite de connexions simultanées d'un seul compte.
- **Moins de corrélation.** Le fournisseur voit une IP de sortie Tor différente à chaque fois, mais toujours le même compte : cette régularité est un motif. Le tirage la casse.

**Contrepartie, à connaître :** un compte aux identifiants périmés produit une panne *intermittente* au lieu d'être touché à coup sûr. C'est pourquoi l'ordre tiré est journalisé — sans cette ligne, un incident survenu sur un tirage donné serait impossible à reconstituer. Désactivez « Choisir un compte au hasard » (page *Réglages* → *Connexion*) pour revenir à l'ordre de la liste et rendre l'incident déterministe.

> Le tirage ne s'applique qu'au **choix** d'un compte neuf : au démarrage et sur un refus d'identifiants. Une coupure réseau continue de réessayer **le même** compte — la logique du tableau ci-dessus est inchangée.

### Quarantaine : un compte refusé n'est pas un compte mort

Le fournisseur envoie un `AUTH_FAILED` **nu, sans motif**. Ce message unique recouvre deux causes opposées :

| Cause | Nature | Bonne réponse |
|-------|--------|---------------|
| Mot de passe invalide | Définitive | Ne plus utiliser ce compte |
| Quota de connexions simultanées atteint | **Temporaire** — quelqu'un d'autre est connecté | Réessayer plus tard |

**Le daemon ne peut pas les distinguer.** Observé en production : un compte a renvoyé `AUTH_FAILED` à deux reprises, puis s'est connecté sans incident une douzaine de fois les jours suivants. Le refus était temporaire.

La réponse est donc une **quarantaine et non une exclusion** (`AUTH_COOLDOWN`, 15 min) :

```
[WARN] Compte 2 refusé (vpn-a) — mis en quarantaine 15 min (mot de passe
       invalide ou connexions simultanées épuisées).
[WARN] Failover : compte 4 (2/10 essayés) chez vpn-a
...
[INFO] [provider] vpn-a : ordre des comptes tiré au hasard → 4 10 8 1 9 6 7 3 5 2
[INFO] [provider] vpn-a : 1 compte(s) en quarantaine, essayé(s) en dernier → 2
```

Le compte puni **recule en fin d'ordre, sans jamais quitter la liste**. Conséquences :

- Un compte simplement occupé n'est plus choisi en priorité, mais **reste essayé** si tous les autres échouent aussi.
- Un compte réellement mort s'enfonce durablement en fin d'ordre : chaque nouvel échec renouvelle sa quarantaine.
- Une connexion réussie **lève immédiatement** la quarantaine du compte concerné : inutile de le pénaliser 15 min de plus une fois redevenu libre.

**Plus d'abandon dès la première passe.** Si tous les comptes de tous les fournisseurs sont refusés, le daemon attend `AUTH_PASS_DELAY` (60 s) et refait **une passe complète** (`AUTH_PASS_MAX` = 2) avant de rendre la main à systemd. Motif : « tous occupés au même instant » est transitoire. Sans cette seconde passe, le scénario aboutissait à ~145 s d'indisponibilité et à un redémarrage complet du daemon — donc à un nouveau bootstrap Tor et à des circuits neufs à re-mesurer — pour une cause qui se résout d'elle-même.

L'état est consultable :

```
katakomba doctor
  [WARN] Comptes en quarantaine     compte 2 (12 min) — essayés en dernier
```

> Le message d'abandon final ne parle plus d'« identifiants refusés » seuls : il nomme les deux causes possibles. L'ancien libellé orientait le diagnostic vers un mot de passe erroné alors que la cause la plus fréquente est le quota de connexions.

### Arrêt propre (SIGTERM / SIGINT)

```
1. SIGTERM → OpenVPN
2. SIGTERM → Tor
3. Suppression des routes /32 Tor
4. Démontage partage LAN + arrêt dnsmasq
5. Suppression chaînes ip6tables
6. Suppression drop-in DNS split
7. Suppression auth.tmp
```

---

## Partage LAN

Quand le partage LAN est activé :

1. IP passerelle assignée à l'interface LAN (`ip addr add`)
2. Routage IP activé (`sysctl net.ipv4.ip_forward=1`)
3. NAT MASQUERADE pour que le trafic LAN sorte par le tunnel
4. Chaîne `KATAKOMBA_LAN_FWD` : bloque tout trafic LAN n'allant pas vers le tunnel
5. dnsmasq en mode `--no-daemon` : DHCP dans le sous-réseau, DNS `1.1.1.1` via tunnel

Si le tunnel tombe, le trafic LAN est bloqué — aucune fuite par la connexion directe.

Les règles des étapes 3 et 4 figent le **nom de l'interface tunnel**. Comme les `.ovpn` utilisent `dev tun` (premier device libre), ce nom peut changer au remontage du tunnel. Depuis la v3.6.1, le daemon compare l'interface mémorisée à l'interface courante et **reconstruit les règles** si elles diffèrent (avec une trace en `WARN`) : sans cela, elles pointaient dans le vide et le trafic LAN tombait sur la règle `DROP` finale — coupure totale et silencieuse jusqu'au redémarrage du service.

---

## DNS split — Domaines locaux

Permet d'accéder à des services hébergés sur votre réseau local avec un nom de domaine personnalisé **pendant que le VPN est actif**.

### Pourquoi c'est nécessaire

Sans DNS split, le `redirect-gateway def1` du VPN route tout le trafic via le tunnel — y compris les paquets vers votre DNS local, qui devient inaccessible.

Avec DNS split :
- `.lan` → votre DNS local (`192.168.50.10`)
- Tout le reste → DNS du VPN via Tor

### Configuration

**Dans la page Exclusions de l'interface :**

1. Saisir l'IP du serveur DNS local
2. Ajouter les domaines locaux (ex : `.lan`)
3. Ajouter le sous-réseau du DNS dans les IPs exclues (ex : `192.168.50.0/24`) — **étape critique**
4. Sauvegarder + Redémarrer

Le daemon génère automatiquement :

```ini
# /etc/systemd/resolved.conf.d/katakomba-split.conf
[Resolve]
DNS=192.168.50.10
Domains=~lan
```

### Vérification

```bash
resolvectl status            # voir les domaines routés
dig nas.lan            # doit résoudre via 192.168.50.10
katakomba status               # affiche "DNS split : actif (→ 192.168.50.10)"
```

---

## Configuration Tor (torrc)

`install.sh` installe `/etc/katakomba/torrc` avec les valeurs par défaut (sans écraser un fichier existant), et la page **Tor** du GUI permet de le modifier. S'il est absent, Tor démarre avec les arguments minimaux intégrés.

**Liste blanche (v3.7.0).** Tor lit le torrc au démarrage, en root, alors que le groupe `katakomba` peut l'écrire. Or `ClientTransportPlugin x exec /chemin` y fait lancer un programme. Seules les options connues et sans effet de bord sont donc acceptées : réglages de circuit, de guards et de nœuds, rembourrage, `UseBridges`/`Bridge` sans transport enfichable… Sont refusés notamment `ClientTransportPlugin`, `Log` (et son abréviation `l`), `%include`, `PidFile`, `HiddenServiceDir`, ainsi que les lignes continuées par `\`. Un torrc refusé est **ignoré en entier** : Tor démarre avec la configuration de base et le journal indique les lignes en cause. Le GUI refuse d'enregistrer un tel fichier.

### Paramètres obligatoires (toujours présents)

```ini
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/katakomba/tor_data
```

(Imposés de toute façon en ligne de commande, qui l'emporte sur le fichier.)

### Valeurs par défaut (circuits longs et stables)

```ini
LongLivedPorts 1194,443
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 3600
CircuitBuildTimeout 60
NewCircuitPeriod 60
KeepalivePeriod 60
NumEntryGuards 3
GuardLifetime 2 months
AvoidDiskWrites 1
SafeLogging 1
ClientUseIPv6 0
TestSocks 1
```

Pour un anonymat renforcé, activez par exemple `ConnectionPadding 1` et
`ExcludeExitNodes {us},{gb},{ca},{au},{nz}` — toutes les options sont
ajustables dans la page Tor ou en mode expert.

### Réinitialisation

Le bouton **Réinitialiser** supprime le fichier torrc. Au prochain démarrage du service, Tor tourne avec les paramètres minimaux sans fichier de configuration externe.

---

## Réparation réseau automatique

`repair_network.sh` est le script de récupération d'urgence. Il peut être déclenché de **trois façons** :

| Déclencheur | Mode | Comportement |
|-------------|------|--------------|
| Bouton GUI "Réparer le réseau" | manuel | Arrête le service, nettoie tout, invite à redémarrer |
| `sudo bash repair_network.sh` | manuel CLI | Identique au bouton GUI |
| Watchdog (3 redémarrages échoués) | automatique | `--internal` : nettoie sans `systemctl stop`, puis `sys.exit(1)` pour relance systemd |

**Ce que le script nettoie :**

1. Processus OpenVPN et Tor résiduels **de ce programme**, reconnus à leur ligne de commande (jamais `pkill -x`, qui couperait un autre VPN ou Tor Browser)
2. Chaînes ip6tables `KATAKOMBA_KS6` / `KATAKOMBA_KS6_FWD` (blocage IPv6)
3. Chaîne iptables `KATAKOMBA_LAN_FWD`, dnsmasq du partage, et la règle NAT `MASQUERADE` associée
4. DNS systemd-resolved — `resolvectl revert` sur `tun0` et `tun1`, suppression du drop-in, redémarrage de `systemd-resolved`
5. Routes `/32` des relais Tor, lues dans `tor-routes.txt` — sans quoi le trafic vers ces IPs continuerait de contourner le tunnel après la réparation
6. Routes OpenVPN def1 bloquées (`0.0.0.0/1`, `128.0.0.0/1`, `default`) sur `tun0` et `tun1`
7. Vérification de connectivité finale (`ip route get 1.1.1.1`, `getent ahosts`)

> Les points 3, 5 et l'extension à `tun1` datent de la v3.6.1 : le script laissait auparavant des routes `/32` et une règle NAT orphelines, et ne traitait que `tun0` alors que les `.ovpn` utilisent `dev tun`.

---

## Format config.json

`/etc/katakomba/config.json` — mode `660 root:katakomba`.

```json
{
  "providers": [
    {
      "name": "ProtonVPN",
      "ovpn_file": "providers/ProtonVPN/server.ovpn",
      "accounts": [
        { "u": "dXNlcm5hbWU=", "p": "cGFzc3dvcmQ=" }
      ]
    }
  ],
  "auto_reconnect": true,
  "random_account": true,
  "block_ipv6": false,
  "excluded_ips": ["192.168.1.0/24", "192.168.50.0/24"],
  "excluded_domains": [".lan"],
  "local_dns": "192.168.50.10",
  "circuit_check": true,
  "circuit_min_kbs": 250,
  "circuit_max_retries": 3,
  "lan_iface": "",
  "lan_gateway": "10.0.0.1",
  "lan_subnet": "10.0.0.0/24",
  "lan_dhcp": true,
  "lan_auto": false,
  "autostart": false
}
```

| Clé | Type | Description |
|-----|------|-------------|
| `providers[].ovpn_file` | string | Chemin relatif au répertoire d'installation |
| `providers[].accounts[].u` | string | Identifiant en base64 |
| `providers[].accounts[].p` | string | Mot de passe en base64 |
| `excluded_ips` | liste | CIDRs/IPs passant par la passerelle locale |
| `excluded_domains` | liste | Domaines routés vers le DNS local |
| `local_dns` | string | IP du serveur DNS local |
| `random_account` | bool | Ordre des comptes tiré au hasard chez chaque fournisseur (l'ordre des fournisseurs reste la priorité de la liste) |
| `circuit_check` | bool | Mesure du débit à la connexion + re-tirage si circuit lent |
| `circuit_min_kbs` | int | Seuil en KB/s (250 ≈ 2 Mbps ; 0 = désactivé) |
| `circuit_max_retries` | int | Re-tirages max avant de conserver le circuit |

---

## Tests

Le projet est couvert par une suite de **628 tests** (`unittest`, aucune dépendance externe) :

```bash
bash run-tests.sh                 # tout
bash run-tests.sh -v              # détail test par test
bash run-tests.sh tests.test_openvpn   # un module
```

**La suite ne touche jamais au système.** `iptables`, `ip`, `resolvectl`, `systemctl`, `curl`, `openvpn` et `tor` sont interceptés et enregistrés au lieu d'être exécutés : les tests vérifient *quelles commandes auraient été lancées*, avec quels arguments et dans quel ordre. On peut donc lancer la suite sur la machine de production, tunnel monté, sans risque. `run-tests.sh` relève une empreinte réseau avant et après pour le prouver, et `tests/test_safety.py` interdit à un futur test de contourner cette règle.

Ce qui est couvert, au-delà des chemins nominaux :

| Domaine | Exemples de cas vérifiés |
|---------|--------------------------|
| Routes exclues | IPv6 refusé, réseau directement connecté ignoré (piège scope-link), CIDR normalisé |
| ControlPort | consensus microdesc (8 champs) *et* ns (9 champs), une seule connexion pour N requêtes, plafond de 32 relais |
| DNS | serveur/domaine `~.`/default-route contrôlés séparément, abstention si l'état est illisible |
| Pare-feu | `DROP` toujours en dernière règle, refus de flusher l'uplink, reconstruction si le tunnel change de nom |
| Qualité de circuit | seuil exact, plafond d'essais, thread périmé qui ne doit pas tuer le tunnel suivant |
| Reconnexion | identifiants refusés vs coupure réseau, nombre de tentatives borné |
| Sécurité | `auth.tmp` en 0600 même sous umask permissif et jamais écrit à travers un lien symbolique, `plugin` et consorts refusés dans un `.ovpn`, `exec` refusé dans un torrc, aucun contenu de fichier recopié au journal, aucun identifiant dans le socket de statut, anti-path-traversal de l'import |
| Cohérence | version identique dans `constants.py` et les deux READMEs, `--script-security 1` imposé **après** `--config` |

Plusieurs tests exercent aussi le système en **lecture seule** pour valider les parseurs contre la réalité plutôt que contre un échantillon figé (format de `/proc/net/dev`, sortie de `resolvectl status`).

---

## Traductions

Le texte source est **en français** : les chaînes marquées `_()` dans le code sont le texte français. Les autres langues sont dans `po/<langue>.po`, lus directement par `i18n.py` : rien à compiler, rien à générer à l'installation, aucune dépendance (ni `gettext` ni `msgfmt`).

```bash
python3 outils/traductions.py mettre-a-jour   # après avoir modifié un texte du code
python3 outils/traductions.py verifier        # manques, {champs} incohérents (code 1)
```

`mettre-a-jour` régénère `po/katakomba.pot` et ajoute aux catalogues les textes nouveaux, vides ; un texte non traduit s'affiche en anglais, puis en français. Les tests échouent tant qu'un catalogue est incomplet, qu'une traduction perd un `{champ}`, ou qu'un texte visible est écrit en dur sans `_()`.

**Ajouter une langue :** son code dans `i18n.LANGUES` (avec son nom dans cette langue), puis `po/<code>.po` à partir de `po/katakomba.pot`, en renseignant `Language` et `Plural-Forms` dans l'en-tête. Les invites polkit (`polkit/org.katakomba.policy`) et la description du lanceur (`Comment[…]`) se traduisent à part.

**Relecture bienvenue :** les traductions anglaise, espagnole, allemande, italienne et portugaise ont été faites depuis le français, sans relecture par des locuteurs natifs. Une correction se fait directement dans le `.po` de la langue.

---

## Sécurité

**Credentials VPN :** stockés en base64 dans `config.json`. C'est de l'obfuscation, **pas du chiffrement**. Le fichier est en mode `660 root:katakomba`, dans un répertoire `2770 root:katakomba`.

**auth.tmp :** créé directement en mode `600` (jamais exposé à l'umask) juste avant de lancer OpenVPN, dans `/run/katakomba` (root seul), sans jamais suivre de lien symbolique ; supprimé dans le bloc `finally` dès qu'OpenVPN a lu le fichier.

**torrc :** mode `660 root:katakomba`, validé par liste blanche avant chaque démarrage de Tor.

**Portée du groupe `katakomba` :** ce groupe existe pour que le GUI tourne **sans root**. Il donne en contrepartie l'accès en écriture à des fichiers que le daemon consomme en root (`config.json`, `torrc`, `providers/*.ovpn`). La v3.7.0 ferme les voies connues par lesquelles ce groupe pouvait obtenir root :

| Voie | Correctif |
|---|---|
| Code du daemon dans le clone de l'utilisateur | déployé dans `/opt/katakomba`, propriété de root |
| `plugin`, `providers`, `engine`… dans un `.ovpn` | liste blanche, copie validée lue par OpenVPN |
| `ClientTransportPlugin … exec` dans le torrc | liste blanche, copie validée ; Tor tourne sous `debian-tor` |
| Lien symbolique à la place d'`auth.tmp` ou du fichier de routes | fichiers du daemon dans `/run` et `/var/lib` (root seul), écriture `O_EXCL \| O_NOFOLLOW` |
| `install_dir` lu par `katakomba gui` | chemin fixe `/opt/katakomba` |

Le groupe reste sensible — il lit les identifiants VPN et choisit les serveurs — : n'y ajoutez que des comptes de confiance.

**Règle polkit :** les membres du groupe démarrent, arrêtent et redémarrent `katakomba.service` **sans mot de passe**, et seulement cela : depuis une session locale et active, pour ce service, pour ces trois verbes. Activer le démarrage automatique, réparer le réseau ou toucher à un autre service demande toujours le mot de passe administrateur. Arrêter le tunnel n'expose rien : le trafic qui ne passe pas par lui reste bloqué en amont. Le groupe pouvait déjà modifier tout ce que le service lit au démarrage ; il peut désormais aussi choisir quand il démarre. Pour revenir à un mot de passe à chaque connexion, supprimez `/usr/share/polkit-1/rules.d/50-katakomba.rules` (polkit le relit aussitôt).

**Scripts `.ovpn` :** l'exécution de scripts définis dans un `.ovpn` est désactivée, et un `.ovpn` qui en contient est refusé avant le lancement — supprimez la directive, le daemon gère le DNS lui-même.

**Tor comme proxy :** le serveur VPN voit l'IP d'un nœud de sortie Tor, jamais votre IP réelle. Votre FAI voit que vous utilisez Tor, mais ne sait pas que vous utilisez un VPN ni quelle destination vous atteignez.

---

## Premiers pas

1. **Téléchargez chez votre fournisseur VPN** sa configuration OpenVPN (fichier `.ovpn` ou archive `.zip`), de préférence en **TCP**. Ne gardez que les serveurs voulus.
2. **Installez le paquet** : `sudo apt install ./katakomba_<version>_all.deb`.
3. **Ouvrez « Katakomba »** depuis le menu des applications. Au premier lancement, un **assistant** vous guide en trois écrans :
   - **Fournisseur** : un nom et le fichier téléchargé, adapté automatiquement ;
   - **Identifiants** : identifiant et mot de passe OpenVPN (chez beaucoup de fournisseurs, différents de ceux du site) ;
   - **Connexion** : enregistrement, démarrage, et suivi en direct jusqu'à « ✓ Connecté ».

La première connexion prend 1 à 3 minutes, le temps que Tor rejoigne son réseau. Ensuite, le service se connecte seul au démarrage de l'ordinateur.

**À savoir avant de commencer**
- **Débit** : Tor + VPN donne quelques Mbps, bien pour naviguer, moins pour de la vidéo en haute définition.
- **Fournisseur** : il doit proposer OpenVPN en **TCP**, Tor ne transporte que du TCP. Testés : iVPN, ProtonVPN.
- **Protection pendant une coupure** : le programme ne bloque pas le trafic quand le tunnel tombe. Pendant les quelques secondes d'une reconnexion, le trafic peut sortir par votre connexion normale, sauf si un pare-feu en amont l'en empêche.
- **Mode avancé** (menu principal ☰) : exclusions, DNS local, partage LAN, réglages de Tor et de la qualité du circuit. Inutile pour un usage courant.

**Vérifier** : `katakomba status` (état) et `katakomba doctor` (diagnostic complet, sans root).

---

## Désinstallation

**Installé par paquet :**
```bash
sudo apt remove katakomba     # retire le programme, garde vos réglages
sudo apt purge  katakomba     # efface aussi réglages, fournisseurs et comptes
```

**Installé depuis les sources :**
```bash
sudo katakomba uninstall              # garde vos réglages
sudo katakomba uninstall --purge      # efface tout
```

Dans les deux cas, le nettoyage réseau (règles pare-feu, DNS) est fait avant le retrait. Le service `tor` du système, désactivé à l'installation, n'est pas réactivé d'office : `sudo systemctl enable --now tor` si vous en avez besoin.
