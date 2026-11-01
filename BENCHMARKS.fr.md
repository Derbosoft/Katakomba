# WireGuard et OpenVPN à travers Tor : banc de mesure

> [English version](BENCHMARKS.md)

Mesuré le 2026-11-01 avec Katakomba 4.4.3. Trois tunnels ont été comparés sur les mêmes circuits Tor :

- **IVPN OpenVPN**
- **Mullvad WireGuard**
- **IVPN WireGuard**, le témoin : comparé à IVPN OpenVPN il isole le protocole, et comparé à Mullvad WireGuard il isole le fournisseur

C'est une photographie prise sur une seule machine et une seule ligne, publiée pour que chacun choisisse par lui-même. Les serveurs, les prix et le réseau Tor changent.

## Résumé

- **Le débit ne les départage pas.** Sur 32 circuits, les trois tunnels sont à égalité dans la marge d'erreur, en Europe comme ailleurs.
- **Les coupures, si.** Quand un circuit Tor tombe, WireGuard a gardé toutes les connexions ouvertes (16 sur 16). OpenVPN revient aussi, mais il les a toutes perdues (0 sur 8).
- **Le serveur VPN pèse plus que le protocole.** Les plus gros écarts, jusqu'à ×12, venaient d'un serveur d'un fournisseur sur une route donnée, et touchaient ses deux tunnels.

| Rapports par rapport à IVPN OpenVPN | IVPN OpenVPN | Mullvad WireGuard | IVPN WireGuard |
|---|---|---|---|
| Descendant, rapport médian | référence | 1,02 [0,93–1,14] | 0,99 [0,92–1,10] |
| Montant, rapport médian | référence | 0,93 [0,79–1,06] | 1,22 [0,96–1,30] |
| Temps de page web, rapport médian (plus bas = plus rapide) | référence | 0,97 [0,90–1,04] | 1,02 [0,98–1,06] |
| Connexions ouvertes conservées à une coupure | **0/8** | **7/7** | **9/9** |
| Retour du tunnel après coupure, médiane | 3,9 s | 1,2 s | 0,44 s |
| Tunnel monté à froid, médiane | 1,31 s | 0,41 s | 0,61 s |
| Première page après montage, médiane / p90 | 2,85 / 5,13 s | 2,73 / 4,94 s | 2,38 / 7,95 s |
| Montages à froid utiles | 30/30 | 30/30 | 29/30 |
| Une heure, sondes réussies | 164/164 | 170/170 | 168/168 |

Entre crochets : intervalle à 95 % par bootstrap. Un intervalle qui contient 1 signifie aucun écart mesurable.

## Comment choisir

Le débit n'est pas une raison de choisir l'un plutôt que l'autre. Les différences utiles sont ailleurs :

| Si le plus important pour vous est | À considérer |
|---|---|
| Longs téléchargements, SSH, appels : des connexions qui doivent survivre à un changement de circuit | WireGuard, chez l'un ou l'autre |
| Un repli sur le même compte si WireGuard cesse de fonctionner | IVPN : Katakomba passe de WireGuard à OpenVPN |
| Un parc où des PC arrivent et disparaissent | Mullvad : Katakomba ne libère que les appareils morts (voir [Parcs](#parcs)) |
| L'expérience en conditions réelles | OpenVPN a ici le plus long historique. IVPN WireGuard en a très peu |

Proton ne faisait pas partie de ce banc.

## Parcs

Différences de fonctionnement de Katakomba selon le fournisseur. Prix et limites relevés sur les pages des fournisseurs le 2026-11-01 ; à vérifier avant d'acheter.

| | Mullvad | IVPN |
|---|---|---|
| Transports | WireGuard seul | WireGuard et OpenVPN |
| Emballage WireGuard | udp-over-tcp, TCP 443 | VMess déguisé en HTTP, TCP 80 |
| Places par compte | 5 | 5 (Standard, Plus), 10 (Pro Suite) |
| Prix par compte | 5 € par mois | 6 $ Standard, 10 $ Pro Suite par mois ; 60 $ et 100 $ par an |
| Récupération d'une place sur compte plein (comptes réservés à Katakomba) | Supprime uniquement les appareils de plus de 3 semaines | Ne peut pas lister les autres sessions : en dernier recours, remet tout un compte à zéro, et ses PC se réenregistrent |
| Renouvellement hebdomadaire de la clé | Appareil neuf, puis suppression de l'ancien | Nouvelle clé sur la même session |

Sources : [tarifs Mullvad](https://mullvad.net/en/pricing), [changements d'offres IVPN, mai 2026](https://www.ivpn.net/blog/ivpn-plan-changes-new-plus-tier-increased-device-limits-additional-privacy-services/).

Rien de tout cela n'a été testé à l'échelle d'un parc. Le banc n'a exercé ni la récupération de places ni le renouvellement de clé.

## Méthode

**Montage.** Un Tor dédié utilisait le torrc de Katakomba, sauf pour les pays des relais et `LongLivedPorts 1194,443,80`. Chaque tunnel tournait dans son propre espace réseau, avec les mêmes options OpenVPN que le démon et un MTU de 1320 pour WireGuard. OpenVPN a négocié CHACHA20-POLY1305 à chaque fois. La cible était `speed.cloudflare.com`.

**Blocs.** Un bloc est un circuit Tor figé (garde, milieu et sortie imposés par `StrictNodes`) plus un lieu VPN, desservi par un serveur de chaque fournisseur. Les mesures d'un même bloc ne sont pas indépendantes : le bloc est donc l'unité statistique. 32 blocs valides, chacun sur un seul chemin Tor.

| Région | Relais Tor | Serveurs VPN | Blocs |
|---|---|---|---|
| Europe | Europe | Europe | 8 |
| Tor libre, VPN UE | Sans contrainte | Europe | 8 |
| Amérique du Nord | Hors Europe | États-Unis, Canada | 9 |
| Asie-Pacifique | Hors Europe, sortie dans la région si possible | Japon, Hong Kong, Singapour, Australie | 7 |

**Performances.** Dans chaque bloc, en ordre tournant : 3 téléchargements de 15 s, 2 envois de 12 s et 2 chargements de page web (16 objets de 200 Ko, 4 connexions à la fois, TLS pour chacun). Également relevés : Tor seul sur le même circuit, latence à vide et en charge, CPU, pertes UDP et d'interface.

**Coupures.** Le circuit Tor a été fermé par `CLOSECIRCUIT` pendant un téléchargement de 40 s, 10 fois par tunnel.

**Montages à froid.** 30 par tunnel, chacun sur un circuit neuf.

**Endurance.** Les trois tunnels ont tourné côte à côte pendant une heure, sur des circuits isolés, avec une sonde de 100 Ko toutes les 20 s.

**Statistiques.** Chaque bloc donne un rapport entre deux tunnels. Médianes et moyennes géométriques utilisent le bootstrap à 95 % sur les blocs. Les valeurs p indiquées viennent de permutations de signe.

## Résultats

### Descendant par région

| Région | Blocs | Mullvad WG / IVPN OpenVPN, moyenne (médiane) | IVPN WG / IVPN OpenVPN, moyenne (médiane) |
|---|---|---|---|
| Europe | 8 | 1,00 (1,09) | 1,03 (1,04) |
| Tor libre, VPN UE | 8 | 0,80 (1,01) | 1,01 (1,10) |
| Amérique du Nord | 9 | 1,02 (0,89) | 1,03 (0,92) |
| Asie-Pacifique | 7 | 1,85 (1,38) | 1,12 (1,06) |
| **Tous** | 32 | 1,09 [0,85–1,39], p = 0,53 | 1,05 [0,95–1,16], p = 0,42 |
| **Hors Europe** | 16 | 1,32 [0,99–1,93], médiane 1,00 | 1,07 [0,92–1,28], médiane 0,95 |

Fournisseur seul (Mullvad WG / IVPN WG, tous blocs) : moyenne 1,04 [0,83–1,30], médiane 0,99.

### Pourquoi les moyennes trompent

Trois blocs font les moyennes régionales. Ils se sont répétés à chaque tour, ce n'est donc pas du bruit :

| Lieu | IVPN OpenVPN | IVPN WireGuard | Mullvad WireGuard | Tor seul |
|---|---|---|---|---|
| Hong Kong | 119 KB/s | 162 KB/s | 1501 KB/s | 1640 KB/s |
| Tokyo | 286 KB/s | 256 KB/s | 794 KB/s | 3183 KB/s |
| Madrid | 948 KB/s | 779 KB/s | 86 KB/s | 612 KB/s |

Les deux tunnels IVPN ont bougé ensemble à chaque fois : la cause est le serveur ou sa route, pas le protocole. Mullvad sort devant dans les deux premiers cas et loin derrière dans le troisième. Sans ces trois blocs, Mullvad WG / IVPN OpenVPN donne 1,05 [0,94–1,18].

### Coût

- **CPU :** 2,2 % par MB/s pour OpenVPN, de 3,6 à 3,9 % pour WireGuard. À ces débits, la charge médiane reste à 1,4 % ou moins.
- **Part du débit de Tor seul conservée :** 0,77 pour OpenVPN, 0,81 pour les deux tunnels WireGuard.
- **Latence en charge :** environ 750 ms pour les trois.
- **Pertes UDP et d'interface :** aucune.

### Coupures

| | Coupures valides | Retour du tunnel, médiane (max) | Connexions conservées |
|---|---|---|---|
| IVPN OpenVPN | 8 sur 10 | 3,9 s (6,9 s) | 0/8 |
| Mullvad WireGuard | 7 sur 10 | 1,2 s (3,7 s) | 7/7 |
| IVPN WireGuard | 9 sur 10 | 0,44 s (2,5 s) | 9/9 |

Le pont WireGuard rouvre sa connexion à travers Tor sans toucher à l'interface : l'adresse et les connexions internes au tunnel restent en place. OpenVPN relance sa session. Il reçoit très probablement une nouvelle adresse, mais cela n'a pas été vérifié.

Pour donner un ordre de grandeur, la machine de l'auteur a subi une rupture toutes les 5 à 8 heures en usage réel. Ce chiffre est fragile : il couvre des périodes et des versions différentes.

## Limites

- Une machine, une ligne, une cible. Les résultats peuvent ne pas se transposer à un autre réseau.
- Coupures, montages à froid et endurance n'ont utilisé que des relais européens. L'explication par le protocole devrait tenir ailleurs, mais cela n'a pas été mesuré.
- Les rapports moyens du montant varient fortement sur quelques blocs : mieux vaut lire les médianes.
- Une heure d'endurance ne peut pas révéler des pannes rares.
- 8 des 32 blocs comparent deux serveurs IVPN différents. Sur les 24 autres, IVPN WG / IVPN OpenVPN a une médiane de 1,05 [moyenne 1,04, 0,93–1,16].
- Le torrc par défaut de Katakomba utilise `LongLivedPorts 1194,443`, sans le port 80 d'IVPN WireGuard. Le banc l'a ajouté.
- Le fonctionnement multi-comptes, les limites d'appareils, le renouvellement de clé Mullvad et l'usage à long terme d'IVPN WireGuard n'ont pas été testés.

### Données écartées

- **Blocs :** 8 blocs de la première série ont échoué parce que tout nouveau garde imposé était refusé, probablement à cause de l'échantillon de gardes de Tor arrivé à saturation. Ils étaient les derniers d'un ordre mélangé : ils ne favorisent donc pas les circuits lents. 12 blocs ont été ajoutés avec un état Tor neuf, surtout hors Europe.
- **Coupures :** les coupures sans interruption visible du tunnel (4) et les téléchargements Mullvad déjà terminés (2) n'ont pas été comptés.
- **Échecs de sonde :** quelques réinitialisations de connexion et délais dépassés sont apparus sur tous les tunnels. Elles sont retirées de la mesure concernée, et la plupart des blocs ont gardé au moins une valeur valide par test.
- **Connexion :** IVPN a refusé une connexion OpenVPN pendant le banc, cause inconnue. Le banc a continué sur un autre serveur et un autre compte.

## Données par bloc

Descendant moyen en KB/s, par bloc. Tor seul est une mesure unique prise juste avant les tunnels : elle peut donc être inférieure à celle d'un tunnel sur un circuit dont le débit varie.

| Région | Lieu | Tor seul | IVPN OpenVPN | Mullvad WG | IVPN WG | Serveurs IVPN (OpenVPN / WG) | Serveur Mullvad |
|---|---|---|---|---|---|---|---|
| Europe | AT | 451 | 332 | 477 | 377 | `at1` / `at2` | `at-vie-wg-003` |
| Europe | CH | 266 | 307 | 275 | 285 | `ch3` / `ch2` | `ch-zrh-wg-004` |
| Europe | ES | 77 | 38 | 17 | 33 | `es1` / `es1` | `es-mad-wg-205` |
| Europe | GB | 2622 | 2137 | 2569 | 2482 | `gb1` / `gb1` | `gb-lon-wg-005` |
| Europe | GB | 560 | 179 | 203 | 146 | `gb1` / `gb3` | `gb-lon-wg-006` |
| Europe | NL | 381 | 180 | 246 | 250 | `nl8` / `nl8` | `nl-ams-wg-202` |
| Europe | PL | 120 | 95 | 83 | 90 | `pl1` / `pl1` | `pl-waw-wg-103` |
| Europe | SE | 291 | 408 | 425 | 461 | `se1` / `se1` | `se-sto-wg-209` |
| Tor libre, VPN UE | CH | 3655 | 3747 | 3257 | 4095 | `ch1` / `ch1` | `ch-zrh-wg-503` |
| Tor libre, VPN UE | ES | 720 | 1378 | 1422 | 745 | `es1` / `es1` | `es-mad-wg-205` |
| Tor libre, VPN UE | ES | 612 | 948 | 86 | 779 | `es1` / `es1` | `es-mad-wg-204` |
| Tor libre, VPN UE | FR | 363 | 190 | 368 | 312 | `fr1` / `fr1` | `fr-par-wg-003` |
| Tor libre, VPN UE | GB | 2493 | 2375 | 2400 | 2912 | `gb1` / `gb1` | `gb-lon-wg-001` |
| Tor libre, VPN UE | IT | 468 | 320 | 339 | 375 | `it2` / `it2` | `it-mil-wg-003` |
| Tor libre, VPN UE | NL | 532 | 333 | 315 | 367 | `nl3` / `nl3` | `nl-ams-wg-202` |
| Tor libre, VPN UE | PL | 452 | 449 | 451 | 394 | `pl1` / `pl1` | `pl-waw-wg-102` |
| Amérique du Nord | CA | 659 | 208 | 216 | 196 | `ca-on1` / `ca-on2` | `ca-tor-wg-204` |
| Amérique du Nord | CA | 392 | 510 | 493 | 471 | `ca-on1` / `ca-on1` | `ca-tor-wg-001` |
| Amérique du Nord | CA | 60 | 54 | 42 | 50 | `ca-qc2` / `ca-qc2` | `ca-mtr-wg-306` |
| Amérique du Nord | US | 3258 | 1023 | 2667 | 2696 | `us-ny3` / `us-ny2` | `us-nyc-wg-606` |
| Amérique du Nord | US | 2372 | 1500 | 1295 | 1426 | `us-tx6` / `us-tx4` | `us-dal-wg-707` |
| Amérique du Nord | US | 1498 | 128 | 104 | 103 | `us-il4` / `us-il3` | `us-chi-wg-315` |
| Amérique du Nord | US | 969 | 933 | 743 | 754 | `us-wa2` / `us-wa2` | `us-sea-wg-402` |
| Amérique du Nord | US | 828 | 420 | 373 | 459 | `us-tx6` / `us-tx4` | `us-dal-wg-601` |
| Amérique du Nord | US | 292 | 155 | 176 | 140 | `us-ca5` / `us-ca5` | `us-lax-wg-404` |
| Asie-Pacifique | AU | 103 | 100 | 91 | 71 | `au-nsw2` / `au-nsw2` | `au-syd-wg-102` |
| Asie-Pacifique | HK | 1640 | 119 | 1501 | 162 | `hk3` / `hk3` | `hk-hkg-wg-201` |
| Asie-Pacifique | HK | 127 | 191 | 286 | 421 | `hk2` / `hk2` | `hk-hkg-wg-201` |
| Asie-Pacifique | JP | 3183 | 286 | 794 | 256 | `jp2` / `jp2` | `jp-tyo-wg-001` |
| Asie-Pacifique | JP | 583 | 337 | 463 | 349 | `jp2` / `jp2` | `jp-tyo-wg-203` |
| Asie-Pacifique | JP | 357 | 537 | 519 | 571 | `jp2` / `jp2` | `jp-tyo-wg-201` |
| Asie-Pacifique | SG | 305 | 476 | 557 | 514 | `sg1` / `sg1` | `sg-sin-wg-103` |
