# Contributing to Katakomba

*[Version française plus bas](#contribuer-à-katakomba).*

Contributions are welcome: bug reports, fixes, translations, and tests with real VPN providers.

## Reporting a bug

Open an [issue](https://github.com/Derbosoft/Katakomba/issues/new/choose) and attach the output of:

```bash
katakomba doctor
katakomba logs 100
```

Remove your credentials and real IP addresses first. For a security problem, follow [SECURITY.md](SECURITY.md) instead.

## Code

- Python 3, standard library only for the daemon; GTK 4 + libadwaita for the interface.
- **The source language is French**: comments, log messages and the `_()` strings are written in French. Translations live in `po/`.
- Every change comes with tests. The suite never runs a system command: `iptables`, `ip`, `resolvectl`, `openvpn`, `tor`… are intercepted. Keep it that way (`tests/test_safety.py` checks it).

```bash
bash run-tests.sh          # the whole suite, safe on a machine with the tunnel up
bash run-tests.sh -v       # test by test
```

- After changing a visible text: `python3 outils/traductions.py mettre-a-jour`.
- After changing the source code on an installed machine: `sudo bash install.sh` (the service runs the copy in `/opt/katakomba`, not your clone).

## Translations

English, Spanish, German, Italian and Portuguese were translated from French **without review by native speakers**. Corrections go straight into `po/<language>.po`. To add a language, see [Translations in the README](README.md#translations).

## VPN providers

Katakomba is tested with iVPN and ProtonVPN. If it works (or fails) with another provider over TCP, an issue saying so is useful.

---

# Contribuer à Katakomba

Les contributions sont bienvenues : bugs, correctifs, traductions, essais avec d'autres fournisseurs VPN.

- **Bug** : ouvrez une [issue](https://github.com/Derbosoft/Katakomba/issues/new/choose) avec la sortie de `katakomba doctor` et `katakomba logs 100`, sans identifiants ni IP réelles. Pour une faille de sécurité, voir [SECURITY.md](SECURITY.md).
- **Code** : la langue source est le français (commentaires, journal, chaînes `_()`). Chaque changement s'accompagne de tests ; la suite n'exécute aucune commande système (`bash run-tests.sh`).
- **Traductions** : relectures bienvenues dans `po/<langue>.po`.
- **Fournisseurs** : testé avec iVPN et ProtonVPN ; signalez ce qui marche ou non ailleurs.
