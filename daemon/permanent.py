"""
Blocage permanent (v4.13.0) : posé au démarrage de la machine, avant le
réseau, par katakomba-blocage.service.

    python3 -m daemon.permanent poser

Mêmes règles que celles du daemon, calculées par le même code : le blocage
hors tunnel (KATAKOMBA_KILL*, sorties et routage) et, si le partage LAN est
activé, le filtrage de ses clients (KATAKOMBA_LAN_FWD), qui ne sortent alors
que par un tunnel encore absent.  Le daemon les remplace d'un seul tenant à
son démarrage, sans instant à découvert.

Sans le réglage (fichier /var/lib/katakomba/blocage-permanent, posé par
« sudo katakomba blocage-permanent on »), rien n'est fait.  Code de sortie 1
si une règle n'a pas pu être posée : systemd marque l'unité en échec, et
« katakomba blocage-permanent status » le montre.
"""

import sys

from . import Daemon


def poser() -> int:
    d = Daemon()
    if not d._blocage_permanent():
        d._log("Blocage permanent désactivé : rien à poser.")
        return 0
    blocage = d._kill_switch_on()
    lan = d._poser_lan_permanent()
    if blocage and lan:
        d._log("Blocage permanent posé : rien ne sort hors du tunnel, sauf Tor et le "
               "réseau local.", "OK")
        return 0
    d._log("Blocage permanent INCOMPLET : cause ci-dessus.", "ERROR")
    return 1


def main(argv) -> int:
    if argv[1:] == ["poser"]:
        return poser()
    print("Usage : python3 -m daemon.permanent poser", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
