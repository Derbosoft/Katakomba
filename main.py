#!/usr/bin/env python3
"""
Katakomba — interface graphique.
Usage : python3 main.py   (ou : katakomba gui)

L'interface ne requiert pas les droits root : la configuration est
accessible via le groupe « katakomba » (créé par install.sh) et les actions
systemctl privilégiées passent par pkexec/polkit.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gui.app import main
except (ImportError, ValueError) as e:
    # GTK 4 ou libadwaita absents : message en clair plutôt qu'une trace.
    import i18n
    i18n.activer()
    print(i18n._("Interface indisponible ({erreur}).").format(erreur=e) + "\n"
          + i18n._("Installez : {commande}").format(
              commande="sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1"),
          file=sys.stderr)
    sys.exit(1)

sys.exit(main())
