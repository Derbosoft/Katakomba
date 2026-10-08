"""
Génère les icônes symboliques propres à Katakomba (assets/icones/).

GTK recolore une icône symbolique en REMPLISSANT ses formes : un tracé au
trait (stroke) y serait rempli comme un polygone.  Les icônes sont donc
dessinées ici au trait, puis converties en contours pleins.

Outil de développement seulement (requiert shapely) :
    python3 outils/icones.py
Les SVG produits sont livrés tels quels ; rien de ceci ne s'exécute à
l'installation.
"""

import math
from pathlib import Path

from shapely import affinity
from shapely.geometry import LineString, Point, Polygon
from shapely.ops import unary_union

SORTIE = Path(__file__).resolve().parents[1] / "assets" / "icones"
TRAIT = 1.5
ROND = {"cap_style": "round", "join_style": "round"}


def cercle(cx, cy, r):
    return Point(cx, cy).buffer(r, 64).exterior.buffer(TRAIT / 2, 16)


def ellipse(cx, cy, rx, ry):
    c = Point(0, 0).buffer(1, 64)
    return affinity.translate(affinity.scale(c, rx, ry), cx, cy).exterior.buffer(TRAIT / 2, 16)


def trait(*points):
    return LineString(points).buffer(TRAIT / 2, 16, **ROND)


def disque(cx, cy, r):
    return Point(cx, cy).buffer(r, 32)


def chevron(bout, depuis, longueur=3.0, angle=40):
    """Pointe de flèche en bout de segment (deux branches au trait)."""
    dx, dy = bout[0] - depuis[0], bout[1] - depuis[1]
    n = math.hypot(dx, dy)
    ux, uy = dx / n, dy / n
    branches = []
    for signe in (1, -1):
        a = math.radians(180 + signe * angle)
        vx = ux * math.cos(a) - uy * math.sin(a)
        vy = ux * math.sin(a) + uy * math.cos(a)
        branches.append(trait(bout, (bout[0] + vx * longueur, bout[1] + vy * longueur)))
    return unary_union(branches)


def goutte(cx, cy, r, pointe):
    """Couche d'oignon : un cercle étiré en pointe vers le haut."""
    corps = Point(cx, cy).buffer(r, 64)
    dx = r * 0.62
    haut = Polygon([(cx - dx, cy - r * 0.78), (cx, pointe), (cx + dx, cy - r * 0.78)])
    return unary_union([corps, haut.buffer(0.35, 16)]).exterior.buffer(TRAIT / 2, 16)


def tor():
    """Oignon : deux couches en goutte, un cœur, une pousse."""
    return unary_union([
        goutte(8, 9.9, 5.3, 2.4), goutte(8, 10.6, 2.6, 6.4), disque(8, 10.9, 0.9),
        trait((8, 2.6), (8, 1.1)), trait((8, 1.9), (10.3, 0.9)),
    ])


def internet():
    """Globe : contour, méridien, équateur."""
    return unary_union([
        cercle(8, 8, 6.25), ellipse(8, 8, 2.7, 6.25), trait((1.75, 8), (14.25, 8)),
    ]).intersection(Point(8, 8).buffer(7.0, 64))


def diagnostic():
    """Pouls : le diagnostic ausculte la connexion."""
    return trait((1, 8.5), (4.4, 8.5), (6.2, 3.6), (9.4, 12.6), (11.2, 8.5), (15, 8.5))


def exclusions():
    """Bifurcation : une partie du trafic contourne le tunnel."""
    centre = (8, 9)
    gauche, droite = (3.6, 4.2), (12.4, 4.2)
    return unary_union([
        trait((8, 14.6), centre), trait(centre, gauche), trait(centre, droite),
        chevron(gauche, centre), chevron(droite, centre),
    ])


def _anneau(coords):
    points = list(coords)[:-1]
    d = f"M{points[0][0]:.2f} {points[0][1]:.2f}"
    d += "".join(f"L{x:.2f} {y:.2f}" for x, y in points[1:])
    return d + "Z"


def en_svg(forme) -> str:
    polygones = [forme] if isinstance(forme, Polygon) else list(forme.geoms)
    d = ""
    for p in polygones:
        d += _anneau(p.exterior.coords)
        d += "".join(_anneau(t.coords) for t in p.interiors)
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" '
            f'viewBox="0 0 16 16"><path d="{d}" fill-rule="evenodd"/></svg>\n')


ICONES = {"katakomba-tor-symbolic": tor, "katakomba-internet-symbolic": internet,
          "katakomba-diagnostic-symbolic": diagnostic,
          "katakomba-exclusions-symbolic": exclusions}


if __name__ == "__main__":
    SORTIE.mkdir(parents=True, exist_ok=True)
    for nom, dessin in ICONES.items():
        (SORTIE / f"{nom}.svg").write_text(en_svg(dessin()))
        print(SORTIE / f"{nom}.svg")
