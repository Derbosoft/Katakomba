"""
Traductions de Katakomba (gettext).

Le texte source est en français, langue du projet : les chaînes marquées
_() dans le code SONT le texte français.  Les autres langues sont dans
po/<langue>.po, lues directement (pas de .mo à compiler, rien à générer à
l'installation).  Un texte absent d'un catalogue retombe sur l'anglais,
puis sur le français.

Tant que activer() n'est pas appelé, _() rend le texte tel quel : le daemon
et ses journaux restent en français quel que soit l'environnement.

Mise à jour des catalogues : python3 outils/traductions.py (voir ce fichier).
"""

import ast
import gettext
import os
from pathlib import Path

PO_DIR = Path(__file__).resolve().parent / "po"
SOURCE = "fr"
# Nom de chaque langue dans cette langue : c'est ainsi qu'on la reconnaît.
LANGUES = {
    "fr": "Français",
    "en": "English",
    "es": "Español",
    "de": "Deutsch",
    "it": "Italiano",
    "pt": "Português",
}
# Langue proposée quand celle du système n'est pas traduite.
REPLI = "en"
SEPARATEUR_DECIMAL = {"en": "."}           # virgule pour toutes les autres

_traduction = gettext.NullTranslations()
_langue = SOURCE


# ── Lecture d'un catalogue .po ───────────────────────────────────────────────

def _chaine(ligne: str) -> str:
    """« "texte \\"échappé\\"" » → texte.  ast : mêmes échappements que C."""
    return ast.literal_eval(ligne)


def lire_po(chemin) -> tuple:
    """(entrées, en-tête).  entrées : {msgid: msgstr} ou, pour un pluriel,
    {(msgid, msgid_plural): [msgstr[0], msgstr[1], …]}.  Les entrées
    « fuzzy » (à revoir) et les traductions vides sont ignorées : le texte
    source s'affiche plutôt qu'une traduction douteuse."""
    entrees, entete = {}, ""
    entree, drapeaux, champ = {}, set(), None

    def ranger():
        nonlocal entete
        mid = entree.get("msgid")
        if mid is None:
            return
        if mid == "":
            entete = entree.get("msgstr", "")
        elif "fuzzy" in drapeaux:
            return
        elif "msgid_plural" in entree:
            formes = [entree[k] for k in sorted(entree) if k.startswith("msgstr[")]
            if formes and all(formes):
                entrees[(mid, entree["msgid_plural"])] = formes
        elif entree.get("msgstr"):
            entrees[mid] = entree["msgstr"]

    def complete():
        return champ is not None and champ.startswith("msgstr")

    for brute in Path(chemin).read_text(encoding="utf-8").splitlines():
        ligne = brute.strip()
        if not ligne:
            continue
        if ligne.startswith("#"):
            if complete():                      # commentaire de l'entrée suivante
                ranger()
                entree, drapeaux, champ = {}, set(), None
            if ligne.startswith("#,"):
                drapeaux |= {d.strip() for d in ligne[2:].split(",")}
            continue
        if ligne.startswith('"'):
            if champ is not None:
                entree[champ] += _chaine(ligne)
            continue
        cle, _, reste = ligne.partition(" ")
        if cle in ("msgid", "msgctxt") and complete():
            ranger()
            entree, drapeaux = {}, set()
        champ = cle
        entree[champ] = _chaine(reste)
    ranger()
    return entrees, entete


class _Catalogue(gettext.NullTranslations):

    def __init__(self, chemin):
        super().__init__()
        self._entrees, entete = lire_po(chemin)
        self._pluriel = lambda n: int(n != 1)
        for ligne in entete.splitlines():
            if ligne.lower().startswith("plural-forms:"):
                expr = ligne.split("plural=", 1)[1].strip().rstrip(";")
                self._pluriel = gettext.c2py(expr)

    def gettext(self, message):
        texte = self._entrees.get(message)
        if texte is None:
            return self._fallback.gettext(message) if self._fallback else message
        return texte

    def ngettext(self, singulier, pluriel, n):
        formes = self._entrees.get((singulier, pluriel))
        if formes is None:
            if self._fallback:
                return self._fallback.ngettext(singulier, pluriel, n)
            return singulier if n == 1 else pluriel
        i = self._pluriel(n)
        return formes[i] if i < len(formes) else formes[-1]


# ── Choix de la langue ───────────────────────────────────────────────────────

def langue_systeme(environ=None) -> str:
    """Première langue de l'environnement que Katakomba connaît (LANGUAGE,
    puis LC_ALL, LC_MESSAGES, LANG, comme gettext) ; l'anglais sinon."""
    environ = os.environ if environ is None else environ
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        valeur = environ.get(var, "")
        if not valeur:
            continue
        for element in valeur.split(":"):
            code = element.split(".")[0].split("@")[0].split("_")[0].lower()
            if code in LANGUES:
                return code
        if var != "LANGUAGE" and valeur not in ("C", "POSIX", "C.UTF-8"):
            break           # locale définie mais non traduite : repli
    return REPLI


def activer(langue: str = "") -> str:
    """Active une langue (code de LANGUES), ou celle du système si vide ou
    inconnue.  Renvoie le code retenu."""
    global _traduction, _langue
    if langue not in LANGUES:
        langue = langue_systeme()
    _langue = langue
    if langue == SOURCE:
        _traduction = gettext.NullTranslations()
        return langue
    t = _Catalogue(PO_DIR / f"{langue}.po") if (PO_DIR / f"{langue}.po").exists() \
        else gettext.NullTranslations()
    if langue != REPLI and (PO_DIR / f"{REPLI}.po").exists():
        t.add_fallback(_Catalogue(PO_DIR / f"{REPLI}.po"))
    _traduction = t
    return langue


def langue() -> str:
    return _langue


# ── Fonctions de traduction ──────────────────────────────────────────────────

def _(texte: str) -> str:
    return _traduction.gettext(texte)


def ngettext(singulier: str, pluriel: str, n: int) -> str:
    return _traduction.ngettext(singulier, pluriel, n)


def N_(texte: str) -> str:
    """Marque un texte à traduire plus tard (tables, messages du daemon
    traduits à l'affichage) : l'extracteur le relève, rien n'est traduit ici."""
    return texte


def nombre(valeur: float, decimales: int = 1) -> str:
    """6.3 → « 6,3 » en français, « 6.3 » en anglais."""
    texte = f"{valeur:.{decimales}f}"
    return texte.replace(".", SEPARATEUR_DECIMAL.get(_langue, ","))
