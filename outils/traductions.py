"""
Catalogues de traduction de Katakomba.

    python3 outils/traductions.py extraire      po/katakomba.pot depuis le code
    python3 outils/traductions.py mettre-a-jour  po/*.po complétés (textes nouveaux
                                                 vides, textes disparus retirés)
    python3 outils/traductions.py verifier      manques et incohérences (code 1)

Le texte source est en français : les chaînes marquées _(), N_() et
ngettext() dans le code.  Pas besoin de gettext (xgettext, msgfmt) : le
code Python est lu avec ast, les .po sont lus tels quels par i18n.py.

Pour ajouter une langue : ajouter son code à i18n.LANGUES, créer
po/<code>.po (copie de katakomba.pot, en-tête Language/Plural-Forms
renseigné), puis traduire chaque msgstr.
"""

import ast
import re
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))

import i18n  # noqa: E402

PO_DIR = RACINE / "po"
POT = PO_DIR / "katakomba.pot"
FONCTIONS_SIMPLES = {"_", "N_"}
# Diagnostic : du Python dans un document bash (« doctor » du CLI).
CLI = RACINE / "katakomba-cli.sh"
_DOCTOR = re.compile(r'python3 - "\$DAEMON_DIR" "\$\{@:2\}" << \'PYEOF\'\n(.*?)\nPYEOF',
                     re.S)


@dataclass
class Entree:
    msgid: str
    pluriel: str = ""
    refs: list = field(default_factory=list)

    @property
    def cle(self):
        return (self.msgid, self.pluriel) if self.pluriel else self.msgid


def sources():
    """(nom affiché, code Python, décalage de ligne) de chaque source."""
    fichiers = sorted((RACINE / "gui").glob("*.py")) + [
        RACINE / n for n in ("main.py", "validation.py", "adaptation.py")]
    for f in fichiers:
        yield f.relative_to(RACINE).as_posix(), f.read_text(encoding="utf-8"), 0
    texte = CLI.read_text(encoding="utf-8")
    m = _DOCTOR.search(texte)
    if m:
        yield CLI.name, m.group(1), texte[:m.start(1)].count("\n")


def _nom(noeud):
    """_(…), mais aussi i18n._(…)."""
    f = noeud.func
    if isinstance(f, ast.Name):
        return f.id
    return f.attr if isinstance(f, ast.Attribute) else ""


def extraire():
    """(entrées dans l'ordre d'apparition, erreurs).  Erreur : un texte
    construit (f-string, concaténation dynamique) passé à _() ne peut pas
    avoir de traduction."""
    entrees, erreurs = {}, []
    for nom, code, decalage in sources():
        for noeud in ast.walk(ast.parse(code)):
            if not isinstance(noeud, ast.Call):
                continue
            fonction = _nom(noeud)
            ligne = noeud.lineno + decalage
            if fonction in FONCTIONS_SIMPLES and noeud.args:
                arg = noeud.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    e = Entree(arg.value)
                elif isinstance(arg, ast.JoinedStr):
                    erreurs.append(f"{nom}:{ligne} : f-string dans {fonction}()")
                    continue
                else:
                    continue            # _(variable) : texte venu d'ailleurs
            elif fonction == "ngettext" and len(noeud.args) >= 2:
                a, b = noeud.args[:2]
                if not all(isinstance(x, ast.Constant) and isinstance(x.value, str)
                           for x in (a, b)):
                    erreurs.append(f"{nom}:{ligne} : ngettext() sans textes constants")
                    continue
                e = Entree(a.value, b.value)
            else:
                continue
            if not e.msgid:
                continue
            entrees.setdefault(e.cle, e).refs.append(f"{nom}:{ligne}")
    return list(entrees.values()), erreurs


# ── Écriture ─────────────────────────────────────────────────────────────────

def _po(texte: str) -> str:
    return '"' + (texte.replace("\\", "\\\\").replace('"', '\\"')
                  .replace("\n", "\\n").replace("\t", "\\t")) + '"'


def _bloc(e: Entree, traduction=None) -> str:
    lignes = [f"#: {' '.join(e.refs)}"] if e.refs else []
    lignes.append(f"msgid {_po(e.msgid)}")
    if e.pluriel:
        lignes.append(f"msgid_plural {_po(e.pluriel)}")
        formes = traduction or ["", ""]
        lignes += [f"msgstr[{i}] {_po(f)}" for i, f in enumerate(formes)]
    else:
        lignes.append(f"msgstr {_po(traduction or '')}")
    return "\n".join(lignes)


ENTETE_POT = ('msgid ""\nmsgstr ""\n'
              '"Project-Id-Version: Katakomba\\n"\n'
              '"Language: \\n"\n'
              '"MIME-Version: 1.0\\n"\n'
              '"Content-Type: text/plain; charset=UTF-8\\n"\n'
              '"Content-Transfer-Encoding: 8bit\\n"\n'
              '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"\n')


def ecrire_pot(entrees):
    PO_DIR.mkdir(exist_ok=True)
    POT.write_text("# Katakomba — textes à traduire (source : français).\n"
                   "# Généré par outils/traductions.py extraire : ne pas modifier.\n"
                   + ENTETE_POT + "\n" + "\n\n".join(_bloc(e) for e in entrees) + "\n",
                   encoding="utf-8")


def _entete_brut(chemin: Path) -> str:
    """En-tête d'un .po tel qu'écrit (commentaires et msgid "")."""
    texte = chemin.read_text(encoding="utf-8")
    fin = texte.find("\n\n")
    return texte if fin < 0 else texte[:fin]


def mettre_a_jour(entrees, chemin: Path):
    existantes, _ = i18n.lire_po(chemin)
    blocs = [_bloc(e, existantes.get(e.cle)) for e in entrees]
    chemin.write_text(_entete_brut(chemin) + "\n\n" + "\n\n".join(blocs) + "\n",
                      encoding="utf-8")


# ── Vérification ─────────────────────────────────────────────────────────────

def champs(texte: str) -> set:
    """Noms des champs {nom} d'un texte à formater (spécification ignorée)."""
    try:
        return {nom for _, nom, _, _ in string.Formatter().parse(texte) if nom is not None}
    except ValueError:
        return {"<accolade non fermée>"}


def verifier_po(chemin: Path, entrees) -> list:
    traductions, entete = i18n.lire_po(chemin)
    problemes = []
    if "Plural-Forms:" not in entete:
        problemes.append(f"{chemin.name} : en-tête Plural-Forms manquant")
    for e in entrees:
        t = traductions.get(e.cle)
        if t is None:
            problemes.append(f"{chemin.name} : non traduit : {e.msgid!r}")
            continue
        attendus = champs(e.msgid) | champs(e.pluriel)
        for forme in (t if isinstance(t, list) else [t]):
            if champs(forme) - attendus or (champs(forme) != attendus and not e.pluriel):
                problemes.append(f"{chemin.name} : champs {sorted(champs(forme))} au lieu "
                                 f"de {sorted(attendus)} : {e.msgid!r}")
    connus = {e.cle for e in entrees}
    problemes += [f"{chemin.name} : texte disparu du code : {c!r}"
                  for c in traductions if c not in connus]
    return problemes


def catalogues():
    return [PO_DIR / f"{code}.po" for code in i18n.LANGUES if code != i18n.SOURCE]


if __name__ == "__main__":
    commande = sys.argv[1] if len(sys.argv) > 1 else ""
    entrees, erreurs = extraire()
    for e in erreurs:
        print("ERREUR", e, file=sys.stderr)
    if commande == "extraire":
        ecrire_pot(entrees)
        print(f"{POT.relative_to(RACINE)} : {len(entrees)} textes")
    elif commande == "mettre-a-jour":
        ecrire_pot(entrees)
        for c in catalogues():
            if c.exists():
                mettre_a_jour(entrees, c)
                print(f"{c.relative_to(RACINE)} mis à jour")
    elif commande == "verifier":
        problemes = [p for c in catalogues() for p in
                     (verifier_po(c, entrees) if c.exists() else [f"{c.name} absent"])]
        for p in problemes:
            print(p)
        print(f"{len(entrees)} textes, {len(problemes)} problème(s)")
        sys.exit(1 if problemes or erreurs else 0)
    else:
        print(__doc__)
        sys.exit(2)
    sys.exit(1 if erreurs else 0)
