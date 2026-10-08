"""Traductions : catalogues complets et cohérents avec le code, choix de la
langue, et règles d'écriture qui évitent les textes restés en français."""

import ast
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "outils"))

import i18n  # noqa: E402
import traductions  # noqa: E402

# Modules dont les textes s'affichent dans l'interface.
MODULES = sorted((RACINE / "gui").glob("*.py")) + [
    RACINE / n for n in ("validation.py", "adaptation.py", "main.py")]


class LecturePoTest(unittest.TestCase):

    def ecrire(self, texte):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        chemin = pathlib.Path(d.name) / "x.po"
        chemin.write_text(texte, encoding="utf-8")
        return chemin

    def test_entrees_pluriels_et_lignes_multiples(self):
        entrees, entete = i18n.lire_po(self.ecrire(
            'msgid ""\nmsgstr ""\n"Plural-Forms: nplurals=2; plural=(n != 1);\\n"\n\n'
            '#: a.py:1\nmsgid "Bonjour"\nmsgstr "Hello"\n\n'
            'msgid "{n} compte"\nmsgid_plural "{n} comptes"\n'
            'msgstr[0] "{n} account"\nmsgstr[1] "{n} accounts"\n\n'
            'msgid "Long"\nmsgstr ""\n"une "\n"deux"\n\n'
            'msgid "Guillemet \\"x\\"\\n"\nmsgstr "Quote \\"x\\"\\n"\n'))
        self.assertEqual(entrees["Bonjour"], "Hello")
        self.assertEqual(entrees[("{n} compte", "{n} comptes")], ["{n} account", "{n} accounts"])
        self.assertEqual(entrees["Long"], "une deux")
        self.assertEqual(entrees['Guillemet "x"\n'], 'Quote "x"\n')
        self.assertIn("Plural-Forms", entete)

    def test_douteux_et_vides_ignores(self):
        """Mieux vaut le texte source qu'une traduction à revoir."""
        entrees, _e = i18n.lire_po(self.ecrire(
            'msgid "Vide"\nmsgstr ""\n\n#, fuzzy\nmsgid "Douteux"\nmsgstr "Doubtful"\n\n'
            'msgid "Bon"\nmsgstr "Good"\n'))
        self.assertEqual(entrees, {"Bon": "Good"})


class ChoixDeLaLangueTest(unittest.TestCase):

    def tearDown(self):
        i18n.activer("fr")

    def test_langue_du_systeme(self):
        for environ, attendu in (
                ({"LANGUAGE": "de:en", "LANG": "fr_FR.UTF-8"}, "de"),
                ({"LANG": "pt_BR.UTF-8"}, "pt"),
                ({"LC_ALL": "it_IT.UTF-8", "LANG": "fr_FR.UTF-8"}, "it"),
                ({"LANG": "fr_FR.UTF-8"}, "fr"),
                ({"LANGUAGE": "ja:ko", "LANG": "es_ES.UTF-8"}, "es"),
                ({"LANG": "ja_JP.UTF-8"}, "en"),        # non traduite : anglais
                ({"LANG": "C.UTF-8"}, "en"),
                ({}, "en")):
            self.assertEqual(i18n.langue_systeme(environ), attendu, environ)

    def test_francais_texte_source(self):
        self.assertEqual(i18n.activer("fr"), "fr")
        self.assertEqual(i18n._("Se connecter"), "Se connecter")

    def test_chaque_langue_traduit(self):
        for code in i18n.LANGUES:
            if code == i18n.SOURCE:
                continue
            i18n.activer(code)
            self.assertNotEqual(i18n._("Se déconnecter"), "Se déconnecter", code)
            self.assertNotEqual(i18n.ngettext("{n} compte", "{n} comptes", 2),
                                "{n} comptes", code)

    def test_langue_inconnue_langue_du_systeme(self):
        with mock.patch.dict("os.environ", {"LANGUAGE": "", "LC_ALL": "",
                                            "LC_MESSAGES": "", "LANG": "de_DE.UTF-8"}):
            self.assertEqual(i18n.activer("xx"), "de")

    def test_repli_sur_l_anglais_puis_le_francais(self):
        with tempfile.TemporaryDirectory() as d:
            po = pathlib.Path(d)
            (po / "en.po").write_text('msgid "A"\nmsgstr "A-en"\n\nmsgid "B"\nmsgstr "B-en"\n')
            (po / "es.po").write_text('msgid "A"\nmsgstr "A-es"\n')
            with mock.patch.object(i18n, "PO_DIR", po):
                i18n.activer("es")
                self.assertEqual([i18n._(t) for t in "ABC"], ["A-es", "B-en", "C"])

    def test_pluriels_selon_la_langue(self):
        i18n.activer("en")
        self.assertEqual(i18n.ngettext("{n} compte", "{n} comptes", 1), "{n} account")
        self.assertEqual(i18n.ngettext("{n} compte", "{n} comptes", 0), "{n} accounts")
        i18n.activer("pt")                   # portugais du Brésil : 0 est singulier
        self.assertEqual(i18n.ngettext("{n} compte", "{n} comptes", 0), "{n} conta")

    def test_separateur_decimal(self):
        i18n.activer("en")
        self.assertEqual(i18n.nombre(6.25), "6.2")
        i18n.activer("de")
        self.assertEqual(i18n.nombre(6.3), "6,3")


class CataloguesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.entrees, cls.erreurs = traductions.extraire()

    def test_aucun_texte_construit_dans_une_traduction(self):
        """_(f"…") ne peut pas avoir de traduction : le texte change à
        chaque appel."""
        self.assertEqual(self.erreurs, [])

    def test_modele_a_jour(self):
        """po/katakomba.pot reflète le code : « outils/traductions.py
        mettre-a-jour » après avoir modifié un texte."""
        dans_le_pot = set()
        texte = traductions.POT.read_text(encoding="utf-8")
        for e in self.entrees:
            ligne = f"msgid {traductions._po(e.msgid)}"
            if ligne in texte:
                dans_le_pot.add(e.cle)
        self.assertEqual({e.cle for e in self.entrees} - dans_le_pot, set())
        # + 1 : l'en-tête (msgid "").
        self.assertEqual(texte.count("\nmsgid "), len(self.entrees) + 1)

    def test_chaque_langue_complete_et_coherente(self):
        for chemin in traductions.catalogues():
            self.assertTrue(chemin.exists(), chemin)
            self.assertEqual(traductions.verifier_po(chemin, self.entrees), [], chemin.name)

    def test_traductions_formatables(self):
        """Une accolade ou un format mal recopié ferait planter l'écran qui
        l'affiche, dans cette seule langue : chaque texte est formaté ici."""
        def valeurs(texte):
            return {nom: 7 for nom in traductions.champs(texte)}
        for chemin in traductions.catalogues():
            traduits, _e = i18n.lire_po(chemin)
            for e in self.entrees:
                t = traduits[e.cle]
                v = valeurs(e.msgid) | valeurs(e.pluriel)
                for forme in (t if isinstance(t, list) else [t]):
                    try:
                        forme.format(**v)
                    except (KeyError, ValueError, IndexError) as err:
                        self.fail(f"{chemin.name} : {forme!r} ({err})")

    def test_chaque_langue_a_son_catalogue(self):
        for code, nom in i18n.LANGUES.items():
            self.assertTrue(nom)
            if code != i18n.SOURCE:
                self.assertTrue((RACINE / "po" / f"{code}.po").exists(), code)


def _appels(noeud, noms):
    for n in ast.walk(noeud):
        if isinstance(n, ast.Call):
            f = n.func
            nom = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            if nom in noms:
                yield n


class RedactionTest(unittest.TestCase):
    """Règles qui gardent l'interface entièrement traduisible."""

    def test_rien_n_est_traduit_a_l_import(self):
        """Un _() évalué à l'import resterait dans la langue de ce moment-là :
        la langue peut changer pendant que l'interface tourne."""
        # main.py est un script : il active la langue juste avant.
        for f in (m for m in MODULES if m.name != "main.py"):
            arbre = ast.parse(f.read_text())
            fonctions = [n for n in ast.walk(arbre)
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))]
            dans_fonction = {id(c) for fn in fonctions for c in ast.walk(fn)}
            for appel in _appels(arbre, {"_", "ngettext"}):
                self.assertIn(id(appel), dans_fonction,
                              f"{f.name}:{appel.lineno} : traduit à l'import (N_ puis _ à l'usage)")

    def test_jamais_de_variable_nommee_souligne(self):
        """« valeurs, _ = … » ou « def rappel(self, *_) » masque _() dans
        toute la fonction, fonctions imbriquées comprises : l'appel suivant
        planterait (« 'tuple' object is not callable »)."""
        for f in MODULES:
            for n in ast.walk(ast.parse(f.read_text())):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    a = n.args
                    params = [*a.posonlyargs, *a.args, *a.kwonlyargs,
                              *(x for x in (a.vararg, a.kwarg) if x)]
                    for p in params:
                        self.assertNotEqual(p.arg, "_", f"{f.name}:{n.lineno} : paramètre « _ »")
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for c in ast.walk(n):
                        if isinstance(c, ast.Name) and c.id == "_" and isinstance(c.ctx, ast.Store):
                            self.fail(f"{f.name}:{c.lineno} : variable « _ » dans {n.name}()")

    PARAMETRES = {"title", "label", "subtitle", "description", "tooltip_text",
                  "placeholder_text", "button_label", "heading", "body", "comments"}
    METHODES = {"set_label", "set_title", "set_subtitle", "set_tooltip_text", "notifier",
                "set_description", "alerte", "confirmer", "rangee_bouton", "Avis"}
    # Noms propres et noms d'options, identiques dans toutes les langues.
    ADMIS = {"Katakomba", "GuardLifetime", "ExcludeExitNodes", "OK"}

    def _visible(self, noeud):
        if isinstance(noeud, ast.JoinedStr):
            return True
        return (isinstance(noeud, ast.Constant) and isinstance(noeud.value, str)
                and re.search(r"[A-Za-zÀ-ÿ]{2}", noeud.value) is not None
                and not re.fullmatch(r"[a-z0-9-]+", noeud.value)      # classe CSS
                and noeud.value not in self.ADMIS)

    def test_aucun_texte_visible_en_dur(self):
        """Tout texte passé à un titre, un libellé ou une notification passe
        par _() ; seuls les noms propres et les options de Tor y échappent."""
        for f in sorted((RACINE / "gui").glob("*.py")):
            for appel in (n for n in ast.walk(ast.parse(f.read_text()))
                          if isinstance(n, ast.Call)):
                for k in appel.keywords:
                    if k.arg in self.PARAMETRES and self._visible(k.value):
                        self.fail(f"{f.name}:{appel.lineno} : {k.arg}= non traduit")
                nom = (appel.func.attr if isinstance(appel.func, ast.Attribute)
                       else getattr(appel.func, "id", ""))
                if nom in self.METHODES:
                    for a in appel.args:
                        if self._visible(a) and not (isinstance(a, ast.JoinedStr)
                                                     and nom == "set_tooltip_text"):
                            self.fail(f"{f.name}:{appel.lineno} : {nom}() non traduit")

    def test_le_daemon_reste_en_francais(self):
        """Ses journaux sont lus par l'interface (événements) : jamais
        traduits, quelle que soit la langue du système."""
        for f in (RACINE / "daemon").glob("*.py"):
            self.assertNotIn("activer(", f.read_text(), f.name)
        import validation
        refus, _a = validation.analyser_ovpn("plugin /x.so\n")
        self.assertIn("refusée", refus[0])

    def test_journal_des_evenements_indifferent_a_la_langue(self):
        """Les motifs lisent le journal du daemon (français) : seuls les
        textes affichés sont traduits."""
        from gui import modele
        ligne = ("2026-09-25T15:14:21+02:00 h katakomba[1]: [2026-09-25 15:14:21] "
                 "[OK   ] Tunnel VPN actif.")
        try:
            i18n.activer("de")
            self.assertEqual(modele.evenements([ligne])[0][3], "Verbunden")
        finally:
            i18n.activer("fr")


if __name__ == "__main__":
    unittest.main()
