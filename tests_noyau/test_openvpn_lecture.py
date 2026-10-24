"""Le modèle de lecture d'OpenVPN (tests/test_fuzz.py), confronté au vrai
binaire.  Le fuzzer ne prouve quelque chose que si ce modèle lit comme
OpenVPN : fins de bloc par préfixe, morceaux de 255 octets, commentaires,
guillemets, espaces.

Méthode : chaque « directive » des fichiers générés est une sonde inconnue
d'OpenVPN (kksondeN).  OpenVPN s'arrête sur la première qu'il lit et la
nomme ; le modèle doit prédire la même — ou l'erreur fatale qui la précède.
Aucune vraie directive n'est jamais soumise à OpenVPN."""

import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.test_fuzz import _ESPACES, _ligne_de_bloc, lecture_openvpn

OPENVPN = shutil.which("openvpn") or (os.path.exists("/usr/sbin/openvpn") and "/usr/sbin/openvpn")
_INCONNUE = re.compile(r"Unrecognized option or missing or extra parameter\(s\) in "
                       r".*?:(\d+): (.*) \(\d+\.\d+[^)]*\)\s*$", re.M)
BLOCS = ("ca", "cert", "key")
FICHIERS = 400


def _sonde(rng, n):
    nom = f"kksonde{n}"
    nom = rng.choice((nom, "--" + nom, f'"{nom}"', f"'{nom}'", nom))
    return (rng.choice(["", " ", "\t", "\v", "\f"] + _ESPACES[-4:])
            + nom + rng.choice(("", " 1", " a#b", " x;y", ' "a b"', " # c", "\r")))


def fichier_sondes(rng) -> str:
    lignes, n = [], 0
    for _ in range(rng.randint(1, 10)):
        tirage = rng.random()
        if tirage < 0.35:
            n += 1
            lignes.append(_sonde(rng, n))
        elif tirage < 0.45:
            lignes.append(rng.choice(("# c", "; c", "", "  ", "#kksonde0")))
        else:
            bloc = rng.choice(BLOCS)
            lignes.append(rng.choice(("", " ", "\t")) + f"<{bloc}>")
            for _ in range(rng.randint(0, 3)):
                if rng.random() < 0.4:
                    n += 1
                    lignes.append(_sonde(rng, n))
                else:
                    lignes.append(_ligne_de_bloc(rng, bloc))
            if rng.random() < 0.85:
                lignes.append(f"</{bloc}>")
    n += 1
    lignes.append(f"kksonde{n}")         # toujours une dernière sonde
    sep = rng.choice(("\n", "\r\n"))
    return sep.join(lignes) + sep


def openvpn_lit(chemin) -> tuple:
    """(« directive », nom) pour la première option inconnue lue, sinon
    (« fatal », message)."""
    r = subprocess.run([OPENVPN, "--config", chemin, "--verb", "1"],
                       capture_output=True, timeout=10, cwd=os.path.dirname(chemin))
    sortie = (r.stdout + r.stderr).decode("utf-8", "replace")
    m = _INCONNUE.search(sortie)
    if m:
        return "directive", m.group(2)
    return "fatal", sortie.strip().splitlines()[0] if sortie.strip() else f"code {r.returncode}"


@unittest.skipUnless(OPENVPN, "openvpn absent")
class LectureOpenvpnTest(unittest.TestCase):

    def test_le_modele_lit_comme_openvpn(self):
        rng = random.Random(2027)
        ecarts, sondes = [], 0
        with tempfile.TemporaryDirectory() as tmp:
            chemin = os.path.join(tmp, "f.ovpn")
            for k in range(FICHIERS):
                texte = fichier_sondes(rng)
                with open(chemin, "w", newline="") as f:
                    f.write(texte)
                attendu = next(iter(lecture_openvpn(texte)), ("fatal", "aucune directive"))
                reel = openvpn_lit(chemin)
                if attendu[0] == "directive":
                    sondes += 1
                if attendu[0] != reel[0] or (attendu[0] == "directive" and attendu[1] != reel[1]):
                    ecarts.append(f"fichier {k} : modèle {attendu}, OpenVPN {reel}\n{texte!r}")
        self.assertEqual(ecarts[:3], [], f"{len(ecarts)} écart(s)")
        self.assertGreater(sondes, FICHIERS // 3, "trop peu de sondes atteintes")

    def test_failles_de_la_3_12(self):
        """Les trois formes corrigées en v3.13.0, sur le vrai binaire."""
        with tempfile.TemporaryDirectory() as tmp:
            chemin = os.path.join(tmp, "f.ovpn")
            for texte in ("<ca>\nMIIB\n</ca>x\nkksonde1\n",
                          "<ca>\n" + "b" * 255 + "</ca>\nkksonde1\n",
                          "<ca>\n" + "b" * 200 + "\r" + "c" * 54 + "</ca>\nkksonde1\n"):
                with open(chemin, "w", newline="") as f:
                    f.write(texte)
                self.assertEqual(openvpn_lit(chemin), ("directive", "kksonde1"), repr(texte))
