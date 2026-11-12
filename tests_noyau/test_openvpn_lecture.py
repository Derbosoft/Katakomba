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


# Certificat d'essai (CN=essai, sans clé) : OpenVPN exige une autorité pour
# démarrer ; aucune poignée de main TLS n'a lieu ici.
_CA = """-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIUZ7aynl0uRVEL+XXCAowHuJfCX7cwCgYIKoZIzj0EAwIw
EDEOMAwGA1UEAwwFZXNzYWkwIBcNMjYxMTEyMDYzNzI4WhgPMjEyNjEwMTkwNjM3
MjhaMBAxDjAMBgNVBAMMBWVzc2FpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
7qxF7a1e8ORU7I2DcfaJ0bUMxtfA4yn9TKY921xWipsiAtuVRWP3K3I2Lh+7bVcK
8fChPB2kelS4D+3ifL70HKNTMFEwHQYDVR0OBBYEFJvi27t4m+zgquFBtyUh3gvU
m/ztMB8GA1UdIwQYMBaAFJvi27t4m+zgquFBtyUh3gvUm/ztMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAN7NfK+b/1SalF1wyEIZxQRcMFroBXL2
+MrJ3j8u1c1UAiA17GCI04BqZGRUiz0tGyrRs61iBYp5LbfFJR7VPleWMg==
-----END CERTIFICATE-----
"""
PORT_SERVEUR = 11194


@unittest.skipUnless(OPENVPN, "openvpn absent")
@unittest.skipUnless(os.environ.get("KATAKOMBA_NOYAU") == "1",
                     "lancer avec bash tests_noyau/lancer.sh (port 9050 pris ici)")
class PassageParTorTest(unittest.TestCase):
    """v4.7.0 : avec les options du daemon, OpenVPN rejoint le proxy de Tor
    (127.0.0.1:9050), jamais le serveur en direct — blocs <connection>
    compris, qui ignorent tout « --socks-proxy » donné après eux."""

    PLAT = f"client\nproto tcp\nremote 127.0.0.1 {PORT_SERVEUR}\n"
    BLOCS = (f"client\n<connection>\nremote 127.0.0.1 {PORT_SERVEUR} tcp\n"
             f"</connection>\n<connection>\nremote 127.0.0.1 {PORT_SERVEUR} tcp\n"
             "socks-proxy 127.0.0.1 1\n</connection>\n")

    def _ou_va_openvpn(self, texte, copie=True) -> set:
        """Ports locaux qu'OpenVPN a joints : 9050 (Tor) ou le serveur."""
        import socket
        import threading
        import validation
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        joints, ecoutes = set(), []
        for port in (9050, PORT_SERVEUR):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(4)
            s.settimeout(0.2)
            ecoutes.append(s)
        fin = threading.Event()

        def ecouter(s):
            while not fin.is_set():
                try:
                    c, _ = s.accept()
                except OSError:
                    continue
                joints.add(s.getsockname()[1])
                c.close()

        fils = [threading.Thread(target=ecouter, args=(s,), daemon=True) for s in ecoutes]
        for f in fils:
            f.start()
        texte += f"<ca>\n{_CA}</ca>\n"
        with tempfile.TemporaryDirectory() as tmp:
            conf, auth = os.path.join(tmp, "c.conf"), os.path.join(tmp, "auth")
            with open(conf, "w", newline="") as f:
                f.write(validation.preparer_copie_ovpn(texte) if copie else texte)
            with open(auth, "w") as f:
                f.write("u\np\n")
            os.chmod(auth, 0o600)
            # Les options du daemon (daemon/openvpn.py), dans le même ordre.
            p = subprocess.Popen(
                [OPENVPN, "--config", conf, "--auth-user-pass", auth,
                 "--script-security", "1", "--verb", "3", "--connect-timeout", "60",
                 "--connect-retry", "1", "--connect-retry-max", "1",
                 "--socks-proxy", "127.0.0.1", "9050", "--dev", "null",
                 "--ifconfig-noexec", "--route-noexec", "--disable-dco"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=tmp)
            try:
                for _ in range(60):
                    if joints or p.poll() is not None:
                        break
                    fin.wait(0.1)
                fin.wait(0.5)            # une seconde connexion éventuelle
            finally:
                p.kill()
                p.wait()
                fin.set()
                for f in fils:
                    f.join()
                for s in ecoutes:
                    s.close()
        return joints

    def test_fichier_plat(self):
        self.assertEqual(self._ou_va_openvpn(self.PLAT), {9050})

    def test_blocs_connection(self):
        self.assertEqual(self._ou_va_openvpn(self.BLOCS), {9050})

    def test_sans_la_copie_les_blocs_sortaient_sans_tor(self):
        """Le défaut corrigé, sur le vrai binaire : c'est bien la copie — le
        proxy en tête — qui protège, pas la ligne de commande."""
        self.assertEqual(self._ou_va_openvpn(self.BLOCS.replace(
            "socks-proxy 127.0.0.1 1\n", ""), copie=False), {PORT_SERVEUR})
