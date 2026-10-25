"""
Pont WireGuard → Tor (pont_wg.py) : format TunSafe, SOCKS5, aller-retour.

Le serveur est simulé par un encodeur qui reproduit celui de Proton
(wgToTunSafe dans conn/tcp_tls_utils.go), y compris les trames « données »
dont l'en-tête WireGuard est retiré.  Aucun accès réseau : tout passe par
127.0.0.1 ou des paires de sockets.
"""

import os
import pathlib
import random
import socket
import struct
import tempfile
import threading
import unittest

import pont_wg
from pont_wg import ErreurPont, Lecteur, encadrer


class EncodeurProton:
    """wgToTunSafe, ligne à ligne."""

    def __init__(self):
        self.prefixe = bytes(8)
        self.compteur = 0

    def trame(self, paquet):
        if len(paquet) < 16:
            return struct.pack(">H", len(paquet)) + paquet
        prefixe = paquet[:8]
        compteur, = struct.unpack_from("<Q", paquet, 8)
        if prefixe == self.prefixe and compteur == self.compteur + 1:
            self.compteur += 1
            taille = len(paquet) - 16
            return bytes([0b10 << 6 | taille >> 8, taille & 0xFF]) + paquet[16:]
        if paquet.startswith(b"\x04\x00\x00\x00"):
            self.prefixe, self.compteur = prefixe, compteur
        return struct.pack(">H", len(paquet)) + paquet


def donnees(index, compteur, charge=b"x" * 40):
    return b"\x04\x00\x00\x00" + struct.pack("<I", index) \
        + struct.pack("<Q", compteur) + charge


def lecteur(flux):
    vue = memoryview(flux)
    pos = [0]

    def lire(n):
        if pos[0] + n > len(vue):
            raise ErreurPont("fin du flux")
        morceau = bytes(vue[pos[0]:pos[0] + n])
        pos[0] += n
        return morceau
    return Lecteur(lire)


class Trames(unittest.TestCase):

    def test_trame_normale(self):
        paquet = b"\x01\x00\x00\x00" + bytes(144)      # initiation de poignée
        self.assertEqual(encadrer(paquet), b"\x00\x94" + paquet)
        self.assertEqual(lecteur(encadrer(paquet)).paquet(), paquet)

    def test_taille_hors_format(self):
        with self.assertRaises(ErreurPont):
            encadrer(b"")
        with self.assertRaises(ErreurPont):
            encadrer(bytes(0x4000))
        encadrer(bytes(0x3FFF))

    def test_trames_donnees_reconstruites(self):
        """Une suite comme celle d'un serveur : poignée, puis données
        compressées, une rupture de compteur, un changement de session."""
        paquets = [b"\x02\x00\x00\x00" + bytes(88)]
        paquets += [donnees(7, c) for c in range(0, 6)]
        paquets += [donnees(7, c) for c in range(9, 12)]       # trou
        paquets += [b"\x02\x00\x00\x00" + bytes(88)]
        paquets += [donnees(8, c) for c in range(0, 4)]        # nouvel index
        enc = EncodeurProton()
        flux = b"".join(enc.trame(p) for p in paquets)
        self.assertTrue(any(flux[i] >> 6 == 0b10 for i in range(len(flux))),
                        "l'encodeur doit produire des trames « données »")
        lec = lecteur(flux)
        self.assertEqual([lec.paquet() for _ in paquets], paquets)

    def test_hasard(self):
        alea = random.Random(5)
        for _ in range(200):
            enc, paquets, index, compteur = EncodeurProton(), [], 1, 0
            for _ in range(alea.randrange(1, 40)):
                tirage = alea.random()
                if tirage < 0.1:
                    paquets.append(bytes([alea.choice((1, 2, 3))]) + bytes(3)
                                   + os.urandom(alea.randrange(0, 100)))
                elif tirage < 0.15:
                    index += 1
                else:
                    compteur += alea.choice((1, 1, 1, 2, 0))
                    paquets.append(donnees(index, compteur,
                                           os.urandom(alea.randrange(16, 1400))))
            lec = lecteur(b"".join(enc.trame(p) for p in paquets))
            self.assertEqual([lec.paquet() for _ in paquets], paquets)

    def test_trame_invalide(self):
        with self.assertRaises(ErreurPont):
            lecteur(b"\x00\x00").paquet()                  # vide
        with self.assertRaises(ErreurPont):
            lecteur(b"\x40\x05hello").paquet()             # type 0b01
        with self.assertRaises(ErreurPont):
            lecteur(b"\x00\x10abc").paquet()               # tronquée


class Socks(unittest.TestCase):

    def _proxy(self, reponse=b"\x05\x00\x00\x01" + bytes(6)):
        """Proxy SOCKS5 minimal : note la demande, répond, puis fait écho."""
        ecoute = socket.create_server(("127.0.0.1", 0))
        recu = {}

        def servir():
            c, _ = ecoute.accept()
            with c:
                lire = pont_wg.lecture_exacte(c)
                recu["salut"] = lire(3)
                c.sendall(b"\x05\x00")
                recu["demande"] = lire(10)
                c.sendall(reponse)
                if reponse[1] == 0:
                    c.sendall(lire(5))
            ecoute.close()
        threading.Thread(target=servir, daemon=True).start()
        return f"127.0.0.1:{ecoute.getsockname()[1]}", recu

    def test_connexion(self):
        socks, recu = self._proxy()
        s = pont_wg.ouvrir_socks(socks, "185.107.56.211", 443)
        with s:
            s.sendall(b"bonjo")
            self.assertEqual(pont_wg.lecture_exacte(s)(5), b"bonjo")
        self.assertEqual(recu["salut"], b"\x05\x01\x00")
        self.assertEqual(recu["demande"], b"\x05\x01\x00\x01"
                         + bytes([185, 107, 56, 211]) + b"\x01\xbb")

    def test_refus(self):
        socks, _ = self._proxy(b"\x05\x05\x00\x01" + bytes(6))
        with self.assertRaisesRegex(ErreurPont, "code 5"):
            pont_wg.ouvrir_socks(socks, "185.107.56.211", 443)


class FauxEmballage:
    """Emballage TunSafe sur une paire de sockets, sans TLS ni réseau."""

    def __init__(self):
        self.cote_serveur = []
        self.connexions = 0

    def __str__(self):
        return "faux emballage"

    def ouvrir(self, socks):
        self.connexions += 1
        a, b = socket.socketpair()
        self.cote_serveur.append(b)
        return pont_wg.LiaisonTunSafe(a), "test"


class AllerRetour(unittest.TestCase):
    """Le pont complet ; l'emballage remplacé par une paire de sockets."""

    def setUp(self):
        self.emb = FauxEmballage()
        self.pont = pont_wg.Pont("127.0.0.1:0", self.emb, "aucun",
                                 journal=lambda m: None)
        threading.Thread(target=self.pont.monter, daemon=True).start()
        self.wg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.wg.bind(("127.0.0.1", 0))
        self.wg.settimeout(5)

    def tearDown(self):
        self.pont.arreter()
        self.wg.close()
        for s in self.emb.cote_serveur:
            s.close()

    def _envoyer(self, paquet):
        self.wg.sendto(paquet, self.pont.udp.getsockname())

    def _serveur(self):
        for _ in range(100):
            if self.emb.cote_serveur:
                s = self.emb.cote_serveur[-1]
                s.settimeout(5)
                return s
            threading.Event().wait(0.02)
        self.fail("le pont n'a pas ouvert de connexion")

    def test_aller_retour_et_reconnexion(self):
        initiation = b"\x01\x00\x00\x00" + bytes(144)
        self._envoyer(initiation)
        serveur = self._serveur()
        self.assertEqual(Lecteur(pont_wg.lecture_exacte(serveur)).paquet(),
                         initiation)

        enc = EncodeurProton()
        retour = [b"\x02\x00\x00\x00" + bytes(88)] \
            + [donnees(3, c) for c in range(5)]
        serveur.sendall(b"".join(enc.trame(p) for p in retour))
        for attendu in retour:
            self.assertEqual(self.wg.recvfrom(65535)[0], attendu)

        # Le serveur coupe : le paquet suivant rouvre une connexion.
        serveur.close()
        self.emb.cote_serveur.clear()
        threading.Event().wait(0.1)
        self._envoyer(donnees(9, 1))
        serveur = self._serveur()
        self.assertEqual(Lecteur(pont_wg.lecture_exacte(serveur)).paquet(),
                         donnees(9, 1))
        self.assertEqual(self.emb.connexions, 2)

    def test_sni_stable(self):
        self.assertEqual(pont_wg.sni_pour("185.107.56.211:443"),
                         pont_wg.sni_pour("185.107.56.211:443"))
        self.assertIn(pont_wg.sni_pour("185.107.56.211:443"), pont_wg.SNI)


class UdpSurTcp(unittest.TestCase):
    """Mullvad : udp-over-tcp (mullvad/udp-over-tcp, src/forward_traffic.rs)."""

    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.b.settimeout(5)
        self.liaison = pont_wg.LiaisonUdpTcp(self.a)

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_format(self):
        self.liaison.envoyer(b"\x01" + bytes(147))
        self.assertEqual(self.b.recv(1000), b"\x00\x94\x01" + bytes(147))

    def test_taille_hors_format(self):
        for paquet in (b"", bytes(0x10000)):
            with self.assertRaises(ErreurPont):
                self.liaison.envoyer(paquet)

    def test_lecture_morcelee_et_paquet_vide(self):
        """tcp2udp découpe le flux où il veut, et relaie un datagramme vide
        tel quel : le pont l'ignore."""
        paquets = [b"\x02" + bytes(91), b"", donnees(7, 1), bytes(1500)]
        flux = b"".join(struct.pack(">H", len(p)) + p for p in paquets)

        def envoyer_en_morceaux():
            rng = random.Random(1)
            i = 0
            while i < len(flux):
                n = rng.randint(1, 7)
                self.b.sendall(flux[i:i + n])
                i += n
        threading.Thread(target=envoyer_en_morceaux, daemon=True).start()
        self.a.settimeout(5)
        recus = [self.liaison.recevoir() for _ in range(3)]
        self.assertEqual(recus, [p for p in paquets if p])

    def test_coupure(self):
        self.b.sendall(b"\x00\x10" + bytes(4))
        self.b.close()
        with self.assertRaises(ErreurPont):
            self.liaison.recevoir()

    def test_emballage(self):
        emb = pont_wg.emballage_depuis("mullvad", "185.65.134.82:443")
        self.assertIsInstance(emb, pont_wg.Mullvad)
        self.assertIn("udp-over-tcp", str(emb))


class FauxTcp2Udp:
    """tcp2udp de Mullvad, en local : chaque connexion TCP reçoit sa propre
    socket UDP vers le « serveur WireGuard », un écho qui retourne les
    paquets.  Écrit d'après forward_traffic.rs, sans le code du pont."""

    def __init__(self):
        self.wg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.wg.bind(("127.0.0.1", 0))
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.connexions = []
        for cible in (self._echo, self._accepter):
            threading.Thread(target=cible, daemon=True).start()

    @property
    def adresse(self):
        return "127.0.0.1:%d" % self.srv.getsockname()[1]

    def _echo(self):
        try:
            while True:
                p, origine = self.wg.recvfrom(65535)
                self.wg.sendto(p[::-1], origine)
        except OSError:
            pass

    def _accepter(self):
        try:
            while True:
                c, _ = self.srv.accept()
                self.connexions.append(c)
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.connect(self.wg.getsockname())
                for cible in (self._tcp2udp, self._udp2tcp):
                    threading.Thread(target=cible, args=(c, u), daemon=True).start()
        except OSError:
            pass

    @staticmethod
    def _tcp2udp(c, u):
        tampon = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    return
                tampon += d
                while len(tampon) >= 2:
                    n, = struct.unpack(">H", tampon[:2])
                    if len(tampon) < 2 + n:
                        break
                    u.send(tampon[2:2 + n])
                    tampon = tampon[2 + n:]
        except OSError:
            pass

    @staticmethod
    def _udp2tcp(c, u):
        try:
            while True:
                p = u.recv(65535)
                c.sendall(struct.pack(">H", len(p)) + p)
        except OSError:
            pass

    def fermer(self):
        for s in [self.srv, self.wg] + self.connexions:
            s.close()


class MullvadAllerRetour(unittest.TestCase):
    """Le pont complet, emballage Mullvad, contre un faux tcp2udp."""

    def test_aller_retour(self):
        serveur = FauxTcp2Udp()
        self.addCleanup(serveur.fermer)
        pont = pont_wg.Pont("127.0.0.1:0", pont_wg.Mullvad(serveur.adresse),
                            "aucun", journal=lambda m: None)
        threading.Thread(target=pont.monter, daemon=True).start()
        self.addCleanup(pont.arreter)
        wg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(wg.close)
        wg.settimeout(5)
        rng = random.Random(2)
        paquets = [bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 1400)))
                   for _ in range(200)]
        for p in paquets:
            wg.sendto(p, pont.udp.getsockname())
            self.assertEqual(wg.recvfrom(65535)[0], p[::-1])
        self.assertEqual(len(serveur.connexions), 1, "une seule connexion TCP")


class TLSMemoireTest(unittest.TestCase):
    """Lecture et écriture simultanées sur un vrai TLS 1.3 local.  Avec un
    SSLSocket partagé entre deux fils, le pont mourait environ une connexion
    sur dix (OpenSSL n'accepte pas deux fils sur un même objet SSL)."""

    @classmethod
    def setUpClass(cls):
        from tests_noyau import test_wireguard
        if test_wireguard.x509 is None:              # pragma: no cover
            raise unittest.SkipTest("python3-cryptography absent")
        certificat = test_wireguard.certificat
        import ssl
        cls._tmp = tempfile.TemporaryDirectory()
        dossier = pathlib.Path(cls._tmp.name)
        certificat(dossier)
        cls.contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.contexte.load_cert_chain(dossier / "cert.pem", dossier / "cle.pem")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_echo_sous_charge(self):
        ecoute = socket.create_server(("127.0.0.1", 0))

        def servir():
            c, _ = ecoute.accept()
            with self.contexte.wrap_socket(c, server_side=True) as t:
                lire = pont_wg.lecture_exacte(t)
                try:
                    while True:
                        taille, = struct.unpack(">H", lire(2))
                        t.sendall(struct.pack(">H", taille) + lire(taille))
                except (OSError, ErreurPont):
                    pass
            ecoute.close()
        threading.Thread(target=servir, daemon=True).start()

        emb = pont_wg.Proton(f"127.0.0.1:{ecoute.getsockname()[1]}")
        liaison, version = emb.ouvrir("aucun")
        self.assertEqual(version, "TLSv1.3")
        paquets = [os.urandom(random.Random(i).randrange(32, 1400)) for i in range(3000)]
        recus, erreurs = [], []

        def lire():
            try:
                for _ in paquets:
                    recus.append(liaison.recevoir())
            except Exception as e:                   # pragma: no cover
                erreurs.append(e)
        lecteur = threading.Thread(target=lire)
        lecteur.start()
        for p in paquets:
            liaison.envoyer(p)
        lecteur.join(30)
        liaison.fermer()
        self.assertFalse(erreurs, erreurs)
        self.assertEqual(recus, paquets)


if __name__ == "__main__":
    unittest.main()
