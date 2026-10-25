"""
Emballage IVPN (pont_wg.py) : VMess « AEAD » sur TCP, déguisé en HTTP.

Le serveur est un modèle écrit d'après v2fly/v2ray-core : OpenVMessAEADHeader
(proxy/vmess/aead/encrypt.go), lecture de l'en-tête de requête
(encoding/server.go), en-tête de réponse AEAD, morceaux sans chiffrement.
Une erreur d'octet, d'ordre ou de clé côté client fait échouer le modèle,
comme elle ferait refuser la connexion par un vrai serveur.
"""

import hashlib
import ipaddress
import socket
import struct
import threading
import time
import unittest
import zlib

import pont_wg
from pont_wg import ErreurPont, kdf, kdf16

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:                                    # pragma: no cover
    AESGCM = None

UUID = "27de860d-5601-412d-8b71-baa048a94b98"


class ServeurVMess:
    """Ce que fait un serveur V2Ray d'une requête VMess UDP."""

    def __init__(self, identifiant=UUID):
        self.cle_cmd = pont_wg.cle_commande(identifiant)

    def ouvrir_entete(self, lire, instant=None):
        auth_id = lire(16)
        dechiffreur = Cipher(algorithms.AES(kdf16(self.cle_cmd, "AES Auth ID Encryption")),
                             modes.ECB()).decryptor()
        clair = dechiffreur.update(auth_id) + dechiffreur.finalize()
        t, = struct.unpack(">Q", clair[:8])
        if struct.unpack(">I", clair[12:])[0] != zlib.crc32(clair[:12]):
            raise ValueError("AuthID : utilisateur inconnu")
        if abs(t - (time.time() if instant is None else instant)) > 120:
            raise ValueError("AuthID : horodatage hors fenêtre")
        longueur_chiffree, nonce = lire(18), lire(8)
        longueur, = struct.unpack(">H", AESGCM(
            kdf16(self.cle_cmd, "VMess Header AEAD Key_Length", auth_id, nonce)).decrypt(
            kdf(self.cle_cmd, "VMess Header AEAD Nonce_Length", auth_id, nonce)[:12],
            longueur_chiffree, auth_id))
        entete = AESGCM(kdf16(self.cle_cmd, "VMess Header AEAD Key", auth_id, nonce)).decrypt(
            kdf(self.cle_cmd, "VMess Header AEAD Nonce", auth_id, nonce)[:12],
            lire(longueur + 16), auth_id)
        return self.analyser(entete)

    @staticmethod
    def analyser(e):
        if struct.unpack(">I", e[-4:])[0] != pont_wg.fnv1a32(e[:-4]):
            raise ValueError("FNV de l'en-tête faux")
        r = {"version": e[0], "iv": e[1:17], "cle": e[17:33], "v": e[33],
             "option": e[34], "bourrage": e[35] >> 4, "securite": e[35] & 0x0F,
             "commande": e[37], "port": struct.unpack(">H", e[38:40])[0]}
        famille = e[40]
        taille = {1: 4, 3: 16}[famille]
        r["adresse"] = str(ipaddress.ip_address(e[41:41 + taille]))
        if len(e) != 41 + taille + r["bourrage"] + 4:
            raise ValueError("longueur d'en-tête incohérente")
        return r

    @staticmethod
    def reponse(requete, commande=b""):
        cle = hashlib.sha256(requete["cle"]).digest()[:16]
        iv = hashlib.sha256(requete["iv"]).digest()[:16]
        entete = bytes([requete["v"], 0, 0, 0])
        lg = AESGCM(kdf16(cle, "AEAD Resp Header Len Key")).encrypt(
            kdf(iv, "AEAD Resp Header Len IV")[:12], struct.pack(">H", len(entete)), None)
        corps = AESGCM(kdf16(cle, "AEAD Resp Header Key")).encrypt(
            kdf(iv, "AEAD Resp Header IV")[:12], entete, None)
        return lg + corps


def lecteur_de(donnees):
    pos = [0]

    def lire(n):
        if pos[0] + n > len(donnees):
            raise ErreurPont("fin du flux")
        m = donnees[pos[0]:pos[0] + n]
        pos[0] += n
        return m
    return lire


@unittest.skipIf(AESGCM is None, "python3-cryptography absent")
class Vmess(unittest.TestCase):

    def test_kdf_vecteur_v2ray(self):
        """proxy/vmess/aead/kdf_test.go, TestKDFValue."""
        self.assertEqual(
            kdf(b"Demo Key for KDF Value Test", "Demo Path for KDF Value Test",
                "Demo Path for KDF Value Test2", "Demo Path for KDF Value Test3").hex(),
            "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892")

    def test_fnv1a(self):
        self.assertEqual(pont_wg.fnv1a32(b""), 0x811C9DC5)
        self.assertEqual(pont_wg.fnv1a32(b"a"), 0xE40C292C)

    def test_cle_commande(self):
        """MD5(uuid ‖ constante), common/protocol/id.go."""
        import uuid
        self.assertEqual(pont_wg.cle_commande(UUID), hashlib.md5(
            uuid.UUID(UUID).bytes + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest())

    def test_entete_lu_par_le_serveur(self):
        for cible in ("95.211.198.167:15351", "[2a00:1:2::3]:51820"):
            session = pont_wg.SessionVMess(UUID, cible)
            r = ServeurVMess().ouvrir_entete(lecteur_de(session.entete()))
            hote, port = pont_wg.adresse(cible)
            self.assertEqual((r["adresse"], r["port"]), (hote, port))
            self.assertEqual(r["version"], 1)
            self.assertEqual(r["commande"], 2)                 # UDP
            self.assertEqual(r["securite"], 5)                 # aucune
            self.assertEqual(r["option"], 0x01)                # morceaux
            self.assertEqual((r["cle"], r["iv"], r["v"]),
                             (session.cle_corps, session.iv_corps, session.v_reponse))

    def test_mauvais_identifiant_refuse(self):
        session = pont_wg.SessionVMess("00000000-0000-0000-0000-000000000001",
                                       "95.211.198.167:15351")
        with self.assertRaises(ValueError):
            ServeurVMess().ouvrir_entete(lecteur_de(session.entete()))

    def test_horloge_decalee_refusee(self):
        session = pont_wg.SessionVMess(UUID, "95.211.198.167:15351")
        with self.assertRaises(ValueError):
            ServeurVMess().ouvrir_entete(
                lecteur_de(session.entete(instant=time.time() - 600)))

    def test_reponse(self):
        session = pont_wg.SessionVMess(UUID, "95.211.198.167:15351")
        r = ServeurVMess().ouvrir_entete(lecteur_de(session.entete()))
        session.lire_reponse(lecteur_de(ServeurVMess.reponse(r)))
        autre = dict(r, v=(r["v"] + 1) % 256)
        with self.assertRaises(ErreurPont):
            session.lire_reponse(lecteur_de(ServeurVMess.reponse(autre)))
        with self.assertRaisesRegex(ErreurPont, "indéchiffrable"):
            session.lire_reponse(lecteur_de(bytes(64)))

    def test_entete_http(self):
        pont_wg.lire_entete_http(lecteur_de(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nreste"))
        with self.assertRaisesRegex(ErreurPont, "refuse"):
            pont_wg.lire_entete_http(lecteur_de(b"HTTP/1.1 404 Not Found\r\n\r\n"))
        with self.assertRaisesRegex(ErreurPont, "trop long"):
            pont_wg.lire_entete_http(lecteur_de(b"X" * 9000))

    def test_requete_http_au_chemin_attendu(self):
        """Le serveur ne vérifie que le chemin : « / »."""
        ligne = pont_wg.HTTP_REQUETE.split(b"\r\n", 1)[0]
        self.assertEqual(ligne, b"GET / HTTP/1.1")
        self.assertTrue(pont_wg.HTTP_REQUETE.endswith(b"\r\n\r\n"))


@unittest.skipIf(AESGCM is None, "python3-cryptography absent")
class LiaisonComplete(unittest.TestCase):
    """L'emballage IVPN de bout en bout, contre le modèle de serveur, sur une
    vraie connexion TCP locale."""

    def test_aller_retour(self):
        ecoute = socket.create_server(("127.0.0.1", 0))
        recu, erreurs = [], []

        def servir():
            try:
                c, _ = ecoute.accept()
                with c:
                    c.settimeout(5)
                    lire = pont_wg.lecture_exacte(c)
                    tampon = b""
                    while not tampon.endswith(b"\r\n\r\n"):
                        tampon += lire(1)
                    assert tampon.startswith(b"GET / HTTP/1.1\r\n")
                    requete = ServeurVMess().ouvrir_entete(lire)
                    for _ in range(3):
                        taille, = struct.unpack(">H", lire(2))
                        recu.append(lire(taille))
                    c.sendall(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"
                              + ServeurVMess.reponse(requete)
                              + b"".join(struct.pack(">H", len(p)) + p
                                         for p in (b"retour-1", b"retour-2"))
                              + b"\x00\x00")
            except Exception as e:                      # pragma: no cover
                erreurs.append(e)
            finally:
                ecoute.close()

        threading.Thread(target=servir, daemon=True).start()
        emb = pont_wg.Ivpn(f"127.0.0.1:{ecoute.getsockname()[1]}",
                           "95.211.198.167:15351", UUID)
        liaison, detail = emb.ouvrir("aucun")
        try:
            for p in (b"\x01" + bytes(147), b"donnees", b"x" * 1400):
                liaison.envoyer(p)
            self.assertEqual(liaison.recevoir(), b"retour-1")
            self.assertEqual(liaison.recevoir(), b"retour-2")
            with self.assertRaisesRegex(ErreurPont, "fin de la session"):
                liaison.recevoir()
        finally:
            liaison.fermer()
        self.assertFalse(erreurs, erreurs)
        self.assertEqual(recu, [b"\x01" + bytes(147), b"donnees", b"x" * 1400])
        self.assertEqual(detail, "VMess")


if __name__ == "__main__":
    unittest.main()
