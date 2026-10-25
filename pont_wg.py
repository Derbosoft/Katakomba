"""
Pont WireGuard → Tor : les paquets UDP de WireGuard passent dans un flux TCP.

Tor ne transporte que du TCP.  Certains fournisseurs acceptent WireGuard
« emballé » dans une connexion TCP, chacun à sa façon :

  proton   TLS sur TCP 443, paquets en trames TunSafe (mode « Stealth »).
  ivpn     VMess (protocole de V2Ray) sur TCP 80, déguisé en requête HTTP ;
           le serveur V2Ray remet les paquets, en UDP, au serveur WireGuard.
  mullvad  udp-over-tcp sur TCP 443 : chaque paquet précédé de sa taille.

Le pont fait la conversion :

  WireGuard du noyau ──UDP──► 127.0.0.1:51820 (ce pont)
                                   │ emballage, SOCKS5
                                   ▼
                              Tor ──► serveur du fournisseur, TCP

Dans tous les cas, ce qui entoure WireGuard ne sert qu'à passer : il n'est ni
vérifié (certificat TLS de Proton) ni chiffré (VMess sans chiffrement, comme
dans l'application d'IVPN ; udp-over-tcp de Mullvad).  L'authentification et le chiffrement, c'est
WireGuard qui les assure, de bout en bout.

La connexion TCP est ouverte au premier paquet, et rouverte au suivant si
elle tombe (circuit Tor coupé, serveur redémarré…).  Les paquets perdus
entre-temps sont ceux qu'aurait perdus l'UDP : WireGuard les renvoie.

Usage :
  python3 pont_wg.py --emballage proton --serveur 185.107.56.211:443
  python3 pont_wg.py --emballage ivpn --serveur 149.22.83.102:80 \\
          --cible 149.22.83.100:15351 --uuid 27de860d-…
  python3 pont_wg.py --emballage mullvad --serveur 185.65.134.82:443
  … --socks 127.0.0.1:9050 (défaut), unix:/chemin, ou « aucun » (essai direct)
"""

import argparse
import functools
import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import struct
import sys
import threading
import time
import uuid
import zlib

ECOUTE_DEFAUT = "127.0.0.1:51820"
DELAI_CONNEXION = 30           # s — un circuit Tor neuf peut être lent
ATTENTE_MAX     = 30           # s entre deux tentatives, au plus


class ErreurPont(Exception):
    pass


def lecture_exacte(sock):
    def lire(n):
        morceaux, reste = [], n
        while reste:
            m = sock.recv(reste)
            if not m:
                raise ErreurPont("connexion fermée par le serveur")
            morceaux.append(m)
            reste -= len(m)
        return b"".join(morceaux)
    return lire


# ── Connexion TCP : directe ou par SOCKS5 (Tor) ──────────────────────────────

def adresse(texte: str):
    hote, _, port = texte.rpartition(":")
    return hote.strip("[]"), int(port)


def ouvrir_socks(socks: str, hote: str, port: int):
    """Socket TCP vers hote:port à travers le proxy SOCKS5 (sans mot de passe).
    Un nom d'hôte est transmis tel quel : Tor le résout à la sortie."""
    if socks.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        cible = socks[len("unix:"):]
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cible = adresse(socks)
    s.settimeout(DELAI_CONNEXION)
    try:
        s.connect(cible)
        lire = lecture_exacte(s)
        s.sendall(b"\x05\x01\x00")
        if lire(2) != b"\x05\x00":
            raise ErreurPont("le proxy SOCKS refuse la connexion sans mot de passe")
        try:
            ip = ipaddress.ip_address(hote)
            dest = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        except ValueError:
            nom = hote.encode("idna")
            dest = b"\x03" + bytes([len(nom)]) + nom
        s.sendall(b"\x05\x01\x00" + dest + struct.pack(">H", port))
        reponse = lire(4)
        if reponse[1] != 0:
            raise ErreurPont(f"SOCKS : échec de la connexion (code {reponse[1]})")
        if reponse[3] == 3:
            lire(lire(1)[0])
        else:
            lire({1: 4, 4: 16}.get(reponse[3], 0))
        lire(2)                                     # adresse liée, ignorée
        return s
    except BaseException:
        s.close()
        raise


def connexion_tcp(socks: str, hote: str, port: int):
    if socks == "aucun":
        brut = socket.create_connection((hote, port), timeout=DELAI_CONNEXION)
    else:
        brut = ouvrir_socks(socks, hote, port)
    if brut.family != socket.AF_UNIX:
        brut.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return brut


# ── Proton : TLS + trames TunSafe ────────────────────────────────────────────
#
# Format TunSafe (TunSafe, network_common.cpp ; ProtonVPN/wireguard-go,
# conn/tcp_tls_utils.go) : 2 octets d'en-tête, gros-boutiste.  Les 2 bits de
# poids fort donnent le type, les 14 autres la taille de ce qui suit.
#   0b00  normal   le paquet WireGuard complet
#   0b10  données  un paquet de données WireGuard sans ses 16 premiers octets,
#                  identiques au paquet précédent sauf le compteur, qui vaut
#                  un de plus : le destinataire les reconstruit.
# Le pont n'envoie que des trames normales — c'est permis, l'autre type n'est
# qu'une économie de 16 octets — mais il doit savoir lire les deux.

TYPE_NORMAL  = 0b00
TYPE_DONNEES = 0b10
TAILLE_MAX   = 0x3FFF          # 14 bits
WG_DONNEES   = b"\x04\x00\x00\x00"   # type « transport data », 3 octets nuls
WG_ENTETE    = 16              # type, réservé, index du destinataire, compteur
WG_PREFIXE   = 8               # l'en-tête sans le compteur

# Noms annoncés dans le TLS (SNI), repris de l'application Proton
# (conn/server_name_utils).  Derrière Tor, seul le nœud de sortie les voit.
SNI = (
    "accounts.google.com", "android.googleapis.com", "api.amazon.com",
    "cdn.ampproject.org", "cloudflare.com", "dl.google.com", "dns.google",
    "edge.microsoft.com", "fonts.googleapis.com", "github.com",
    "login.live.com", "play.googleapis.com", "s3.amazonaws.com",
    "www.googleapis.com", "www.gstatic.com",
)


def encadrer(paquet: bytes) -> bytes:
    """Trame normale : en-tête de type 0b00, puis le paquet entier."""
    if not 0 < len(paquet) <= TAILLE_MAX:
        raise ErreurPont(f"paquet de {len(paquet)} octets : hors format")
    return struct.pack(">H", len(paquet)) + paquet


class Lecteur:
    """Relit les trames d'un flux et rend les paquets WireGuard complets.

    `lire(n)` doit rendre exactement n octets, ou lever une exception.
    """

    def __init__(self, lire):
        self._lire = lire
        self._prefixe = bytes(WG_PREFIXE)
        self._compteur = 0

    def paquet(self) -> bytes:
        entete, = struct.unpack(">H", self._lire(2))
        genre, taille = entete >> 14, entete & TAILLE_MAX
        if taille == 0:
            raise ErreurPont("trame vide")
        if genre == TYPE_NORMAL:
            paquet = self._lire(taille)
            if len(paquet) >= WG_ENTETE and paquet.startswith(WG_DONNEES):
                self._prefixe = paquet[:WG_PREFIXE]
                self._compteur, = struct.unpack_from("<Q", paquet, WG_PREFIXE)
        elif genre == TYPE_DONNEES:
            # Le compteur n'avance que sur les paquets de données, comme dans
            # TunSafe (network_common.cpp).  Le client de Proton l'avance sur
            # toute trame : faux dès qu'une poignée de main s'intercale.
            self._compteur = (self._compteur + 1) & 0xFFFFFFFFFFFFFFFF
            paquet = (self._prefixe + struct.pack("<Q", self._compteur)
                      + self._lire(taille))
        else:
            raise ErreurPont(f"type de trame inconnu : {genre:#04b}")
        return paquet


class LiaisonTunSafe:
    """Trames TunSafe sur un flux : `flux` fournit sendall, recv et close
    (socket ordinaire, ou TLSMemoire)."""

    def __init__(self, flux):
        self.sock = flux
        self._lecteur = Lecteur(lecture_exacte(flux))

    def envoyer(self, paquet):
        self.sock.sendall(encadrer(paquet))

    def recevoir(self):
        return self._lecteur.paquet()

    def fermer(self):
        self.sock.close()


class TLSMemoire:
    """Client TLS dont OpenSSL ne touche jamais le réseau (ssl.SSLObject).

    Le pont lit et écrit en même temps, depuis deux fils.  Un SSLSocket ne
    le supporte pas : OpenSSL interdit d'utiliser un même objet SSL depuis
    deux fils, et en TLS 1.3 la lecture traite des messages de session
    pendant que l'autre fil chiffre.  Le pont mourait alors sans un mot,
    environ une connexion sur dix (vu sur un vrai noyau, voir
    tests_noyau/test_wireguard.py).

    Ici, OpenSSL ne travaille qu'en mémoire, sous un verrou jamais tenu
    pendant une attente du réseau.  Les octets chiffrés partent dans l'ordre
    où OpenSSL les a produits : le verrou d'envoi est pris avant de rendre
    celui d'OpenSSL."""

    def __init__(self, brut, contexte, sni):
        self.brut = brut
        self._entree = ssl.MemoryBIO()
        self._sortie = ssl.MemoryBIO()
        self._ssl = contexte.wrap_bio(self._entree, self._sortie, server_hostname=sni)
        self._verrou = threading.Lock()
        self._envoi = threading.Lock()
        self._clair = bytearray()
        while True:                                    # poignée de main
            try:
                self._ssl.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._expedier(self._sortie.read())
                self._recevoir_brut()
        self._expedier(self._sortie.read())

    def version(self):
        return self._ssl.version()

    def _expedier(self, donnees):
        if donnees:
            self.brut.sendall(donnees)

    def _recevoir_brut(self):
        donnees = self.brut.recv(65536)
        if not donnees:
            raise ErreurPont("connexion fermée par le serveur")
        self._entree.write(donnees)

    def sendall(self, donnees):
        with self._verrou:
            self._ssl.write(donnees)
            chiffre = self._sortie.read()
            self._envoi.acquire()
        try:
            self._expedier(chiffre)
        finally:
            self._envoi.release()

    def recv(self, n):
        """Comme socket.recv : au plus n octets, b"" en fin de connexion.
        Un seul fil lit."""
        while not self._clair:
            try:
                self._recevoir_brut()
            except ErreurPont:
                return b""
            with self._verrou:
                try:
                    while True:
                        self._clair += self._ssl.read(65536)
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLZeroReturnError:
                    return b""
                # Réponse éventuelle d'OpenSSL (mise à jour de clé TLS 1.3).
                chiffre = self._sortie.read()
                self._envoi.acquire()
            try:
                self._expedier(chiffre)
            finally:
                self._envoi.release()
        morceau = bytes(self._clair[:n])
        del self._clair[:n]
        return morceau

    def close(self):
        self.brut.close()


class Proton:
    def __init__(self, serveur: str, sni=None):
        self.serveur = serveur
        self.sni = sni or sni_pour(serveur)

    def __str__(self):
        return f"Proton {self.serveur} (TLS, SNI {self.sni})"

    def ouvrir(self, socks):
        brut = connexion_tcp(socks, *adresse(self.serveur))
        contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexte.check_hostname = False
        contexte.verify_mode = ssl.CERT_NONE        # voir l'en-tête du module
        contexte.set_alpn_protocols(["h2", "http/1.1"])
        try:
            tls = TLSMemoire(brut, contexte, self.sni)
        except BaseException:
            brut.close()
            raise
        brut.settimeout(None)
        return LiaisonTunSafe(tls), tls.version()


def sni_pour(serveur: str) -> str:
    """Même nom à chaque reconnexion vers un serveur donné."""
    hote, _ = adresse(serveur)
    return SNI[int(ipaddress.ip_address(hote)) % len(SNI)]


# ── IVPN : VMess sur TCP, déguisé en HTTP ────────────────────────────────────
#
# Repris de v2fly/v2ray-core (proxy/vmess/aead, proxy/vmess/encoding,
# transport/internet/headers/http) et de la configuration de l'application
# d'IVPN (ivpn/desktop-app, daemon/v2r/config.go) :
#   - en-tête HTTP de camouflage, à l'aller comme au retour ; le serveur ne
#     vérifie que le chemin, « / » ;
#   - en-tête VMess « AEAD » (alterId 0), commande UDP, vers la cible ;
#   - corps sans chiffrement (« security: none »), découpé en morceaux :
#     2 octets de taille, puis un paquet WireGuard par morceau.
# Le chiffrement de l'en-tête exige AES-GCM : python3-cryptography, chargé
# seulement pour cet emballage.

VMESS_SEL       = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
VMESS_VERSION   = 1
OPTION_MORCEAUX = 0x01            # RequestOptionChunkStream
SECU_AUCUNE     = 5               # SecurityType_NONE
CMD_UDP         = 2
HTTP_REQUETE = (
    "GET / HTTP/1.1\r\n"
    "Host: www.inet-telecom.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Connection: keep-alive\r\n"
    "Pragma: no-cache\r\n"
    "\r\n").encode()
HTTP_ENTETE_MAX = 8192


def _hmac_sur(h, cle, message):
    """HMAC dont la fonction de hachage est `h` (bloc de 64 octets)."""
    if len(cle) > 64:
        cle = h(cle)
    cle = cle.ljust(64, b"\0")
    return h(bytes(c ^ 0x5C for c in cle) + h(bytes(c ^ 0x36 for c in cle) + message))


def kdf(cle: bytes, *chemin) -> bytes:
    """KDF de VMess : HMAC emboîtés, chaque élément du chemin servant de clé
    à un HMAC dont la fonction de hachage est le niveau précédent."""
    def base(m):
        return hmac.new(b"VMess AEAD KDF", m, hashlib.sha256).digest()
    h = base
    for element in chemin:
        if isinstance(element, str):
            element = element.encode()
        h = functools.partial(_hmac_sur, h, element)
    return h(cle)


def kdf16(cle, *chemin):
    return kdf(cle, *chemin)[:16]


def cle_commande(identifiant: str) -> bytes:
    return hashlib.md5(uuid.UUID(identifiant).bytes + VMESS_SEL).digest()


def fnv1a32(donnees: bytes) -> int:
    h = 0x811C9DC5
    for octet in donnees:
        h = ((h ^ octet) * 0x01000193) & 0xFFFFFFFF
    return h


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ErreurPont("emballage IVPN : python3-cryptography est requis "
                         "(sudo apt install python3-cryptography)") from None
    return Cipher, algorithms, modes, AESGCM


def sceller_entete(cle_cmd: bytes, donnees: bytes, instant=None, alea=os.urandom):
    """SealVMessAEADHeader."""
    Cipher, algorithms, modes, AESGCM = _aes()
    t = int(time.time() if instant is None else instant)
    clair = struct.pack(">Q", t) + alea(4)
    clair += struct.pack(">I", zlib.crc32(clair))
    chiffreur = Cipher(algorithms.AES(kdf16(cle_cmd, "AES Auth ID Encryption")),
                       modes.ECB()).encryptor()
    auth_id = chiffreur.update(clair) + chiffreur.finalize()
    nonce = alea(8)
    longueur = AESGCM(kdf16(cle_cmd, "VMess Header AEAD Key_Length", auth_id, nonce)) \
        .encrypt(kdf(cle_cmd, "VMess Header AEAD Nonce_Length", auth_id, nonce)[:12],
                 struct.pack(">H", len(donnees)), auth_id)
    corps = AESGCM(kdf16(cle_cmd, "VMess Header AEAD Key", auth_id, nonce)) \
        .encrypt(kdf(cle_cmd, "VMess Header AEAD Nonce", auth_id, nonce)[:12],
                 donnees, auth_id)
    return auth_id + longueur + nonce + corps


class SessionVMess:
    """Une requête VMess UDP : en-tête à l'aller, en-tête de réponse au
    retour, puis des morceaux dans les deux sens."""

    def __init__(self, identifiant: str, cible: str, alea=os.urandom):
        self.cle_cmd = cle_commande(identifiant)
        hasard = alea(33)
        self.cle_corps, self.iv_corps = hasard[:16], hasard[16:32]
        self.v_reponse = hasard[32]
        self.cible = adresse(cible)
        self._alea = alea

    def entete(self, instant=None) -> bytes:
        hote, port = self.cible
        ip = ipaddress.ip_address(hote)
        bourrage = self._alea(1)[0] % 16
        e = (bytes([VMESS_VERSION]) + self.iv_corps + self.cle_corps
             + bytes([self.v_reponse, OPTION_MORCEAUX,
                      bourrage << 4 | SECU_AUCUNE, 0, CMD_UDP])
             + struct.pack(">H", port)               # le port AVANT l'adresse
             + bytes([1 if ip.version == 4 else 3]) + ip.packed
             + self._alea(bourrage))
        e += struct.pack(">I", fnv1a32(e))
        return sceller_entete(self.cle_cmd, e, instant, self._alea)

    def lire_reponse(self, lire):
        """DecodeResponseHeader (AEAD)."""
        *_, AESGCM = _aes()
        cle = hashlib.sha256(self.cle_corps).digest()[:16]
        iv = hashlib.sha256(self.iv_corps).digest()[:16]
        try:
            longueur, = struct.unpack(">H", AESGCM(kdf16(cle, "AEAD Resp Header Len Key"))
                                      .decrypt(kdf(iv, "AEAD Resp Header Len IV")[:12],
                                               lire(18), None))
            entete = AESGCM(kdf16(cle, "AEAD Resp Header Key")).decrypt(
                kdf(iv, "AEAD Resp Header IV")[:12], lire(longueur + 16), None)
        except Exception as e:
            if isinstance(e, ErreurPont):
                raise
            raise ErreurPont("réponse VMess indéchiffrable (identifiant "
                             "refusé, ou horloge de la machine décalée)") from None
        if len(entete) < 4 or entete[0] != self.v_reponse:
            raise ErreurPont("réponse VMess inattendue")


def lire_entete_http(lire):
    """Lit la réponse HTTP de camouflage, jusqu'à la ligne vide."""
    tampon = b""
    while not tampon.endswith(b"\r\n\r\n"):
        if len(tampon) > HTTP_ENTETE_MAX:
            raise ErreurPont("en-tête HTTP du serveur trop long")
        tampon += lire(1)
    statut = tampon.split(b"\r\n", 1)[0]
    if b" 200 " not in statut + b" ":
        raise ErreurPont(f"le serveur V2Ray refuse : {statut.decode(errors='replace')[:60]}")


class LiaisonVMess:
    def __init__(self, sock, session):
        self.sock = sock
        self._session = session
        self._lire = lecture_exacte(sock)
        self._reponse_lue = False

    def envoyer(self, paquet):
        if not 0 < len(paquet) <= 0xFFFF:
            raise ErreurPont(f"paquet de {len(paquet)} octets : hors format")
        self.sock.sendall(struct.pack(">H", len(paquet)) + paquet)

    def recevoir(self):
        if not self._reponse_lue:
            lire_entete_http(self._lire)
            self._session.lire_reponse(self._lire)
            self._reponse_lue = True
        taille, = struct.unpack(">H", self._lire(2))
        if taille == 0:
            raise ErreurPont("fin de la session VMess")
        return self._lire(taille)

    def fermer(self):
        self.sock.close()


class Ivpn:
    def __init__(self, serveur: str, cible: str, identifiant: str):
        self.serveur = serveur
        self.cible = cible
        self.identifiant = identifiant
        _aes()                    # échec immédiat si la bibliothèque manque

    def __str__(self):
        return f"IVPN {self.serveur} (VMess sur TCP) → {self.cible}"

    def ouvrir(self, socks):
        sock = connexion_tcp(socks, *adresse(self.serveur))
        try:
            session = SessionVMess(self.identifiant, self.cible)
            sock.sendall(HTTP_REQUETE + session.entete())
            sock.settimeout(None)
        except BaseException:
            sock.close()
            raise
        return LiaisonVMess(sock, session), "VMess"


# ── Mullvad : udp-over-tcp ───────────────────────────────────────────────────
#
# Repris de mullvad/udp-over-tcp (src/forward_traffic.rs) : chaque paquet UDP
# précédé de sa taille, 2 octets gros-boutistes.  Rien d'autre : ni
# chiffrement, ni identifiant, ni déguisement.  Le serveur (tcp2udp) écoute
# sur l'IP même du serveur WireGuard, ports 80, 443 et 5001 (fixés dans
# l'application, mullvad-api/src/relay_list.rs).  Un paquet vide est permis
# par le format : il est relayé tel quel par tcp2udp, ignoré ici.

class LiaisonUdpTcp:
    def __init__(self, sock):
        self.sock = sock
        self._lire = lecture_exacte(sock)

    def envoyer(self, paquet):
        if not 0 < len(paquet) <= 0xFFFF:
            raise ErreurPont(f"paquet de {len(paquet)} octets : hors format")
        self.sock.sendall(struct.pack(">H", len(paquet)) + paquet)

    def recevoir(self):
        while True:
            taille, = struct.unpack(">H", self._lire(2))
            if taille:
                return self._lire(taille)

    def fermer(self):
        self.sock.close()


class Mullvad:
    def __init__(self, serveur: str):
        self.serveur = serveur

    def __str__(self):
        return f"Mullvad {self.serveur} (udp-over-tcp)"

    def ouvrir(self, socks):
        sock = connexion_tcp(socks, *adresse(self.serveur))
        sock.settimeout(None)
        return LiaisonUdpTcp(sock), "udp-over-tcp"


EMBALLAGES = ("proton", "ivpn", "mullvad")


# ── Le pont ──────────────────────────────────────────────────────────────────

class Pont:
    def __init__(self, ecoute, emballage, socks, journal=None):
        self.emballage = emballage
        self.socks = socks
        self._journal = journal or (lambda m: print(
            time.strftime("%H:%M:%S"), m, file=sys.stderr, flush=True))
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(adresse(ecoute))
        self._wg = None                 # adresse UDP de WireGuard
        self._liaison = None
        self._verrou = threading.Lock()
        self._prochain_essai = 0.0
        self._attente = 1.0
        self._arret = threading.Event()

    def journal(self, message):
        self._journal(message)

    def _connexion(self):
        """La liaison en cours, ouverte au besoin ; None si en attente."""
        with self._verrou:
            if self._liaison is not None:
                return self._liaison
            if time.monotonic() < self._prochain_essai:
                return None
            via = ("accès direct" if self.socks == "aucun"
                   else f"Tor ({self.socks})")
            self.journal(f"Connexion : {self.emballage}, via {via}…")
            try:
                liaison, detail = self.emballage.ouvrir(self.socks)
            except (OSError, ErreurPont) as e:
                self.journal(f"Échec : {e}")
                self._prochain_essai = time.monotonic() + self._attente
                self._attente = min(self._attente * 2, ATTENTE_MAX)
                return None
            self.journal(f"Connecté ({detail}).")
            self._attente = 1.0
            self._liaison = liaison
            threading.Thread(target=self._descendre, args=(liaison,),
                             daemon=True).start()
            return liaison

    def _fermer(self, liaison, raison):
        with self._verrou:
            if self._liaison is liaison:
                self._liaison = None
                self.journal(f"Connexion perdue : {raison}")
        try:
            liaison.fermer()
        except OSError:
            pass

    def _descendre(self, liaison):
        """Serveur → WireGuard."""
        try:
            while True:
                paquet = liaison.recevoir()
                if self._wg is not None:
                    self.udp.sendto(paquet, self._wg)
        except (OSError, ErreurPont, struct.error) as e:
            self._fermer(liaison, e)

    def monter(self):
        """WireGuard → serveur.  Boucle principale, jusqu'à arreter()."""
        self.journal(f"Écoute UDP sur {self.udp.getsockname()[0]}:"
                     f"{self.udp.getsockname()[1]}.")
        while not self._arret.is_set():
            try:
                paquet, origine = self.udp.recvfrom(65535)
            except OSError:
                break
            if not ipaddress.ip_address(origine[0]).is_loopback:
                continue                # seul WireGuard, en local, parle au pont
            self._wg = origine
            liaison = self._connexion()
            if liaison is None:
                continue
            try:
                liaison.envoyer(paquet)
            except (OSError, ErreurPont) as e:
                self._fermer(liaison, e)

    def arreter(self):
        self._arret.set()
        self.udp.close()
        with self._verrou:
            liaison, self._liaison = self._liaison, None
        if liaison is not None:
            liaison.fermer()


def emballage_depuis(nom, serveur, cible=None, identifiant=None, sni=None):
    if nom == "proton":
        return Proton(serveur, sni)
    if nom == "ivpn":
        if not (cible and identifiant):
            raise ErreurPont("emballage ivpn : --cible et --uuid sont requis")
        return Ivpn(serveur, cible, identifiant)
    if nom == "mullvad":
        return Mullvad(serveur)
    raise ErreurPont(f"emballage inconnu : {nom}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Pont WireGuard (UDP) → Tor → "
                                "WireGuard emballé dans du TCP.")
    p.add_argument("--emballage", choices=EMBALLAGES, default="proton")
    p.add_argument("--serveur", required=True,
                   help="IP:port TCP du serveur, ex. 185.107.56.211:443")
    p.add_argument("--cible", help="ivpn : IP:port UDP du serveur WireGuard, "
                                   "derrière V2Ray")
    p.add_argument("--uuid", help="ivpn : identifiant VMess")
    p.add_argument("--sni", help="proton : nom TLS annoncé (choisi d'après l'IP sinon)")
    p.add_argument("--socks", default="127.0.0.1:9050",
                   help="proxy SOCKS5 de Tor (IP:port ou unix:/chemin), "
                        "ou « aucun » pour un essai sans Tor")
    p.add_argument("--ecoute", default=ECOUTE_DEFAUT,
                   help=f"adresse UDP locale pour WireGuard ({ECOUTE_DEFAUT})")
    a = p.parse_args(argv)
    try:
        emballage = emballage_depuis(a.emballage, a.serveur, a.cible, a.uuid, a.sni)
    except ErreurPont as e:
        p.error(str(e))
    pont = Pont(a.ecoute, emballage, a.socks)
    try:
        pont.monter()
    except KeyboardInterrupt:
        pass
    finally:
        pont.arreter()


if __name__ == "__main__":
    main()
