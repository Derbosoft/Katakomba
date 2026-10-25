"""WireGuard de bout en bout, sur un vrai noyau : interface et clés posées par
le daemon (vrai wg), vrai pont, poignée de main réelle, routes, blocage hors
tunnel actif.

Le pair joue le fournisseur : un vrai serveur WireGuard, derrière un faux
serveur Proton « Stealth » (TLS sur 443, trames TunSafe), puis un faux
serveur Mullvad (udp-over-tcp sur 443).  Tor est remplacé
par un petit proxy SOCKS5 sur 127.0.0.1:9050 : ce qui passe par lui, ici,
passerait par Tor en vrai."""

import base64
import datetime
import os
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import daemon.firewall as m_firewall
import daemon.wireguard as m_wireguard

from tests_noyau.noyau import (CasNoyau, daemon_de_test, joindre, root_reel,
                               sans_passe_droit_hors_root, sh, via)
from validation import analyser_wg

RACINE = Path(__file__).resolve().parents[1]
INTERNET = "203.0.113.80"

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.x509.oid import NameOID
except ImportError:                                    # pragma: no cover
    x509 = None


def paire_wg():
    cle = X25519PrivateKey.generate()
    brut = serialization.Encoding.Raw
    privee = cle.private_bytes(brut, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    publique = cle.public_key().public_bytes(brut, serialization.PublicFormat.Raw)
    return base64.b64encode(privee).decode(), base64.b64encode(publique).decode()


def certificat(dossier: Path):
    """Certificat auto-signé du faux serveur (le pont ne le vérifie pas)."""
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proton.test")])
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nom).issuer_name(nom)
            .public_key(cle.public_key()).serial_number(1)
            .not_valid_before(maintenant - datetime.timedelta(days=1))
            .not_valid_after(maintenant + datetime.timedelta(days=1))
            .sign(cle, hashes.SHA256()))
    (dossier / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (dossier / "cle.pem").write_bytes(cle.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


# Faux serveur Proton : TLS sur 443, trames TunSafe ↔ UDP vers le WireGuard
# local du pair.  Le décodage est celui du pont lui-même (même format).
SERVEUR_PROTON = """
import socket, ssl, sys, threading
sys.path.insert(0, {racine!r})
import pont_wg
journal = open({journal!r}, "a", buffering=1)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain({cert!r}, {cle!r})
srv = socket.create_server(("0.0.0.0", 443))
journal.write("écoute\\n")
while True:
    c, _ = srv.accept()
    try:
        t = ctx.wrap_socket(c, server_side=True)
    except OSError as e:
        journal.write(f"TLS : {{e}}\\n")
        continue
    journal.write("connexion\\n")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.connect(("127.0.0.1", 51820))
    def monter(t=t, u=u):
        lec = pont_wg.Lecteur(pont_wg.lecture_exacte(t))
        try:
            while True:
                p = lec.paquet()
                journal.write(f"montée {{len(p)}}\\n")
                u.send(p)
        except Exception as e:
            journal.write(f"montée finie : {{e!r}}\\n")
    def descendre(t=t, u=u):
        try:
            while True:
                p = u.recv(65535)
                journal.write(f"descente {{len(p)}}\\n")
                t.sendall(pont_wg.encadrer(p))
        except Exception as e:
            journal.write(f"descente finie : {{e!r}}\\n")
    threading.Thread(target=monter, daemon=True).start()
    threading.Thread(target=descendre, daemon=True).start()
"""

# Faux serveur Mullvad : tcp2udp sur 443, transcrit de mullvad/udp-over-tcp
# (src/forward_traffic.rs) sans rien reprendre du pont, pour que les deux
# côtés ne partagent pas une même erreur.
SERVEUR_MULLVAD = """
import socket, struct, threading
journal = open({journal!r}, "a", buffering=1)
srv = socket.create_server(("0.0.0.0", 443))
journal.write("écoute\\n")
while True:
    c, _ = srv.accept()
    journal.write("connexion\\n")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.connect(("127.0.0.1", 51820))
    def monter(c=c, u=u):
        # process_tcp2udp : datagrammes complets transmis, le reste gardé.
        tampon = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                tampon += d
                while len(tampon) >= 2:
                    n, = struct.unpack(">H", tampon[:2])
                    if len(tampon) < 2 + n:
                        break
                    journal.write(f"montée {{n}}\\n")
                    u.send(tampon[2:2 + n])
                    tampon = tampon[2 + n:]
            journal.write("montée finie : fin du flux\\n")
        except Exception as e:
            journal.write(f"montée finie : {{e!r}}\\n")
    def descendre(c=c, u=u):
        # process_udp2tcp : la taille, puis le datagramme.
        try:
            while True:
                p = u.recv(65535)
                journal.write(f"descente {{len(p)}}\\n")
                c.sendall(struct.pack(">H", len(p)) + p)
        except Exception as e:
            journal.write(f"descente finie : {{e!r}}\\n")
    threading.Thread(target=monter, daemon=True).start()
    threading.Thread(target=descendre, daemon=True).start()
"""


class FauxTor:
    """Proxy SOCKS5 minimal sur 127.0.0.1:9050, connexions directes."""

    def __init__(self):
        self.srv = socket.create_server(("127.0.0.1", 9050))
        self.srv.settimeout(0.2)
        self.fin = False
        self.demandes = []
        self.fins = []
        self.fil = threading.Thread(target=self._boucle, daemon=True)
        self.fil.start()

    def _boucle(self):
        while not self.fin:
            try:
                c, _ = self.srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._servir, args=(c,), daemon=True).start()

    @staticmethod
    def _lire(c, n):
        d = b""
        while len(d) < n:
            m = c.recv(n - len(d))
            if not m:
                raise OSError("fermé")
            d += m
        return d

    def _servir(self, c):
        try:
            c.settimeout(10)
            self._lire(c, 3)
            c.sendall(b"\x05\x00")
            _v, _cmd, _r, genre = self._lire(c, 4)
            if genre == 1:
                hote = socket.inet_ntoa(self._lire(c, 4))
            elif genre == 3:
                hote = self._lire(c, self._lire(c, 1)[0]).decode()
            else:
                hote = socket.inet_ntop(socket.AF_INET6, self._lire(c, 16))
            port, = struct.unpack(">H", self._lire(c, 2))
            self.demandes.append((hote, port))
            s = socket.create_connection((hote, port), timeout=10)
            c.sendall(b"\x05\x00\x00\x01" + bytes(6))
            c.settimeout(None)
            s.settimeout(None)
            for a, b, sens in ((c, s, "montée"), (s, c, "descente")):
                threading.Thread(target=self._relayer, args=(a, b, sens), daemon=True).start()
        except OSError as e:
            self.fins.append(("SOCKS", repr(e)))
            c.close()

    def _relayer(self, a, b, sens):
        raison = "fin du flux"
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError as e:
            raison = repr(e)
        self.fins.append((sens, raison))
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def fermer(self):
        self.fin = True
        self.fil.join()
        self.srv.close()


@unittest.skipIf(x509 is None, "python3-cryptography absent")
class WireGuardBoutEnBoutTest(CasNoyau):
    SERVEUR = SERVEUR_PROTON
    DNS = "10.2.0.1"                      # celui de Proton
    EMBALLAGE = "proton"

    def setUp(self):
        super().setUp()
        if not os.path.isdir("/etc/wireguard"):
            self.skipTest("/etc/wireguard absent (paquet wireguard-tools)")
        if subprocess.run(["ip", "link", "add", "wg-essai", "type", "wireguard"],
                          capture_output=True).returncode:
            self.skipTest("module noyau wireguard indisponible")
        sh("ip link del wg-essai")
        # /etc/wireguard propre à ce test : le profil AppArmor de wg ne lui
        # laisse lire que ce répertoire, et rien ne doit y rester.
        sh("mount -t tmpfs -o mode=700 tmpfs /etc/wireguard")
        self.addCleanup(sh, "umount /etc/wireguard", ok=False)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)
        os.chmod(tmp, 0o755)
        # Le pont rangé comme dans /opt/katakomba (644 sous 755) : en vrai
        # root, son utilisateur sans droit ne traverserait pas le dépôt
        # (/home/runner, 750 sur la CI).
        code = tmp / "code"
        code.mkdir(mode=0o755)
        shutil.copy(RACINE / "pont_wg.py", code)
        (code / "pont_wg.py").chmod(0o644)
        self.addCleanup(setattr, m_wireguard, "SCRIPT_DIR", m_wireguard.SCRIPT_DIR)
        m_wireguard.SCRIPT_DIR = code

        sh("ip route add default via 192.168.1.1 dev eth0")
        self.pair.internet(INTERNET)
        self.pair.serveur(8080)

        cli_priv, cli_pub = paire_wg()
        srv_priv, srv_pub = paire_wg()
        Path("/etc/wireguard/srv.conf").write_text(
            f"[Interface]\nPrivateKey = {srv_priv}\nListenPort = 51820\n\n"
            f"[Peer]\nPublicKey = {cli_pub}\nAllowedIPs = 10.2.0.2/32\n")
        self.pair.run("ip link add wg-srv type wireguard && "
                      "wg setconf wg-srv /etc/wireguard/srv.conf && "
                      "ip addr add 10.2.0.1/24 dev wg-srv && ip link set wg-srv up")
        certificat(tmp)
        self.journal_serveur = tmp / "serveur.log"
        code = self.SERVEUR.format(racine=str(RACINE), cert=str(tmp / "cert.pem"),
                                     cle=str(tmp / "cle.pem"), journal=str(self.journal_serveur))
        p = subprocess.Popen(["nsenter", "-t", str(self.pair.pid), "-n", sys.executable,
                              "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pair.enfants.append(p)

        self.tor = FauxTor()
        self.addCleanup(self.tor.fermer)
        self.conf = analyser_wg(
            f"[Interface]\nPrivateKey = {cli_priv}\nAddress = 10.2.0.2/32\n"
            f"DNS = {self.DNS}\n\n[Peer]\nPublicKey = {srv_pub}\n"
            "AllowedIPs = 0.0.0.0/0\nEndpoint = 192.168.1.1:51820\n")[0]
        self.assertEqual(self.conf["emballage"], self.EMBALLAGE)

        self.addCleanup(setattr, m_firewall, "TOR_USER", m_firewall.TOR_USER)
        m_firewall.TOR_USER = "nobody"
        self.d = daemon_de_test(circuit_check=False)
        # Le vrai chemin, APRÈS daemon_de_test : son import des outils de la
        # suite ordinaire le détourne vers un bac à sable, que wg n'aurait
        # pas le droit de lire.
        self.addCleanup(setattr, m_wireguard, "WG_CONF_RUN", m_wireguard.WG_CONF_RUN)
        m_wireguard.WG_CONF_RUN = Path("/etc/wireguard/katakomba-wg.conf")
        sans_passe_droit_hors_root(self.d)
        self.addCleanup(self.d._kill_switch_off, True)
        self.assertTrue(self.d._kill_switch_on())
        self.d._apply_vpn_dns = self.d._apply_dns_split = lambda: None
        self.d.tor_process = type("P", (), {"pid": 1})()
        self.d._tor_relay_ips = lambda: set()
        if not root_reel():
            # Espace utilisateur : setgroups y est interdit, et seul l'uid 0
            # existe.  Le changement d'identité du pont n'est vérifié qu'en
            # vrai root (CI).
            vrai = subprocess.Popen

            def popen(*a, **k):
                for cle in ("user", "group", "extra_groups"):
                    k.pop(cle, None)
                return vrai(*a, **k)
            self.addCleanup(setattr, m_wireguard, "subprocess", m_wireguard.subprocess)
            m_wireguard.subprocess = type("S", (), {
                "Popen": staticmethod(popen), "PIPE": subprocess.PIPE,
                "STDOUT": subprocess.STDOUT})
        time.sleep(0.5)          # serveur TLS du pair à l'écoute

    def _pont(self):
        if root_reel():
            import pwd
            nobody = pwd.getpwnam("nobody")
            ids = (nobody.pw_uid, nobody.pw_gid)
        else:
            ids = (0, 0)
        proc = self.d._lancer_pont(self.conf, *ids)

        def arreter():
            proc.terminate()
            proc.wait(5)
            proc.stdout.close()
        self.addCleanup(arreter)
        return proc

    def _etat(self):
        """Pour les messages d'échec : journal du daemon et du pont, état
        WireGuard des deux côtés."""
        return "\n".join((self.d.log_dump(), sh("wg show tun-katakomba", ok=False),
                          self.pair.run("wg show wg-srv", ok=False),
                          "SOCKS : " + repr(self.tor.demandes) + " " + repr(self.tor.fins),
                          "Serveur : " + self.journal_serveur.read_text()[-2000:]
                          if self.journal_serveur.exists() else "Serveur : aucun journal"))

    def _poignee(self, delai=20):
        fin = time.time() + delai
        while time.time() < fin:
            if self.d._poignee_age() is not None:
                return True
            time.sleep(0.2)
        return False

    def test_tunnel_complet_blocage_actif(self):
        self.assertEqual(self.d._configurer_wg(self.conf), "", self.d.log_dump())
        self.assertEqual(sorted(os.listdir("/etc/wireguard")), ["srv.conf"],
                         "clé privée laissée dans /etc/wireguard")
        self.assertIn("127.0.0.1:51871", sh("wg show tun-katakomba endpoints"))
        self.assertIn("mtu 1320", sh("ip link show tun-katakomba"))

        self._pont()
        self.assertTrue(self._poignee(), self._etat())
        self.assertIn(("192.168.1.1", 443), self.tor.demandes,
                      "le pont n'est pas passé par le proxy SOCKS")

        self.assertTrue(self.d._tunnel_actif(self.conf), self.d.log_dump())
        self.assertEqual(via(INTERNET), "tun-katakomba")
        self.assertEqual(joindre(INTERNET, 8080, delai=5), "ok",
                         "Internet injoignable par le tunnel")
        reception = int(self.pair.run("wg show wg-srv transfer").split()[1])
        self.assertGreater(reception, 0)

        # Le tunnel tombe (pont arrêté) : plus rien ne sort, même à découvert.
        self.d._demonter_tunnel()
        self.assertEqual(joindre(INTERNET, 8080, delai=2), "refus")

    def test_sans_pont_aucune_poignee(self):
        self.assertEqual(self.d._configurer_wg(self.conf), "", self.d.log_dump())
        self.assertFalse(self._poignee(delai=4))
        self.assertIsNone(self.d._poignee_age())

    def test_relance_du_pont_seul(self):
        """Relance légère du watchdog : le pont seul repart, sur une nouvelle
        connexion TCP ; l'interface et la session WireGuard restent, et le
        trafic reprend sans rien reconfigurer."""
        self.assertEqual(self.d._configurer_wg(self.conf), "", self.d.log_dump())
        proc = self._pont()
        self.assertTrue(self._poignee(), self._etat())
        self.assertTrue(self.d._tunnel_actif(self.conf), self.d.log_dump())
        self.assertEqual(joindre(INTERNET, 8080, delai=5), "ok")
        proc.terminate()
        proc.wait(5)
        self.assertEqual(joindre(INTERNET, 8080, delai=2), "muet", "trafic sans pont ?")
        self._pont()
        for _ in range(20):
            if joindre(INTERNET, 8080, delai=2) == "ok":
                break
        else:
            self.fail("le trafic ne reprend pas après la relance du pont\n" + self._etat())
        self.assertGreaterEqual(len(self.tor.demandes), 2)


class MullvadBoutEnBoutTest(WireGuardBoutEnBoutTest):
    """Les mêmes essais, derrière un faux serveur udp-over-tcp de Mullvad ;
    l'emballage est reconnu au DNS du fichier, sans commentaire."""
    SERVEUR = SERVEUR_MULLVAD
    DNS = "10.64.0.1"                     # celui de Mullvad
    EMBALLAGE = "mullvad"


if __name__ == "__main__":
    unittest.main()
