"""Adaptation automatique d'un .ovpn de fournisseur (adaptation.py).

Chaque règle répond à un blocage vérifié sur OpenVPN 2.7 ; les tests portent
sur le RÉSULTAT : ce qui reste actif, ce qui est signalé, et le fait que le
fichier produit passe toujours la validation du daemon."""

import pathlib
import tempfile
import unittest
import zipfile
from datetime import date

from adaptation import adapter, lire_sources
from validation import analyser_ovpn

CA = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n"
TLS = ("<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\nab\n"
       "-----END OpenVPN Static key V1-----\n</tls-crypt>\n")

# Forme type d'un fichier téléchargé : scripts DNS et option Windows inclus.
FOURNISSEUR_TCP = ("client\ndev tun\nproto tcp\nremote 198.51.100.1 443\n"
                   "remote 198.51.100.2 7770\nremote-random\nnobind\n"
                   "persist-key\npersist-tun\ncipher AES-256-GCM\n"
                   "auth-user-pass\nscript-security 2\n"
                   "up /etc/openvpn/update-resolv-conf\n"
                   "down /etc/openvpn/update-resolv-conf\n"
                   "block-outside-dns\n" + CA + TLS)


def actives(texte):
    """Lignes actives (hors commentaires, vides et blocs de données)."""
    sortie, bloc = [], None
    for l in texte.splitlines():
        s = l.strip()
        if bloc:
            bloc = None if s == f"</{bloc}>" else bloc
            continue
        if s.startswith("<") and s.endswith(">") and not s.startswith("</"):
            bloc = s[1:-1] if s[1:-1] != "connection" else None
            continue
        if s and not s.startswith(("#", ";")):
            sortie.append(s)
    return sortie


def adapte(*textes, annexes=None):
    fichiers = [(f"f{i}.ovpn", t) for i, t in enumerate(textes)]
    lire = (lambda nom, ref: (annexes or {}).get(ref))
    return adapter(fichiers, lire, aujourdhui=date(2026, 9, 23))


class ReglesTest(unittest.TestCase):

    def test_fichier_type_rendu_fonctionnel(self):
        r = adapte(FOURNISSEUR_TCP)
        self.assertEqual(r.erreurs, [])
        act = actives(r.texte)
        for interdit in ("script-security 2", "block-outside-dns"):
            self.assertNotIn(interdit, act)
        self.assertFalse(any(l.startswith(("up ", "down ")) for l in act))
        self.assertEqual(r.serveurs, 2)
        self.assertEqual(analyser_ovpn(r.texte)[0], [])

    def test_ligne_retiree_conservee_en_commentaire(self):
        r = adapte(FOURNISSEUR_TCP)
        self.assertIn("# [katakomba] retiré", r.texte)
        self.assertIn("up /etc/openvpn/update-resolv-conf", r.texte)
        self.assertTrue(any("update-resolv-conf" in m for m in r.modifications))

    def test_udp_converti_avec_avertissement(self):
        r = adapte("client\ndev tun\nproto udp\nremote a.example 1194\n"
                   "explicit-exit-notify 1\nfragment 1300\n" + CA)
        act = actives(r.texte)
        self.assertIn("proto tcp", act)
        self.assertNotIn("proto udp", act)
        self.assertNotIn("fragment 1300", act, "fragment est fatal en TCP")
        self.assertTrue(any("UDP" in a for a in r.avertissements))

    def test_sans_proto_tcp_ajoute(self):
        """OpenVPN utilise l'UDP quand rien n'est précisé."""
        r = adapte("client\ndev tun\nremote a.example 443\n" + CA)
        self.assertIn("proto tcp", actives(r.texte))
        self.assertTrue(r.avertissements)

    def test_proto_dans_remote(self):
        r = adapte("client\ndev tun\nremote a.example 443 tcp\n" + CA)
        self.assertIn("remote a.example 443", actives(r.texte))
        self.assertEqual(r.avertissements, [], "fichier déjà TCP")

    def test_proto_tcp6_normalise(self):
        """Le proxy Tor écoute en IPv4 (127.0.0.1)."""
        r = adapte("client\ndev tun\nproto tcp6\nremote a 443\n" + CA)
        self.assertIn("proto tcp", actives(r.texte))

    def test_options_windows_et_disparues_retirees(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n"
                   "register-dns\nwindows-driver wintun\nncp-disable\n"
                   "keysize 256\ntls-remote x\n" + CA)
        act = actives(r.texte)
        for o in ("register-dns", "windows-driver wintun", "ncp-disable",
                  "keysize 256", "tls-remote x"):
            self.assertNotIn(o, act)

    def test_option_windows_protegee_conservee(self):
        """« setenv opt » la rend ignorable : OpenVPN l'accepte (vérifié)."""
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n"
                   "setenv opt block-outside-dns\n" + CA)
        self.assertIn("setenv opt block-outside-dns", actives(r.texte))

    def test_route_nopull_retire(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\nroute-nopull\n" + CA)
        self.assertNotIn("route-nopull", actives(r.texte))

    def test_elements_manquants_ajoutes(self):
        r = adapte("remote a 443 tcp\n" + CA)
        act = actives(r.texte)
        for l in ("client", "dev tun"):
            self.assertIn(l, act)

    def test_redirect_gateway_jamais_ajoute(self):
        """Le serveur l'envoie lui-même : le doublon fait avertir OpenVPN
        (constaté en production après un réimport)."""
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n" + CA)
        self.assertFalse(any(l.startswith("redirect-gateway")
                             for l in actives(r.texte)))

    def test_plugin_et_directive_inconnue_neutralises(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n"
                   "plugin /x.so\nzorglub 1\n" + CA)
        act = actives(r.texte)
        self.assertNotIn("plugin /x.so", act)
        self.assertNotIn("zorglub 1", act)
        self.assertEqual(analyser_ovpn(r.texte)[0], [])

    def test_fichier_d_identifiants_ignore(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n"
                   "auth-user-pass /home/x/creds.txt\n" + CA)
        self.assertIn("auth-user-pass", actives(r.texte))
        self.assertNotIn("auth-user-pass /home/x/creds.txt", actives(r.texte))

    def test_idempotent(self):
        une = adapte(FOURNISSEUR_TCP).texte
        deux = adapte(une)
        self.assertEqual(deux.modifications, [], deux.modifications)
        self.assertEqual(actives(deux.texte), actives(une))


class AnnexesTest(unittest.TestCase):

    def test_fichiers_references_integres(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\nca ca.crt\n"
                   "tls-auth ta.key 1\n",
                   annexes={"ca.crt": b"-----BEGIN CERTIFICATE-----\nX\n"
                                      b"-----END CERTIFICATE-----\n",
                            "ta.key": b"-----BEGIN OpenVPN Static key V1-----\n"
                                      b"ab\n-----END OpenVPN Static key V1-----\n"})
        self.assertEqual(r.erreurs, [])
        self.assertIn("<ca>", r.texte)
        self.assertIn("<tls-auth>", r.texte)
        self.assertIn("key-direction 1", actives(r.texte))
        self.assertNotIn("ca ca.crt", actives(r.texte))

    def test_fichier_reference_absent(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\nca ca.crt\n")
        self.assertTrue(r.erreurs)
        self.assertIn("ca.crt", r.erreurs[0])
        self.assertEqual(r.texte, "")

    def test_pkcs12_en_base64(self):
        r = adapte("client\ndev tun\nproto tcp\nremote a 443\n" + CA
                   + "pkcs12 id.p12\n", annexes={"id.p12": b"\x00\x01\xff"})
        self.assertIn("<pkcs12>\nAAH/\n</pkcs12>", r.texte)


class RefusTest(unittest.TestCase):

    def test_tap_refuse(self):
        self.assertTrue(adapte("client\ndev tap\nremote a 443\n" + CA).erreurs)

    def test_configuration_serveur_refusee(self):
        self.assertTrue(adapte("server 10.8.0.0 255.255.255.0\ndev tun\n").erreurs)

    def test_sans_remote_refuse(self):
        self.assertTrue(adapte("client\ndev tun\nproto tcp\n" + CA).erreurs)

    def test_aucun_fichier(self):
        self.assertTrue(adapter([]).erreurs)


class FusionTest(unittest.TestCase):
    """Un .ovpn par serveur, comme dans beaucoup d'archives de fournisseurs."""

    @staticmethod
    def serveur(hote, ca=CA):
        return (f"client\ndev tun\nproto tcp\nremote {hote} 443\nnobind\n"
                "script-security 2\n" + ca)

    def test_fusion_en_un_seul_fichier(self):
        r = adapte(self.serveur("fr1.example"), self.serveur("de1.example"),
                   self.serveur("fr1.example"))
        self.assertEqual(r.erreurs, [])
        self.assertEqual(r.serveurs, 2, "doublon non retiré")
        act = actives(r.texte)
        self.assertEqual([l for l in act if l.startswith("remote ")],
                         ["remote fr1.example 443", "remote de1.example 443"])
        self.assertEqual(r.texte.count("<ca>"), 1)

    def test_modification_repetee_comptee_une_fois(self):
        r = adapte(self.serveur("a"), self.serveur("b"), self.serveur("c"))
        secu = [m for m in r.modifications if "script-security" in m]
        self.assertEqual(len(secu), 1)
        self.assertIn("×3", secu[0])

    def test_certificats_differents_non_fusionnes(self):
        autre = CA.replace("MIIB", "AUTRE")
        r = adapte(self.serveur("a"), self.serveur("b", ca=autre))
        self.assertTrue(r.erreurs)
        self.assertEqual(r.texte, "")

    def test_variantes_udp_ignorees_si_tcp_present(self):
        udp = "client\ndev tun\nproto udp\nremote u.example 1194\n" + CA
        r = adapte(self.serveur("t.example"), udp)
        self.assertEqual(r.erreurs, [])
        self.assertIn("remote t.example 443", actives(r.texte))
        self.assertNotIn("remote u.example 1194", actives(r.texte))
        self.assertTrue(any("UDP ignoré" in a for a in r.avertissements))


class SourcesTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_archive_du_fournisseur(self):
        z = self.dir / "vpn.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for pays in ("fr", "de"):
                zf.writestr(f"tcp/{pays}.ovpn", "client\ndev tun\nproto tcp\n"
                            f"remote {pays}.example 443\nca ca.crt\n")
                zf.writestr(f"udp/{pays}.ovpn", "client\ndev tun\nproto udp\n"
                            f"remote {pays}.example 1194\nca ca.crt\n")
            zf.writestr("ca.crt", "-----BEGIN CERTIFICATE-----\nX\n"
                                  "-----END CERTIFICATE-----\n")
            zf.writestr("__MACOSX/tcp/._fr.ovpn", "binaire")
        fichiers, lire, erreurs = lire_sources([z])
        self.assertEqual(erreurs, [])
        self.assertEqual(len(fichiers), 4)
        r = adapter(fichiers, lire)
        self.assertEqual(r.erreurs, [], r.erreurs)
        self.assertEqual(r.serveurs, 2)
        self.assertIn("<ca>", r.texte)

    def test_dossier_avec_annexe(self):
        (self.dir / "a.ovpn").write_text("client\ndev tun\nproto tcp\n"
                                         "remote a 443\nca ca.crt\n")
        (self.dir / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nX\n"
                                         "-----END CERTIFICATE-----\n")
        fichiers, lire, erreurs = lire_sources([self.dir / "a.ovpn"])
        r = adapter(fichiers, lire)
        self.assertEqual((erreurs, r.erreurs), ([], []))

    def test_annexe_hors_du_dossier_jamais_lue(self):
        """Le GUI lit en utilisateur, mais n'a pas à suivre « ../../ »."""
        sous = self.dir / "sous"
        sous.mkdir()
        (self.dir / "secret.crt").write_text("SECRET")
        (sous / "a.ovpn").write_text("client\ndev tun\nproto tcp\n"
                                     "remote a 443\nca ../secret.crt\n")
        fichiers, lire, _ = lire_sources([sous / "a.ovpn"])
        r = adapter(fichiers, lire)
        self.assertTrue(r.erreurs, "fichier hors du dossier intégré")
        self.assertNotIn("SECRET", r.texte)

    def test_archive_sans_ovpn(self):
        z = self.dir / "vide.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("lisezmoi.txt", "rien")
        self.assertTrue(lire_sources([z])[2])

    def test_modele_du_depot_adaptable(self):
        texte = (pathlib.Path(__file__).resolve().parents[1]
                 / "template.ovpn").read_text()
        r = adapter([("template.ovpn", texte)])
        self.assertEqual(r.erreurs, [], r.erreurs)


class DataCiphersTest(unittest.TestCase):
    """« cipher X » seul est ignoré pour la négociation depuis OpenVPN 2.6."""

    BASE = "client\ndev tun\nproto tcp\nremote a 443\n" + CA

    def test_cbc_ajoute_en_dernier_recours(self):
        r = adapte(self.BASE + "cipher AES-256-CBC\n")
        self.assertIn("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:"
                      "AES-256-CBC", actives(r.texte))
        self.assertIn("cipher AES-256-CBC", actives(r.texte), "cipher retiré")

    def test_chiffrement_moderne_rien_a_faire(self):
        r = adapte(self.BASE + "cipher AES-256-GCM\n")
        self.assertFalse(any(l.startswith("data-ciphers") for l in actives(r.texte)))

    def test_data_ciphers_existant_respecte(self):
        r = adapte(self.BASE + "cipher AES-256-CBC\ndata-ciphers AES-256-CBC\n")
        self.assertEqual([l for l in actives(r.texte) if l.startswith("data-ciphers")],
                         ["data-ciphers AES-256-CBC"])

    def test_bf_cbc_jamais_ajoute(self):
        """L'ajouter rend le fichier refusé par OpenVPN 2.7 (vérifié)."""
        r = adapte(self.BASE + "cipher BF-CBC\n")
        self.assertFalse(any(l.startswith("data-ciphers") for l in actives(r.texte)))
        self.assertTrue(any("BF-CBC" in a for a in r.avertissements))

    def test_idempotent(self):
        une = adapte(self.BASE + "cipher AES-128-CBC\n").texte
        self.assertEqual(adapte(une).modifications, [])


if __name__ == "__main__":
    unittest.main()
