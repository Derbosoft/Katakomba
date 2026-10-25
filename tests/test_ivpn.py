"""
ivpn.py : choix du serveur, fichier produit, réponses de l'API.  L'API est
simulée : aucun accès réseau, aucun compte.
"""

import json
import unittest
from unittest import mock

import ivpn

LISTE = {
    "wireguard": [
        {"country_code": "NL", "city": "Amsterdam", "hosts": [
            {"hostname": "nl1.wg.ivpn.net", "host": "95.211.1.1", "v2ray": "95.211.1.3",
             "public_key": "A" * 43 + "=", "local_ip": "172.16.0.1/12", "load": 80},
            {"hostname": "nl2.wg.ivpn.net", "host": "95.211.2.1", "v2ray": "",
             "public_key": "B" * 43 + "=", "local_ip": "172.16.0.1/12", "load": 1},
        ]},
        {"country_code": "CH", "city": "Zurich", "hosts": [
            {"hostname": "ch1.wg.ivpn.net", "host": "185.1.1.1", "v2ray": "185.1.1.2",
             "public_key": "C" * 43 + "=", "local_ip": "172.16.0.1/12", "load": 5},
        ]},
    ],
    "config": {"ports": {"v2ray": {"id": "27de860d-5601-412d-8b71-baa048a94b98",
                                   "wireguard": [{"type": "UDP", "port": 15351}]}}},
}
SESSION = {"status": 200, "token": "jeton", "wireguard": {"status": 200,
                                                         "ip_address": "172.30.1.2"}}


class Choix(unittest.TestCase):

    def test_seulement_avec_v2ray(self):
        _, hote = ivpn.choisir_hote(LISTE, "NL")
        self.assertEqual(hote["hostname"], "nl1.wg.ivpn.net")   # nl2 : sans V2Ray

    def test_pays_absent(self):
        with self.assertRaises(ivpn.ErreurIvpn):
            ivpn.choisir_hote(LISTE, "FR")

    def test_ville(self):
        _, hote = ivpn.choisir_hote(LISTE, ville="zur")
        self.assertEqual(hote["hostname"], "ch1.wg.ivpn.net")


class Fichier(unittest.TestCase):

    def test_conf(self):
        passerelle = LISTE["wireguard"][0]
        texte = ivpn.config_wg("P" * 43 + "=", "172.30.1.2", LISTE, passerelle,
                               passerelle["hosts"][0], "jeton")
        self.assertIn("# Katakomba-Emballage = ivpn", texte)
        self.assertIn("# Katakomba-Serveur = 95.211.1.3:80", texte)
        self.assertIn("# Katakomba-Cible = 95.211.1.1:15351", texte)
        self.assertIn("Address = 172.30.1.2/32", texte)
        self.assertIn("DNS = 172.16.0.1", texte)
        self.assertIn("Endpoint = 95.211.1.1:2049", texte)
        self.assertIn("# Katakomba-Session = jeton", texte)
        self.assertNotIn("Katakomba-Session", ivpn.config_wg(
            "P" * 43 + "=", "172.30.1.2", LISTE, passerelle, passerelle["hosts"][0]),
            "session gérée : le jeton reste dans l'état du daemon")

    def test_conf_accepte_par_la_validation(self):
        from validation import analyser_wg
        import base64
        passerelle = LISTE["wireguard"][0]
        hote = {**passerelle["hosts"][0], "public_key": base64.b64encode(bytes(32)).decode()}
        texte = ivpn.config_wg(base64.b64encode(bytes(range(32))).decode(), "172.30.1.2",
                               LISTE, passerelle, hote)
        reglages, refus, _ = analyser_wg(texte)
        self.assertEqual(refus, [])
        self.assertEqual((reglages["emballage"], reglages["serveur"]),
                         ("ivpn", "95.211.1.3:80"))


class Api(unittest.TestCase):

    def _session(self, reponse, statut=200):
        with mock.patch.object(ivpn, "requete", return_value=(statut, reponse)) as r:
            resultat = ivpn.ouvrir_session("aucun", "i-XXXX", "cle")
        corps = r.call_args.args[3]
        self.assertFalse(corps["force"], "une session ne doit jamais être forcée")
        return resultat

    def test_succes(self):
        self.assertEqual(self._session(SESSION), {"jeton": "jeton", "adresse": "172.30.1.2"})

    def test_compte_plein(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "plein"):
            self._session({"status": 602, "message": "limit"})

    def test_compte_refuse(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "refusé"):
            self._session({"status": 401, "message": "bad"})

    def test_codes_de_l_api(self):
        """Codes de l'application IVPN (errors.go) : 702 est un compte
        inactif, pas un captcha."""
        for code, motif in ((702, "inactif"), (70001, "captcha"), (70011, "double"),
                            (601, "session inconnue")):
            with self.assertRaisesRegex(ivpn.ErreurIvpn, motif) as e:
                self._session({"status": code, "message": "x"})
            self.assertEqual(e.exception.code, 70001 if code == 70001 else code)

    def test_cle_refusee(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "clé WireGuard refusée"):
            self._session({"status": 200, "token": "t",
                           "wireguard": {"status": 500, "message": "non"}})


class Choix2(unittest.TestCase):

    def test_plusieurs_villes(self):
        hotes = ivpn.choisir_hotes(LISTE, n=3)
        self.assertEqual(sorted(h["hostname"] for _p, h in hotes),
                         ["ch1.wg.ivpn.net", "nl1.wg.ivpn.net"], "nl2 : sans V2Ray")

    def test_pays_voulus_sinon_tous(self):
        self.assertEqual([h["hostname"] for _p, h in ivpn.choisir_hotes(LISTE, ["CH"], 3)],
                         ["ch1.wg.ivpn.net"])
        self.assertEqual(len(ivpn.choisir_hotes(LISTE, ["FR"], 3)), 2)

    def test_liste_piegee(self):
        piegee = {"wireguard": [None, {"hosts": None}, {"hosts": [None, {"host": "1.2.3.4"}]},
                                {"country_code": 3, "hosts": "x"}]}
        self.assertEqual(ivpn.choisir_hotes(piegee, ["NL"], 3), [])


class Requetes(unittest.TestCase):
    """Mode « api » : ce que le daemon reçoit."""

    def test_reponse_et_erreurs(self):
        with mock.patch.object(ivpn, "requete", return_value=(200, SESSION)):
            r = ivpn.repondre("aucun", '{"action": "nouvelle", "compte": "i-X", '
                                       '"publique": "k"}')
        self.assertEqual(r, {"ok": True, "jeton": "jeton", "adresse": "172.30.1.2"})
        with mock.patch.object(ivpn, "requete", return_value=(200, {"status": 602})):
            r = ivpn.repondre("aucun", '{"action": "nouvelle", "compte": "i-X", '
                                       '"publique": "k"}')
        self.assertEqual((r["ok"], r["code"]), (False, 602))
        self.assertNotIn("i-X", json.dumps(r))
        with mock.patch.object(ivpn, "requete", side_effect=OSError("tor")):
            r = ivpn.repondre("aucun", '{"action": "statut", "jeton": "j"}')
        self.assertEqual((r["ok"], r["code"]), (False, 0))
        self.assertEqual(ivpn.repondre("aucun", "{")["ok"], False)
        self.assertEqual(ivpn.repondre("aucun", '{"action": "rm"}')["ok"], False)

    def test_fermer_une_session_deja_fermee(self):
        with mock.patch.object(ivpn, "requete", return_value=(200, {"status": 601})):
            self.assertEqual(ivpn.repondre("aucun", '{"action": "fermer", "jeton": "j"}'),
                             {"ok": True})

    def test_statut_et_cle(self):
        with mock.patch.object(ivpn, "requete", return_value=(200, {
                "status": 200, "service_status": {"is_active": True, "active_until": 9}})):
            self.assertEqual(ivpn.statut_session("aucun", "j"), {"actif": True, "jusqua": 9})
        with mock.patch.object(ivpn, "requete",
                               return_value=(200, {"status": 200, "ip_address": "172.1.2.3"})) as r:
            self.assertEqual(ivpn.changer_cle("aucun", "j", "neuve", "ancienne"), "172.1.2.3")
        self.assertEqual(r.call_args.args[3], {"session_token": "j", "public_key": "neuve",
                                               "connected_public_key": "ancienne"})


if __name__ == "__main__":
    unittest.main()
