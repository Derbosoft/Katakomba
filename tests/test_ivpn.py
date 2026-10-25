"""
ivpn.py : choix du serveur, fichier produit, réponses de l'API.  L'API est
simulée : aucun accès réseau, aucun compte.
"""

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
        texte = ivpn.config_wg("P" * 43 + "=", SESSION, LISTE, passerelle,
                               passerelle["hosts"][0])
        self.assertIn("# Katakomba-Emballage = ivpn", texte)
        self.assertIn("# Katakomba-Serveur = 95.211.1.3:80", texte)
        self.assertIn("# Katakomba-Cible = 95.211.1.1:15351", texte)
        self.assertIn("Address = 172.30.1.2/32", texte)
        self.assertIn("DNS = 172.16.0.1", texte)
        self.assertIn("Endpoint = 95.211.1.1:2049", texte)


class Api(unittest.TestCase):

    def _session(self, reponse, statut=200):
        with mock.patch.object(ivpn, "requete", return_value=(statut, reponse)) as r:
            resultat = ivpn.ouvrir_session("aucun", "i-XXXX", "cle")
        corps = r.call_args.args[3]
        self.assertFalse(corps["force"], "une session ne doit jamais être forcée")
        return resultat

    def test_succes(self):
        self.assertEqual(self._session(SESSION)["token"], "jeton")

    def test_compte_plein(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "plein"):
            self._session({"status": 602, "message": "limit"})

    def test_compte_refuse(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "refusé"):
            self._session({"status": 401, "message": "bad"})

    def test_cle_refusee(self):
        with self.assertRaisesRegex(ivpn.ErreurIvpn, "clé WireGuard refusée"):
            self._session({"status": 200, "token": "t",
                           "wireguard": {"status": 500, "message": "non"}})


if __name__ == "__main__":
    unittest.main()
