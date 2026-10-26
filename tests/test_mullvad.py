"""
mullvad.py : relais, fichier produit, réponses de l'API.  L'API est simulée :
aucun accès réseau, aucun compte.
"""

import base64
import json
import unittest
from unittest import mock

import mullvad
from validation import analyser_wg

CLE = base64.b64encode(bytes(range(32))).decode()
LISTE = {
    "locations": {"nl-ams": {"city": "Amsterdam"}, "de-fra": {"city": "Frankfurt"},
                  "se-sto": {"city": "Stockholm"}},
    "relays": [
        {"hostname": "nl-ams-wg-001", "location": "nl-ams", "active": True,
         "ipv4_addr_in": "185.1.1.1", "public_key": CLE, "weight": 100},
        {"hostname": "nl-ams-wg-002", "location": "nl-ams", "active": True,
         "ipv4_addr_in": "185.1.1.2", "public_key": CLE, "weight": 100},
        {"hostname": "de-fra-wg-001", "location": "de-fra", "active": True,
         "ipv4_addr_in": "185.1.2.1", "public_key": CLE, "weight": 100},
        {"hostname": "se-sto-wg-001", "location": "se-sto", "active": False,
         "ipv4_addr_in": "185.1.3.1", "public_key": CLE, "weight": 100},
    ],
}
APPAREIL = {"id": "59f3e588-886c-4afe-8981-4f23839b8083", "name": "wise poodle",
            "pubkey": CLE, "ipv4_address": "10.169.172.113/32",
            "ipv6_address": "fc00:bbbb:bbbb:bb01::1/128", "hijack_dns": False,
            "created": "2026-10-26T18:13:22+00:00"}


def reponses(*suite):
    """requete() simulée : chaque appel rend l'élément suivant (statut, corps)."""
    it = iter(suite)
    return mock.patch.object(mullvad, "requete",
                             side_effect=lambda *a, **k: (*next(it), 1793038800.0))


class Relais(unittest.TestCase):

    def test_actifs_et_pays(self):
        self.assertEqual([r["hostname"] for r in mullvad.candidats(LISTE, ["SE"])], [])
        self.assertEqual(len(mullvad.candidats(LISTE, ["nl"])), 2)

    def test_villes_differentes(self):
        hotes = mullvad.choisir_hotes(LISTE, ["NL", "DE"], 2)
        self.assertEqual(sorted(r["location"] for (r,) in hotes), ["de-fra", "nl-ams"])

    def test_pays_absent_tous_les_pays(self):
        self.assertEqual(len(mullvad.choisir_hotes(LISTE, ["FR"], 3)), 3)

    def test_liste_piegee(self):
        piegee = {"relays": [None, {"active": True}, {"active": True, "location": 3,
                                                      "ipv4_addr_in": "1.2.3.4",
                                                      "public_key": CLE}]}
        self.assertEqual(mullvad.choisir_hotes(piegee, [], 3), [])

    def test_conf_reconnue_comme_mullvad(self):
        (relais,) = mullvad.choisir_hotes(LISTE, ["DE"], 1)[0]
        texte = mullvad.config_wg(CLE, "10.169.172.113/32", LISTE, relais)
        reglages, refus, _ = analyser_wg(texte)
        self.assertEqual(refus, [])
        self.assertEqual((reglages["emballage"], reglages["serveur"]),
                         ("mullvad", "185.1.2.1:443"))
        self.assertIn("Frankfurt", texte)


class Api(unittest.TestCase):

    def test_appareil_neuf(self):
        with reponses((200, {"access_token": "t"}), (201, APPAREIL)) as r:
            a = mullvad.nouvel_appareil("aucun", "1234", "pub")
        self.assertEqual((a["jeton"], a["adresse"]), (APPAREIL["id"], "10.169.172.113/32"))
        self.assertEqual(r.call_args_list[1].args[3], {"pubkey": "pub", "hijack_dns": False})
        self.assertEqual(r.call_args_list[1].args[4], "t", "jeton d'accès absent")

    def test_codes(self):
        for statut, code_api, code in ((400, "MAX_DEVICES_REACHED", 602),
                                       (401, "INVALID_ACCOUNT", 401),
                                       (404, "DEVICE_NOT_FOUND", 601),
                                       (503, "", 0)):
            with reponses((200, {"access_token": "t"}), (statut, {"code": code_api})):
                with self.assertRaises(mullvad.ErreurMullvad) as e:
                    mullvad.nouvel_appareil("aucun", "1234", "pub")
            self.assertEqual(e.exception.code, code, code_api)

    def test_compte_refuse_des_le_jeton(self):
        with reponses((400, {"code": "INVALID_ACCOUNT", "error": "x"})):
            with self.assertRaises(mullvad.ErreurMullvad) as e:
                mullvad.appareils("aucun", "0000")
        self.assertEqual(e.exception.code, 401)

    def test_identifiant_jamais_dans_l_url_s_il_est_mal_forme(self):
        with reponses((200, {"access_token": "t"})) as r:
            with self.assertRaises(mullvad.ErreurMullvad):
                mullvad.supprimer("aucun", "1234", "../accounts/me")
        self.assertEqual(len(r.call_args_list), 1, "requête envoyée avec un chemin piégé")

    def test_suppression_deja_faite(self):
        with reponses((200, {"access_token": "t"}), (404, {"code": "DEVICE_NOT_FOUND"})):
            mullvad.supprimer("aucun", "1234", APPAREIL["id"])

    def test_statut_et_expiration(self):
        with reponses((200, {"access_token": "t"}), (200, APPAREIL),
                      (200, {"expiry": "2026-11-26T18:00:00+00:00"})):
            s = mullvad.statut_appareil("aucun", "1234", APPAREIL["id"])
        self.assertEqual((s["actif"], s["publique"]), (True, CLE))
        with reponses((200, {"access_token": "t"}), (200, APPAREIL),
                      (200, {"expiry": "2026-01-01T00:00:00+00:00"})):
            self.assertFalse(mullvad.statut_appareil("aucun", "1234", APPAREIL["id"])["actif"])

    def test_liste_d_appareils_a_l_heure_du_serveur(self):
        with reponses((200, {"access_token": "t"}), (200, [APPAREIL])):
            r = mullvad.appareils("aucun", "1234")
        self.assertEqual(r["maintenant"], 1793038800)
        self.assertEqual(r["appareils"][0]["jeton"], APPAREIL["id"])
        self.assertGreater(r["appareils"][0]["cree"], 0)

    def test_liste_des_relais_allegee(self):
        brut = {"locations": LISTE["locations"], "openvpn": {}, "wireguard": {
            "relays": [{**LISTE["relays"][0], "shadowsocks_extra_addr_in": ["x"] * 50}]}}
        with reponses((200, brut)):
            r = mullvad.serveurs("aucun")
        self.assertEqual(set(r["relays"][0]), {"hostname", "location", "active",
                                               "ipv4_addr_in", "public_key", "weight"})

    def test_repondre(self):
        with reponses((200, {"access_token": "t"}), (201, APPAREIL)):
            r = mullvad.repondre("aucun", json.dumps({"action": "nouvelle",
                                                      "compte": "1234567812345678",
                                                      "publique": "pub"}))
        self.assertTrue(r["ok"])
        with reponses((400, {"code": "INVALID_ACCOUNT"})):
            r = mullvad.repondre("aucun", json.dumps({"action": "appareils",
                                                      "compte": "1234567812345678"}))
        self.assertEqual((r["ok"], r["code"]), (False, 401))
        self.assertNotIn("1234567812345678", json.dumps(r))
        with mock.patch.object(mullvad, "requete", side_effect=OSError("tor")):
            r = mullvad.repondre("aucun", '{"action": "serveurs"}')
        self.assertEqual((r["ok"], r["code"]), (False, 0))
        self.assertFalse(mullvad.repondre("aucun", "[")["ok"])


if __name__ == "__main__":
    unittest.main()
