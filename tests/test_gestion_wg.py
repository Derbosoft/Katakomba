"""
WireGuard géré (daemon/gestion_wg.py) : session IVPN de ce PC, ouverte,
gardée, renouvelée, vérifiée et fermée par Katakomba.  L'API d'IVPN est
simulée par FausseApi, qui tient comme le vrai service des comptes à places
limitées et des sessions ; aucun accès réseau, aucun compte réel.
"""

import base64
import json
import os
import stat
import time
import unittest
from unittest import mock

import daemon.gestion_wg as m_gestion_wg
import daemon.session as m_session
import ivpn
from tests.helpers import FakeDaemon, no_sleep

CLE = base64.b64encode(bytes(range(32))).decode()
LISTE = {
    "wireguard": [
        {"country_code": ville[0], "city": ville[1], "hosts": [{
            "hostname": f"{ville[0].lower()}{n}.wg.ivpn.net", "host": f"185.0.{i}.{n}",
            "v2ray": f"185.0.{i}.{n + 100}", "public_key": CLE,
            "local_ip": "172.16.0.1/12", "load": 10 * n} for n in (1, 2)]}
        for i, ville in enumerate((("NL", "Amsterdam"), ("CH", "Zurich"),
                                   ("SE", "Stockholm"), ("DE", "Frankfurt")))
    ],
    "config": {"ports": {"v2ray": {"id": "27de860d-5601-412d-8b71-baa048a94b98",
                                   "wireguard": [{"type": "UDP", "port": 15351}]}}},
}


class FausseApi:
    """Le service IVPN, vu par le daemon : _api_ivpn(requete) → réponse."""

    def __init__(self, places=None, captcha=False, reseau=False):
        self.places = places or {}          # numéro de compte → places libres
        self.sessions = {}                  # jeton → [compte, clé publique, adresse]
        self.appels = []
        self.captcha, self.reseau = captcha, reseau
        self.n = 0

    def __call__(self, q):
        self.appels.append(q)
        if self.reseau:
            return {"ok": False, "code": ivpn.RESEAU, "message": "API injoignable"}
        a = q["action"]
        if a == "serveurs":
            return {"ok": True, "liste": json.loads(json.dumps(LISTE))}
        if a == "nouvelle":
            if self.captcha:
                return {"ok": False, "code": 70001, "message": "captcha"}
            compte = q["compte"]
            if compte not in self.places:
                return {"ok": False, "code": 401, "message": "compte refusé"}
            if q["force"]:
                for jeton in [j for j, s in self.sessions.items() if s[0] == compte]:
                    del self.sessions[jeton]
                    self.places[compte] += 1
            if self.places[compte] <= 0:
                return {"ok": False, "code": 602, "message": "compte plein"}
            self.places[compte] -= 1
            self.n += 1
            jeton = f"jeton{self.n}"
            self.sessions[jeton] = [compte, q["publique"], f"172.30.0.{self.n}"]
            return {"ok": True, "jeton": jeton, "adresse": f"172.30.0.{self.n}"}
        s = self.sessions.get(q.get("jeton"))
        if a == "fermer":
            if s:
                del self.sessions[q["jeton"]]
                self.places[s[0]] += 1
            return {"ok": True}
        if s is None:
            return {"ok": False, "code": ivpn.SESSION_INCONNUE, "message": "session inconnue"}
        if a == "statut":
            return {"ok": True, "actif": True, "jusqua": 0}
        if a == "cle":
            s[1] = q["publique"]
            return {"ok": True, "adresse": s[2]}
        raise AssertionError(a)

    def actions(self):
        return [q["action"] for q in self.appels]


def fournisseur(n=1, **gestion):
    enc = lambda s: base64.b64encode(s.encode()).decode()      # noqa: E731
    return {"name": "ivpn", "ovpn_file": "/dev/null",
            "accounts": [{"u": enc(f"i-AAAA-BBBB-000{i}"), "p": enc("x")} for i in range(n)],
            "wg_auto": {"service": "ivpn", **gestion}}


def compte(i):
    return f"i-AAAA-BBBB-000{i}"


class Base(unittest.TestCase):

    def setUp(self):
        for f in (m_gestion_wg.SESSION_FILE, m_gestion_wg.SERVEURS_FILE):
            f.unlink(missing_ok=True)
        m_gestion_wg.MACHINE_ID.write_text("machine-a\n")
        self.addCleanup(m_gestion_wg.SESSION_FILE.unlink, missing_ok=True)
        self.addCleanup(m_gestion_wg.SERVEURS_FILE.unlink, missing_ok=True)

    def daemon(self, api, p=None, **config):
        p = p or fournisseur()
        d = FakeDaemon(config={"providers": [p], "random_account": False, **config})
        d._api_ivpn = api
        return d, p


class SessionTest(Base):

    def test_premier_demarrage(self):
        api = FausseApi({compte(0): 2, compte(1): 2, compte(2): 2})
        d, p = self.daemon(api, fournisseur(3))
        reglages, nom, issue = d._wg_gere_reglages(p, 0)
        self.assertEqual(issue, "", d.log_dump())
        self.assertEqual((reglages["emballage"], reglages["adresse"]), ("ivpn", "172.30.0.1"))
        self.assertTrue(nom.startswith("IVPN "))
        self.assertEqual(api.actions(), ["nouvelle", "serveurs"])
        self.assertEqual(len(api.sessions), 1)
        brut = m_gestion_wg.SESSION_FILE.read_text()
        self.assertEqual(stat.S_IMODE(os.stat(m_gestion_wg.SESSION_FILE).st_mode), 0o600)
        self.assertNotIn("i-AAAA", brut, "numéro de compte écrit en clair")
        self.assertNotIn("i-AAAA", "\n".join(m for _, m in d.logs))

    def test_redemarrage_sans_appel(self):
        """Un redémarrage reprend la même session et la liste en cache :
        aucun appel, aucune place de plus."""
        api = FausseApi({compte(0): 2})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appels.clear()
        d2, _ = self.daemon(api, p)
        reglages, _nom, issue = d2._wg_gere_reglages(p, 1)
        self.assertEqual((issue, api.appels), ("", []))
        self.assertEqual(reglages["adresse"], "172.30.0.1")
        self.assertEqual(api.places[compte(0)], 1)

    def test_serveurs_de_villes_differentes(self):
        api = FausseApi({compte(0): 2})
        d, p = self.daemon(api, fournisseur(countries=["NL", "CH", "SE"]))
        serveurs = {d._wg_gere_reglages(p, i)[0]["serveur"] for i in range(3)}
        self.assertEqual(len(serveurs), 3)
        self.assertEqual(len(d._comptes()), m_gestion_wg.SERVEURS_GERES)

    def test_un_seul_serveur_dans_le_pays(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api, fournisseur(countries=["NL"]))
        d._ivpn_hotes = []
        with mock.patch.object(m_gestion_wg.ivpn, "choisir_hotes",
                               side_effect=lambda l, pays, n: [c[1:] for c in
                                                                m_gestion_wg.ivpn.candidats(l, pays)[:1]]):
            self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")
            self.assertEqual(d._wg_gere_reglages(p, 1)[2], "indisponible")
        self.assertTrue(d.has_log("les 1 serveur(s) des pays choisis ont été essayés"))

    def test_compte_plein_puis_suivant(self):
        api = FausseApi({compte(0): 0, compte(1): 0, compte(2): 1})
        d, p = self.daemon(api, fournisseur(3))
        with mock.patch("random.shuffle"):
            self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")
        self.assertEqual([q["compte"] for q in api.appels if q["action"] == "nouvelle"],
                         [compte(0), compte(1), compte(2)])
        self.assertEqual(d._wg_gere_statut()["account"], 3)

    def test_tous_pleins_sans_remise_a_zero(self):
        api = FausseApi({compte(0): 0, compte(1): 0, compte(2): 0})
        d, p = self.daemon(api, fournisseur(3))
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertFalse(any(q.get("force") for q in api.appels), "session forcée")
        self.assertTrue(d.has_log("tous les comptes utilisables sont pleins", "ERROR"))
        # Pause : pas de nouvel appel avant PAUSE_API.
        api.appels.clear()
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertEqual(api.appels, [])

    def test_tous_pleins_comptes_reserves(self):
        api = FausseApi({compte(0): 0, compte(1): 0})
        api.sessions = {"telephone": [compte(0), "x", "172.30.9.8"],
                        "portable": [compte(1), "y", "172.30.9.9"]}
        d, p = self.daemon(api, fournisseur(2, reserved_accounts=True))
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")
        forcees = [q for q in api.appels if q.get("force")]
        self.assertEqual(len(forcees), 1)
        remis = forcees[0]["compte"]
        autres = [j for j, s in api.sessions.items() if s[0] == remis and not j.startswith("jeton")]
        self.assertEqual(autres, [], "l'autre session du compte remis à zéro reste ouverte")
        self.assertEqual(len(api.sessions), 2, "l'autre compte a été touché")
        n = int(remis[-1]) + 1
        self.assertTrue(d.has_log(f"remise à zéro du compte {n}", "WARN"))

    def test_captcha_arrete_les_essais(self):
        api = FausseApi({compte(0): 1, compte(1): 1}, captcha=True)
        d, p = self.daemon(api)
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertEqual(api.actions(), ["nouvelle"], "les autres comptes martelés")
        self.assertGreater(d._wg_gere_pause - time.time(), m_gestion_wg.PAUSE_API)

    def test_api_injoignable(self):
        api = FausseApi({compte(0): 1}, reseau=True)
        d, p = self.daemon(api)
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertEqual(len(api.appels), 1)

    def test_compte_refuse_puis_suivant(self):
        api = FausseApi({compte(1): 1})                 # compte 0 inconnu de l'API
        d, p = self.daemon(api, fournisseur(2))
        with mock.patch("random.shuffle"):
            self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")
        self.assertTrue(d.has_log("IVPN, compte 1 : compte refusé", "WARN"))

    def test_image_disque_clonee(self):
        """Une autre machine (même disque) ne reprend pas la session, et ne
        la ferme pas : elle est à l'original."""
        api = FausseApi({compte(0): 2})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        m_gestion_wg.MACHINE_ID.write_text("machine-b\n")
        d2, _ = self.daemon(api, p)
        api.appels.clear()
        with mock.patch("random.shuffle"):
            self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        self.assertEqual(api.actions(), ["nouvelle"])
        self.assertEqual(len(api.sessions), 2)
        self.assertTrue(d2.has_log("autre machine", "WARN"))

    def test_compte_retire_de_la_configuration(self):
        api = FausseApi({compte(0): 1, compte(1): 1})
        d, p = self.daemon(api, fournisseur(1))
        d._wg_gere_reglages(p, 0)
        autre = fournisseur(2)
        autre["accounts"] = autre["accounts"][1:]
        d2, _ = self.daemon(api, autre)
        self.assertEqual(d2._wg_gere_reglages(autre, 0)[2], "")
        self.assertEqual([s[0] for s in api.sessions.values()], [compte(1)])
        self.assertEqual(api.places[compte(0)], 1, "place du compte retiré non rendue")


class RenouvellementTest(Base):

    def _session(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        etat = json.loads(m_gestion_wg.SESSION_FILE.read_text())
        etat["rotation"] = time.time() - 1
        m_gestion_wg.SESSION_FILE.write_text(json.dumps(etat))
        api.appels.clear()
        return api, d, p, etat

    def test_nouvelle_cle_meme_session(self):
        api, d, p, avant = self._session()
        d._wg_gere_reglages(p, 0)
        self.assertEqual(api.actions(), ["cle"])
        self.assertEqual(api.appels[0]["active"], avant["publique"])
        apres = json.loads(m_gestion_wg.SESSION_FILE.read_text())
        self.assertEqual(apres["jeton"], avant["jeton"])
        self.assertNotEqual(apres["cle"], avant["cle"])
        self.assertEqual(api.sessions[avant["jeton"]][1], apres["publique"])
        self.assertGreater(apres["rotation"], time.time() + m_gestion_wg.ROTATION - 60)
        self.assertEqual(api.places[compte(0)], 0, "une place de plus prise")

    def test_session_fermee_entre_temps(self):
        api, d, p, avant = self._session()
        api.sessions.clear()
        api.places[compte(0)] = 1
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")
        self.assertEqual(api.actions(), ["cle", "nouvelle"])

    def test_refus_reporte(self):
        api, d, p, avant = self._session()
        api.reseau = True
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "", "session perdue sur un refus")
        apres = json.loads(m_gestion_wg.SESSION_FILE.read_text())
        self.assertEqual(apres["cle"], avant["cle"])
        self.assertAlmostEqual(apres["rotation"] - time.time(),
                               m_gestion_wg.ROTATION_REPORT, delta=60)


class EchecTest(Base):

    def _pret(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appels.clear()
        return api, d, p

    def test_session_fermee_par_un_autre_pc(self):
        api, d, p = self._pret()
        api.sessions.clear()
        self.assertTrue(d._wg_gere_echec())
        self.assertFalse(m_gestion_wg.SESSION_FILE.exists())

    def test_session_active_cle_reposee_une_fois(self):
        api, d, p = self._pret()
        self.assertFalse(d._wg_gere_echec())
        self.assertEqual(api.actions(), ["statut", "cle"])
        api.appels.clear()
        self.assertFalse(d._wg_gere_echec())
        self.assertEqual(api.actions(), ["statut"])

    def test_api_injoignable_le_serveur_reste_en_cause(self):
        api, d, p = self._pret()
        api.reseau = True
        self.assertFalse(d._wg_gere_echec())
        self.assertTrue(m_gestion_wg.SESSION_FILE.exists())


class MenageTest(Base):

    def test_gestion_desactivee_session_fermee(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        sans = {**p}
        del sans["wg_auto"]
        d2, _ = self.daemon(api, sans)
        d2._wg_gere_menage()
        d2._wg_gere_menage()
        self.assertEqual(api.sessions, {})
        self.assertFalse(m_gestion_wg.SESSION_FILE.exists())
        self.assertEqual(api.actions().count("fermer"), 1)

    def test_gestion_active_rien_a_faire(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appels.clear()
        d._wg_gere_menage()
        self.assertEqual(api.appels, [])


class AssistantTest(Base):
    """_api_ivpn : ivpn.py lancé sans droit, compte par l'entrée standard."""

    def test_sans_droit_et_sans_argument_secret(self):
        d = FakeDaemon()
        d._utilisateur_vpn = lambda: (997, 996)
        sortie = mock.Mock(stdout='{"ok": true, "jeton": "j", "adresse": "a"}')
        with mock.patch.object(m_gestion_wg.subprocess, "run", return_value=sortie) as run:
            r = d.__class__._api_ivpn(d, {"action": "nouvelle", "compte": "i-SECRET"})
        self.assertTrue(r["ok"])
        cmd, kw = run.call_args.args[0], run.call_args.kwargs
        self.assertNotIn("i-SECRET", " ".join(cmd))
        self.assertIn("i-SECRET", kw["input"])
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (997, 996, []))
        self.assertEqual(cmd[-3:], ["api", "--socks", "127.0.0.1:9050"])

    def test_sortie_illisible(self):
        d = FakeDaemon()
        d._utilisateur_vpn = lambda: (997, 996)
        for sortie in ("", "[1]", '{"ok": "oui"}', "Traceback"):
            with mock.patch.object(m_gestion_wg.subprocess, "run",
                                   return_value=mock.Mock(stdout=sortie)):
                self.assertEqual(d.__class__._api_ivpn(d, {"action": "statut"})["ok"], False)


class BoucleTest(Base):
    """Le fournisseur géré dans la boucle VPN."""

    def _boucle(self, api, issues, p=None, **config):
        d, p = self.daemon(api, p, **config)
        vus, suite = [], iter(issues)

        def session(nom, uid, gid, reglages=None):
            vus.append((d._transport, reglages and reglages["adresse"]))
            return next(suite, "arret")
        d._session_wireguard = session
        d._session_openvpn = lambda *a: (vus.append(("openvpn", None)), next(suite, "arret"))[1]
        d._get_active_creds = lambda: ("/dev/null", "u", "p", "x", 0)
        d._utilisateur_vpn = lambda: (997, 996)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session):
            d._vpn_loop()
        return d, vus

    def test_wireguard_gere_d_abord(self):
        api = FausseApi({compte(0): 1})
        d, vus = self._boucle(api, ["arret"])
        self.assertEqual(vus, [("wireguard", "172.30.0.1")])
        self.assertTrue(d.has_log("WireGuard géré, serveur 1"))

    def test_api_indisponible_openvpn_prend_le_relais(self):
        api = FausseApi({compte(0): 1}, reseau=True)
        d, vus = self._boucle(api, ["arret"])
        self.assertEqual(vus, [("openvpn", None)])

    def test_session_perdue_reenregistrement(self):
        """Échec de poignée de main, session fermée chez IVPN (remise à
        zéro par un autre PC) : nouvelle session, même serveur."""
        api = FausseApi({compte(0): 2})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.sessions.clear()
        api.places[compte(0)] = 2
        d, vus = self._boucle(api, ["echec", "arret"], p)
        self.assertEqual(vus, [("wireguard", "172.30.0.1"), ("wireguard", "172.30.0.2")])
        self.assertEqual(d._account_cooldown, {})

    def test_statut_sans_secret(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        st = d._status_snapshot()["wg_managed"]
        self.assertEqual((st["service"], st["account"]), ("ivpn", 1))
        brut = json.dumps(d._status_snapshot())
        etat = json.loads(m_gestion_wg.SESSION_FILE.read_text())
        for secret in (etat["jeton"], etat["cle"], compte(0)):
            self.assertNotIn(secret, brut)

    def test_sans_comptes_pas_de_wireguard_gere(self):
        p = fournisseur(0)
        self.assertEqual(m_gestion_wg.service_gere(p), "")
        self.assertEqual(m_session.transports_du(p, ["wireguard", "openvpn"]), ["openvpn"])


if __name__ == "__main__":
    unittest.main()
