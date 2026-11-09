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


ECHEANCE = 1893456000                   # 2030-01-01


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
            return {"ok": True, "actif": True, "jusqua": ECHEANCE}
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
        for f in (m_gestion_wg.fichier_session("ivpn"), m_gestion_wg.fichier_serveurs("ivpn")):
            f.unlink(missing_ok=True)
        m_gestion_wg.MACHINE_ID.write_text("machine-a\n")
        self.addCleanup(m_gestion_wg.fichier_session("ivpn").unlink, missing_ok=True)
        self.addCleanup(m_gestion_wg.fichier_serveurs("ivpn").unlink, missing_ok=True)

    def daemon(self, api, p=None, **config):
        p = p or fournisseur()
        d = FakeDaemon(config={"providers": [p], "random_account": False, **config})
        d._api_wg = lambda service, q: api(q)
        return d, p


class SessionTest(Base):

    def test_premier_demarrage(self):
        api = FausseApi({compte(0): 2, compte(1): 2, compte(2): 2})
        d, p = self.daemon(api, fournisseur(3))
        reglages, nom, issue = d._wg_gere_reglages(p, 0)
        self.assertEqual(issue, "", d.log_dump())
        self.assertEqual((reglages["emballage"], reglages["adresse"]), ("ivpn", "172.30.0.1"))
        self.assertTrue(nom.startswith("IVPN "))
        self.assertEqual(api.actions(), ["nouvelle", "statut", "serveurs"])
        self.assertEqual(len(api.sessions), 1)
        brut = m_gestion_wg.fichier_session("ivpn").read_text()
        self.assertEqual(stat.S_IMODE(os.stat(m_gestion_wg.fichier_session("ivpn")).st_mode), 0o600)
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
        d._wg_hotes = []
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
        self.assertGreater(d._wg_pauses["ivpn"] - time.time(), m_gestion_wg.PAUSE_API)

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
        self.assertEqual(api.actions(), ["nouvelle", "statut"])
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
        etat = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        etat["rotation"] = time.time() - 1
        m_gestion_wg.fichier_session("ivpn").write_text(json.dumps(etat))
        api.appels.clear()
        return api, d, p, etat

    def test_nouvelle_cle_meme_session(self):
        api, d, p, avant = self._session()
        d._wg_gere_reglages(p, 0)
        self.assertEqual(api.actions(), ["cle", "statut"])
        self.assertEqual(api.appels[0]["active"], avant["publique"])
        apres = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
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
        self.assertEqual(api.actions(), ["cle", "nouvelle", "statut"])

    def test_refus_reporte(self):
        api, d, p, avant = self._session()
        api.reseau = True
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "", "session perdue sur un refus")
        apres = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
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
        self.assertTrue(d._wg_gere_echec(p))
        self.assertFalse(m_gestion_wg.fichier_session("ivpn").exists())

    def test_session_active_cle_reposee_une_fois(self):
        api, d, p = self._pret()
        self.assertFalse(d._wg_gere_echec(p))
        self.assertEqual(api.actions(), ["statut", "cle"])
        api.appels.clear()
        self.assertFalse(d._wg_gere_echec(p))
        self.assertEqual(api.actions(), ["statut"])

    def test_api_injoignable_le_serveur_reste_en_cause(self):
        api, d, p = self._pret()
        api.reseau = True
        self.assertFalse(d._wg_gere_echec(p))
        self.assertTrue(m_gestion_wg.fichier_session("ivpn").exists())


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
        self.assertFalse(m_gestion_wg.fichier_session("ivpn").exists())
        self.assertEqual(api.actions().count("fermer"), 1)

    def test_gestion_active_rien_a_faire(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appels.clear()
        d._wg_gere_menage()
        self.assertEqual(api.appels, [])


    def test_place_d_avant_la_4_5_completee_au_demarrage(self):
        """Ni échéance ni nom : une requête au démarrage, Tor prêt, même si
        le fournisseur n'est pas l'étape en cours (place de secours)."""
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        etat = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        del etat["jusqua"], etat["nom"]
        m_gestion_wg.fichier_session("ivpn").write_text(json.dumps(etat))
        d2, _ = self.daemon(api, p)
        d2._current_provider_idx = 5
        api.appels.clear()
        d2._wg_gere_menage()
        self.assertEqual(api.actions(), ["statut"])
        apres = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        self.assertEqual(apres["jusqua"], ECHEANCE)
        self.assertEqual(d2._wg_comptes_statut()[0]["expires"], ECHEANCE)
        api.appels.clear()
        d2._wg_menage_fait = False
        d2._wg_gere_menage()
        self.assertEqual(api.appels, [], "complétée, elle ne doit plus rien demander")

    def test_completion_qui_echoue_rien_d_ecrit(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        etat = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        del etat["jusqua"]
        m_gestion_wg.fichier_session("ivpn").write_text(json.dumps(etat))
        api.reseau = True
        d2, _ = self.daemon(api, p)
        d2._wg_gere_menage()
        self.assertNotIn("jusqua", json.loads(
            m_gestion_wg.fichier_session("ivpn").read_text()))

    def test_place_d_une_autre_machine_non_completee(self):
        api = FausseApi({compte(0): 1})
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        etat = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        del etat["jusqua"]
        m_gestion_wg.fichier_session("ivpn").write_text(json.dumps(etat))
        m_gestion_wg.MACHINE_ID.write_text("machine-b\n")
        d2, _ = self.daemon(api, p)
        api.appels.clear()
        d2._wg_gere_menage()
        self.assertEqual(api.appels, [])


class AssistantTest(Base):
    """_api_ivpn : ivpn.py lancé sans droit, compte par l'entrée standard."""

    def test_sans_droit_et_sans_argument_secret(self):
        d = FakeDaemon()
        d._utilisateur_vpn = lambda: (997, 996)
        sortie = mock.Mock(stdout='{"ok": true, "jeton": "j", "adresse": "a"}')
        with mock.patch.object(m_gestion_wg.subprocess, "run", return_value=sortie) as run:
            r = d.__class__._api_wg(d, "ivpn", {"action": "nouvelle", "compte": "i-SECRET"})
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
                self.assertEqual(d.__class__._api_wg(d, "ivpn", {"action": "statut"})["ok"], False)


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
        self.assertTrue(d.has_log("(WireGuard géré)"))
        self.assertFalse(d.has_log("ordre des .conf"))

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
        etat = json.loads(m_gestion_wg.fichier_session("ivpn").read_text())
        for secret in (etat["jeton"], etat["cle"], compte(0)):
            self.assertNotIn(secret, brut)

    def test_sans_comptes_pas_de_wireguard_gere(self):
        p = fournisseur(0)
        self.assertEqual(m_gestion_wg.service_gere(p), "")
        self.assertEqual(m_session.transports_du(p, ["wireguard", "openvpn"]), ["openvpn"])


# ── Mullvad (v4.3.0) ─────────────────────────────────────────────────────────

RELAIS = {
    "locations": {f"{c}-{v}": {"country": c.upper(), "city": v.title()}
                  for c, v in (("nl", "ams"), ("de", "fra"), ("se", "sto"), ("ch", "zrh"))},
    "relays": [{"hostname": f"{loc}-wg-00{n}", "location": loc, "active": True,
                "ipv4_addr_in": f"185.1.{i}.{n}", "public_key": CLE, "weight": 100}
               for i, loc in enumerate(("nl-ams", "de-fra", "se-sto", "ch-zrh"))
               for n in (1, 2)],
}
JOUR = 24 * 3600


class FauxMullvad:
    """Le service Mullvad : 5 appareils par compte, date de création."""

    def __init__(self, comptes, actif=True, jusqua=0):
        self.appareils = {c: [] for c in comptes}   # compte → [[id, clé, créé, adresse]]
        self.actif, self.appels, self.n = actif, [], 0
        self.jusqua, self.expires, self.pannes = jusqua, set(), set()
        self.maintenant = time.time()

    def __call__(self, q):
        self.appels.append(q)
        a = q["action"]
        if a in self.pannes:
            return {"ok": False, "code": ivpn.RESEAU, "message": "API injoignable"}
        if a == "serveurs":
            return {"ok": True, "liste": json.loads(json.dumps(RELAIS))}
        compte = q.get("compte")
        if compte not in self.appareils:
            return {"ok": False, "code": 401, "message": "compte refusé"}
        liste = self.appareils[compte]
        if a == "nouvelle":
            if len(liste) >= 5:
                return {"ok": False, "code": 602, "message": "compte plein"}
            self.n += 1
            ident = f"00000000-0000-4000-8000-{self.n:012d}"
            liste.append([ident, q["publique"], self.maintenant, f"10.64.0.{self.n}/32"])
            return {"ok": True, "jeton": ident, "adresse": f"10.64.0.{self.n}/32",
                    "publique": q["publique"], "cree": int(self.maintenant),
                    "nom": "Happy Seal"}
        if a == "appareils":
            return {"ok": True, "maintenant": int(self.maintenant),
                    "appareils": [{"jeton": x[0], "cree": int(x[2])} for x in liste]}
        trouve = [x for x in liste if x[0] == q.get("jeton")]
        if a == "fermer":
            for x in trouve:
                liste.remove(x)
            return {"ok": True}
        if not trouve:
            return {"ok": False, "code": 601, "message": "appareil inconnu"}
        if a == "statut":
            return {"ok": True, "actif": self.actif and compte not in self.expires,
                    "jusqua": self.jusqua, "publique": trouve[0][1]}
        if a == "cle":
            trouve[0][1] = q["publique"]
            return {"ok": True, "adresse": trouve[0][3]}
        raise AssertionError(a)

    def actions(self):
        return [q["action"] for q in self.appels]

    def total(self):
        return sum(len(x) for x in self.appareils.values())


def mullvad(n=1, **gestion):
    enc = lambda s: base64.b64encode(s.encode()).decode()      # noqa: E731
    return {"name": "mullvad", "ovpn_file": "",
            "accounts": [{"u": enc(f"123456781234567{i}"), "p": ""} for i in range(n)],
            "wg_auto": {"service": "mullvad", **gestion}}


def numero(i):
    return f"123456781234567{i}"


class MullvadTest(Base):

    def setUp(self):
        super().setUp()
        self.addCleanup(m_gestion_wg.fichier_session("mullvad").unlink, missing_ok=True)
        self.addCleanup(m_gestion_wg.fichier_serveurs("mullvad").unlink, missing_ok=True)
        for f in (m_gestion_wg.fichier_session("mullvad"),
                  m_gestion_wg.fichier_serveurs("mullvad")):
            f.unlink(missing_ok=True)

    def daemon(self, api, p=None, **config):
        p = p or mullvad()
        d = FakeDaemon(config={"providers": [p], "random_account": False, **config})
        d._api_wg = lambda service, q: (self.assertEqual(service, "mullvad"), api(q))[1]
        return d, p

    def etat(self):
        return json.loads(m_gestion_wg.fichier_session("mullvad").read_text())

    def test_premier_appareil(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        reglages, nom, issue = d._wg_gere_reglages(p, 0)
        self.assertEqual(issue, "", d.log_dump())
        self.assertEqual(reglages["emballage"], "mullvad")
        self.assertTrue(reglages["serveur"].endswith(":443"), "udp-over-tcp sur TCP 443")
        self.assertTrue(nom.startswith("Mullvad "))
        self.assertEqual(api.total(), 1)
        self.assertNotIn(numero(0), m_gestion_wg.fichier_session("mullvad").read_text())

    def test_pas_d_openvpn_chez_mullvad(self):
        self.assertEqual(m_session.transports_du(mullvad(), ["wireguard", "openvpn"]),
                         ["wireguard"])
        sans = mullvad()
        del sans["wg_auto"]
        self.assertEqual(m_session.transports_du(sans, ["wireguard", "openvpn"]),
                         ["openvpn"], "comportement d'avant la v4.3.0 changé")

    def test_renouvellement_par_appareil_neuf(self):
        """La preuve de vie : un appareil neuf, l'ancien supprimé."""
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        avant = self.etat()
        avant["rotation"] = time.time() - 1
        m_gestion_wg.fichier_session("mullvad").write_text(json.dumps(avant))
        api.appels.clear()
        d2, _ = self.daemon(api, p)
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        apres = self.etat()
        self.assertEqual(api.actions(), ["nouvelle", "statut", "fermer"])
        self.assertNotEqual(apres["jeton"], avant["jeton"])
        self.assertEqual(api.total(), 1)
        self.assertTrue(d2.has_log("l'ancien supprimé", "OK"))
        self.assertFalse(d2.has_log("session ouverte"), "renouvellement annoncé comme nouveau")

    def test_renouvellement_compte_plein(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        for k in range(4):
            api.appareils[numero(0)].append([f"autre{k}", "x", time.time(), "10.9.9.9/32"])
        avant = self.etat()
        avant["rotation"] = time.time() - 1
        m_gestion_wg.fichier_session("mullvad").write_text(json.dumps(avant))
        d2, _ = self.daemon(api, p)
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        ids = [x[0] for x in api.appareils[numero(0)]]
        self.assertEqual(self.etat()["jeton"], avant["jeton"], "place risquée pour rien")
        self.assertIn(avant["jeton"], ids)
        self.assertEqual(len(ids), 5)

    def test_compte_plein_appareils_morts_supprimes(self):
        api = FauxMullvad([numero(0)])
        vieux = time.time() - 30 * JOUR
        recent = time.time() - 10 * JOUR
        api.appareils[numero(0)] = [[f"mort{k}", "x", vieux, "10.9.9.9/32"] for k in range(2)] + \
                                   [[f"vivant{k}", "x", recent, "10.9.9.9/32"] for k in range(3)]
        d, p = self.daemon(api, mullvad(reserved_accounts=True))
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "", d.log_dump())
        ids = [x[0] for x in api.appareils[numero(0)]]
        self.assertEqual([i for i in ids if i.startswith("mort")], [])
        self.assertEqual(len([i for i in ids if i.startswith("vivant")]), 3,
                         "appareil de moins de 3 semaines supprimé")
        self.assertTrue(d.has_log("2 appareil(s) de plus de 3 semaines supprimé(s)", "WARN"))

    def test_compte_plein_sans_reserve_rien_supprime(self):
        api = FauxMullvad([numero(0)])
        api.appareils[numero(0)] = [[f"mort{k}", "x", time.time() - 60 * JOUR, "a"]
                                    for k in range(5)]
        d, p = self.daemon(api)
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertEqual(api.total(), 5)
        self.assertNotIn("appareils", api.actions())
        self.assertNotIn("fermer", api.actions())

    def test_appareil_supprime_par_un_autre(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appareils[numero(0)].clear()
        self.assertTrue(d._wg_gere_echec(p))
        self.assertFalse(m_gestion_wg.fichier_session("mullvad").exists())

    def test_cle_juste_pas_de_resynchro(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.appels.clear()
        self.assertFalse(d._wg_gere_echec(p))
        self.assertEqual(api.actions(), ["statut"])

    def test_compte_expire(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        api.actif = False
        self.assertTrue(d._wg_gere_echec(p))
        self.assertEqual(api.total(), 0, "appareil du compte expiré laissé en place")
        self.assertEqual(d._wg_cause, m_gestion_wg.CAUSE_EXPIRE)

    def test_compte_expire_ecarte_des_l_ouverture(self):
        """Mullvad accepte un appareil sur un compte expiré : repris à chaque
        essai, il empêcherait le secours de prendre jamais le relais."""
        api = FauxMullvad([numero(0)], actif=False)
        d, p = self.daemon(api)
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "indisponible")
        self.assertEqual(api.total(), 0)
        self.assertEqual(d._wg_cause, m_gestion_wg.CAUSE_EXPIRE)
        self.assertGreater(d._wg_pauses["mullvad"], time.time())

    def test_compte_expire_le_suivant_sert(self):
        api = FauxMullvad([numero(0), numero(1)])
        api.expires = {numero(0)}
        d, p = self.daemon(api, mullvad(2))
        self.assertEqual(d._wg_gere_reglages(p, 0)[2], "", d.log_dump())
        self.assertEqual((len(api.appareils[numero(0)]), len(api.appareils[numero(1)])), (0, 1))

    def test_echeance_et_nom_gardes(self):
        api = FauxMullvad([numero(0)], jusqua=1893456000)
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        etat = self.etat()
        self.assertEqual((etat["jusqua"], etat["nom"]), (1893456000, "Happy Seal"))
        self.assertTrue(d.has_log("appareil « Happy Seal »", "OK"))

    def test_ordre_propre_au_fournisseur(self):
        """random_account du fournisseur l'emporte sur le réglage général :
        Mullvad dans l'ordre, IVPN au hasard, sur le même PC."""
        api = FauxMullvad([numero(0), numero(1), numero(2)])
        p = mullvad(3)
        p["random_account"] = False
        d, _ = self.daemon(api, p, random_account=True)
        with mock.patch("random.shuffle", side_effect=AssertionError("tirage")):
            d._wg_gere_reglages(p, 0)
        self.assertEqual(len(api.appareils[numero(0)]), 1)

    def test_ordre_de_la_config_si_tirage_desactive(self):
        """Un parc déployé par script met le compte préféré du PC en tête."""
        api = FauxMullvad([numero(0), numero(1), numero(2)])
        d, p = self.daemon(api, mullvad(3), random_account=False)
        with mock.patch("random.shuffle", side_effect=AssertionError("tirage")):
            d._wg_gere_reglages(p, 0)
        self.assertEqual(len(api.appareils[numero(0)]), 1)

    def _rotation_due(self, age_appareil=0.0):
        avant = self.etat()
        avant["rotation"] = time.time() - 1
        avant["appareil_du"] = time.time() - age_appareil
        m_gestion_wg.fichier_session("mullvad").write_text(json.dumps(avant))
        return avant

    def _compte_plein(self, api):
        for k in range(4):
            api.appareils[numero(0)].append([f"autre{k}", "x", time.time(), "10.9.9.9/32"])

    def test_compte_plein_cle_changee_sans_perdre_la_place(self):
        """L'API qui cède à ce moment ne doit rien coûter au PC."""
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due()
        d2, _ = self.daemon(api, p)
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        apres = self.etat()
        self.assertEqual(apres["jeton"], avant["jeton"])
        self.assertNotEqual(apres["cle"], avant["cle"])
        self.assertEqual(apres["appareil_du"], avant["appareil_du"], "preuve de vie falsifiée")
        self.assertEqual(api.total(), 5)
        self.assertNotIn("fermer", api.actions())

    def test_compte_plein_api_qui_cede_rien_de_perdu(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due()
        d2, _ = self.daemon(api, p)
        api.pannes = {"cle"}
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        apres = self.etat()
        self.assertEqual((apres["jeton"], apres["cle"]), (avant["jeton"], avant["cle"]))
        self.assertGreater(apres["rotation"], time.time())

    def test_compte_reserve_plein_appareil_vieux_remplace(self):
        """Clé seule, il passerait pour mort à 3 semaines et un autre PC le
        supprimerait : à 2 semaines, il est remplacé."""
        api = FauxMullvad([numero(0)])
        p = mullvad(reserved_accounts=True)
        d, _ = self.daemon(api, p)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due(m_gestion_wg.PREUVE_DE_VIE + 1)
        d2, _ = self.daemon(api, p)
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        apres = self.etat()
        self.assertNotEqual(apres["jeton"], avant["jeton"])
        self.assertAlmostEqual(apres["appareil_du"], time.time(), delta=60)
        self.assertEqual(api.total(), 5)

    def test_compte_reserve_jeune_cle_seule(self):
        api = FauxMullvad([numero(0)])
        p = mullvad(reserved_accounts=True)
        d, _ = self.daemon(api, p)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due(m_gestion_wg.ROTATION)
        d2, _ = self.daemon(api, p)
        d2._wg_gere_reglages(p, 0)
        self.assertEqual(self.etat()["jeton"], avant["jeton"])

    def test_preuve_de_vie_avant_le_menage(self):
        """Le remplacement doit toujours précéder l'âge où un appareil est
        supprimé par un autre PC, renouvellement le plus tardif compris."""
        pire = (m_gestion_wg.PREUVE_DE_VIE - 1 + m_gestion_wg.ROTATION
                + m_gestion_wg.ROTATION_ALEA)
        self.assertLess(pire, m_gestion_wg.APPAREIL_MORT)

    def test_suppression_refusee_aucun_fantome(self):
        """Suppression refusée : le PC garde sa place au lieu d'oublier un
        appareil que plus personne ne pourrait supprimer."""
        api = FauxMullvad([numero(0)])
        p = mullvad(reserved_accounts=True)
        d, _ = self.daemon(api, p)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due(m_gestion_wg.PREUVE_DE_VIE + 1)
        d2, _ = self.daemon(api, p)
        api.pannes = {"fermer"}
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        self.assertEqual(self.etat()["jeton"], avant["jeton"])
        self.assertTrue(d2.has_log("reporté", "WARN"))

    def test_ancien_etat_sans_date_d_appareil(self):
        """État d'une version antérieure : la clé y datait de l'appareil."""
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        self._compte_plein(api)
        avant = self._rotation_due()
        del avant["appareil_du"]
        m_gestion_wg.fichier_session("mullvad").write_text(json.dumps(avant))
        d2, _ = self.daemon(api, p)
        self.assertEqual(d2._wg_gere_reglages(p, 0)[2], "")
        self.assertEqual(self.etat()["appareil_du"], avant["cle_du"])

    def test_statut_meme_sur_le_secours(self):
        """L'échéance se lit sans être sur l'étape gérée."""
        api = FauxMullvad([numero(0)], jusqua=1893456000)
        d, p = self.daemon(api, mullvad(1))
        d._wg_gere_reglages(p, 0)
        d2, _ = self.daemon(api, p)
        d2._current_provider_idx = 7
        d2._wg_charger_etats()
        ligne = d2._wg_comptes_statut()[0]
        self.assertEqual((ligne["account"], ligne["tail"], ligne["device"], ligne["expires"]),
                         (1, "5670", "Happy Seal", 1893456000))
        self.assertNotIn("12345678", json.dumps(d2._wg_comptes_statut()))

    def test_statut_sans_place(self):
        api = FauxMullvad([numero(0)])
        d, _ = self.daemon(api)
        self.assertEqual(d._wg_comptes_statut()[0]["account"], 0)

    def test_menage_supprime_l_appareil(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        sans = {**p}
        del sans["wg_auto"]
        d2, _ = self.daemon(api, sans)
        d2._wg_gere_menage()
        self.assertEqual(api.total(), 0)
        fermer = [q for q in api.appels if q["action"] == "fermer"]
        self.assertEqual(fermer[0]["compte"], numero(0), "compte retrouvé par son empreinte")

    def test_statut(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        st = d._status_snapshot()["wg_managed"]
        self.assertEqual((st["service"], st["account"], st["provider"]), ("mullvad", 1, "mullvad"))
        self.assertNotIn(numero(0), json.dumps(d._status_snapshot()))

    def test_chaque_connexion_un_autre_serveur(self):
        """Comme « remote-random » d'OpenVPN : chaque reconnexion après une
        coupure tire un serveur, jamais celui d'avant, sans appel à l'API."""
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api, mullvad(countries=["NL"]))     # 2 relais
        serveurs, suite = [], iter(["coupure"] * 4)
        d._session_wireguard = lambda nom, *a, reglages=None: (
            serveurs.append(reglages["serveur"]), next(suite, "arret"))[1]
        d._utilisateur_vpn = lambda: (997, 996)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session):
            d._vpn_loop()
        self.assertEqual(len(serveurs), 5, d.log_dump())
        for avant, apres in zip(serveurs, serveurs[1:]):
            self.assertNotEqual(avant, apres, serveurs)
        self.assertTrue(d.has_log("reconnexion sur un autre serveur", "WARN"))
        self.assertEqual(api.actions(), ["nouvelle", "statut", "serveurs"])   # au démarrage seulement

    def test_nouveau_tirage_sans_le_serveur_precedent(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        precedent = None
        for _ in range(20):
            d._wg_hotes = []
            serveur = d._wg_gere_reglages(p, 0)[0]["serveur"]
            self.assertNotEqual(serveur, precedent)
            precedent = serveur

    def test_seul_serveur_repris(self):
        """Un seul serveur dans les pays choisis : il sert encore."""
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api, mullvad(countries=["NL"]))
        RELAIS_NL = [r for r in RELAIS["relays"] if r["location"] == "nl-ams"][:1]
        with mock.patch.dict(RELAIS, relays=RELAIS_NL):
            d._wg_gere_reglages(p, 0)
        for _ in range(2):
            d._wg_hotes = []
            self.assertEqual(d._wg_gere_reglages(p, 0)[2], "")

    def test_liste_des_serveurs_gardee_7_jours(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        cache = m_gestion_wg.fichier_serveurs("mullvad")
        brut = json.loads(cache.read_text())
        brut["le"] -= 3 * JOUR
        cache.write_text(json.dumps(brut))
        api.appels.clear()
        d._wg_hotes = []
        d._wg_gere_reglages(p, 0)
        self.assertEqual(api.actions(), [], "liste retéléchargée avant 7 jours")

    def test_liste_des_serveurs_rafraichie_apres_un_serveur_muet(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        d._wg_gere_reglages(p, 0)
        cache = m_gestion_wg.fichier_serveurs("mullvad")
        brut = json.loads(cache.read_text())
        brut["le"] -= 2 * JOUR
        cache.write_text(json.dumps(brut))
        d._wg_gere_echec(p)                       # serveur muet, appareil en règle
        api.appels.clear()
        d._wg_hotes = []
        d._wg_gere_reglages(p, 0)
        self.assertEqual(api.actions(), ["serveurs"])
        self.assertFalse(d._wg_liste_douteuse)

    def test_serveur_muet_nomme_dans_le_journal(self):
        api = FauxMullvad([numero(0)])
        d, p = self.daemon(api)
        suite = iter(["echec", "echec"])
        d._session_wireguard = lambda nom, *a, reglages=None: next(suite, "arret")
        d._utilisateur_vpn = lambda: (997, 996)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session):
            d._vpn_loop()
        self.assertTrue(d.has_log("(mullvad) sans poignée de main — serveur suivant", "WARN"),
                        d.log_dump())
        self.assertTrue(any(m.startswith("Serveur ") and "-wg-" in m for _, m in d.logs),
                        "le serveur muet n'est pas nommé")

    def test_indisponible_sans_openvpn_nouvelle_passe(self):
        api = FauxMullvad([])                         # compte refusé partout
        d, p = self.daemon(api)
        vus = []
        d._session_wireguard = lambda *a, **k: vus.append("wg") or "arret"
        d._session_openvpn = lambda *a: vus.append("openvpn") or "arret"
        d._utilisateur_vpn = lambda: (997, 996)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session):
            d._vpn_loop()
        self.assertEqual(vus, [], "OpenVPN tenté chez Mullvad")
        self.assertTrue(d.has_log("Aucun compte n'a pu obtenir une session WireGuard"))


if __name__ == "__main__":
    unittest.main()
