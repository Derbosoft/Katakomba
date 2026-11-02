"""Mode secours (daemon/retour.py) : le rang et la raison exposés au statut, la
sonde de la première étape, à côté du tunnel en service, et le retour."""

import base64
import json
import time
import unittest
from unittest import mock

import daemon.gestion_wg as m_gestion_wg
import daemon.retour as m_retour
import daemon.session as m_session
from tests.helpers import FakeDaemon, FakeProc, no_sleep, provider, provider_wg

REGLAGES = {"emballage": "mullvad", "serveur": "185.1.1.1:443"}


def gere(nom="mullvad"):
    enc = base64.b64encode(b"1234567812345670").decode()
    return {"name": nom, "ovpn_file": "", "accounts": [{"u": enc, "p": ""}],
            "wg_auto": {"service": "mullvad"}}


def daemon(providers=None, **config):
    """Tunnel de secours en service : fournisseur 2, OpenVPN."""
    d = FakeDaemon(config={"providers": providers or [gere(), provider("ivpn")],
                           "random_account": False, **config})
    d._current_provider_idx, d._transport = 1, "openvpn"
    d._tunnel_up, d._secours_depuis = True, 1000.0
    d.openvpn_process = FakeProc(returncode=None)
    d._utilisateur_vpn = lambda: (997, 996)
    return d


class RangTest(unittest.TestCase):

    def test_etapes_dans_l_ordre(self):
        d = FakeDaemon(config={"providers": [
            gere(), provider_wg("x", 1, ovpn="/dev/null", n_accounts=1)]})
        self.assertEqual(d._etapes(), [(0, "wireguard"), (1, "wireguard"), (1, "openvpn")])

    def test_mullvad_n_a_pas_d_etape_openvpn(self):
        self.assertEqual(FakeDaemon(config={"providers": [gere()]})._etapes(),
                         [(0, "wireguard")])

    def test_rang(self):
        d = daemon()
        self.assertEqual(d._rang_etape(), 2)
        d._current_provider_idx, d._transport = 0, "wireguard"
        self.assertEqual(d._rang_etape(), 1)

    def test_fournisseur_retire_a_chaud(self):
        d = daemon()
        d._current_provider_idx = 9
        self.assertEqual(d._rang_etape(), 0)


class SecoursTest(unittest.TestCase):

    def test_entree_en_secours(self):
        d = daemon()
        d._secours_depuis, d._cause_etape = 0.0, m_gestion_wg.CAUSE_PLEINS
        d._etape_montee()
        self.assertGreater(d._secours_depuis, 0)
        statut = d._statut_secours()
        self.assertEqual(statut["reason"], "accounts_full")
        self.assertTrue(d.has_log("Mode secours", "WARN"))

    def test_premiere_etape_rien_a_signaler(self):
        d = daemon()
        d._secours_depuis, d._current_provider_idx, d._transport = 0.0, 0, "wireguard"
        d._etape_montee()
        self.assertEqual(d._statut_secours(), {})

    def test_fin_du_secours(self):
        d = daemon()
        d._current_provider_idx, d._transport = 0, "wireguard"
        d._cause_etape, d._retour_prochain = "x", 5.0
        d._etape_montee()
        self.assertEqual((d._statut_secours(), d._cause_etape, d._retour_prochain),
                         ({}, "", 0.0))

    def test_reconnexion_sur_le_secours_garde_sa_date(self):
        d = daemon()
        d._etape_montee()
        self.assertEqual(d._secours_depuis, 1000.0)

    def test_statut_expose(self):
        d = daemon()
        d._cause_etape = "api_unreachable"
        d.tor_process = None
        st = d._status_snapshot()
        self.assertEqual((st["stage_rank"], st["stage_count"], st["transport"]),
                         (2, 2, "openvpn"))
        self.assertEqual(st["fallback"]["reason"], "api_unreachable")
        self.assertEqual(st["fallback"]["since"], 1000)
        json.dumps(st)

    def test_premiere_cause_gardee(self):
        d = daemon([provider("a"), provider("b"), provider("c")])
        d._current_provider_idx = 0
        d._etape_suivante("api_unreachable")
        d._etape_suivante("servers_silent")
        self.assertEqual(d._cause_etape, "api_unreachable")


def boucle(providers, issues, **config):
    d = FakeDaemon(config={"providers": providers, "random_account": False, **config})
    essais, suite = [], iter(issues)

    def session(transport):
        def jouer(*_a, **_k):
            essais.append((d._current_provider_idx, transport))
            issue = next(suite, "arret")
            return issue() if callable(issue) else issue
        return jouer
    d._session_wireguard = session("wireguard")
    d._session_openvpn = session("openvpn")
    d._compte_wireguard = lambda: ("/p/0.conf", "x", 0)
    d._get_active_creds = lambda: ("/p/a.ovpn", "u", "p", "x", 0)
    d._utilisateur_vpn = lambda: (997, 996)
    d._check_socks_port = lambda: True
    d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
    d._ipv6_block_off = lambda: None
    return d, essais


class BoucleTest(unittest.TestCase):

    def test_retour_sur_la_premiere_etape(self):
        providers = [provider_wg("a", 1), provider("b")]

        def sonde_reussie():
            d._retour_vers = (0, "wireguard", 0, None)
            return "coupure"
        d, essais = boucle(providers, [sonde_reussie, "arret"])
        with no_sleep(m_session):
            d._vpn_loop(1)
        self.assertEqual(essais[0], (1, "openvpn"), d.log_dump())
        self.assertEqual(essais[-1], (0, "wireguard"), d.log_dump())
        self.assertIsNone(d._retour_vers)

    def test_retour_sans_compter_pour_une_panne(self):
        d, essais = boucle([provider_wg("a", 1), provider("b")], [])
        d._reconnect_vpn_count = 3
        d._retour_vers = (0, "wireguard", 0, None)
        d._revenir()
        self.assertEqual((d._reconnect_vpn_count, d._current_provider_idx, d._transport),
                         (0, 0, "wireguard"))

    def test_serveur_sonde_seul_au_tirage(self):
        """Il ne répond plus : l'étape échoue vite, le secours reprend, sans
        passer par trois serveurs de 90 s chacun."""
        d, _ = boucle([gere(), provider("b")], [])
        d._retour_vers = (0, "wireguard", None, ("hote",))
        d._revenir()
        self.assertEqual(d._wg_hotes, [("hote",)])
        self.assertEqual(d._current_account_idx, 0)
        self.assertEqual(d._account_order, [0, 1, 2])

    def test_arret_prioritaire_sur_le_retour(self):
        def arret():
            d._retour_vers = (0, "wireguard", 0, None)
            return "arret"
        d, essais = boucle([provider_wg("a", 1), provider("b")], [arret])
        with no_sleep(m_session):
            d._vpn_loop(1)
        self.assertEqual(len(essais), 1)


class DuTest(unittest.TestCase):

    def due(self, **config):
        d = daemon(**config)
        d._retour_prochain = time.time() - 1
        return d

    def test_due(self):
        self.assertTrue(self.due()._retour_du())

    def test_premiere_sonde_apres_un_intervalle(self):
        d = daemon()
        self.assertFalse(d._retour_du())
        self.assertGreaterEqual(d._retour_prochain, time.time() + 29 * 60)
        self.assertLessEqual(d._retour_prochain, time.time() + 41 * 60)

    def test_etale_sur_le_parc(self):
        d = daemon()
        tirages = set()
        for _ in range(20):
            d._planifier_retour()
            tirages.add(round(d._retour_prochain))
        self.assertGreater(len(tirages), 1)

    def test_pas_sur_la_premiere_etape(self):
        d = self.due()
        d._current_provider_idx, d._transport = 0, "wireguard"
        self.assertFalse(d._retour_du())

    def test_desactive(self):
        self.assertFalse(self.due(primary_retry_min=0)._retour_du())
        self.assertFalse(self.due(auto_reconnect=False)._retour_du())

    def test_valeur_trop_basse_relevee(self):
        self.assertEqual(daemon(primary_retry_min=1)._retour_minutes(), m_retour.RETOUR_MIN)

    def test_valeur_illisible(self):
        for valeur in ("x", True, None, 1.5):
            self.assertEqual(daemon(primary_retry_min=valeur)._retour_minutes(),
                             m_retour.RETOUR_DEFAUT, valeur)

    def test_conditions_du_moment(self):
        for attribut, valeur in (("_tunnel_up", False), ("_stop_vpn", True),
                                 ("_stop_flag", True), ("_retour_en_cours", True),
                                 ("_mesure_en_cours", True),
                                 ("_retour_vers", (0, "wireguard", 0, None))):
            d = self.due()
            setattr(d, attribut, valeur)
            self.assertFalse(d._retour_du(), attribut)

    def test_openvpn_n_est_pas_sonde(self):
        """Essayer OpenVPN prendrait une place et demanderait bien plus
        qu'une poignée de main."""
        d = self.due(transports=["openvpn"])
        d.config["providers"] = [provider("a"), provider("b")]
        self.assertIsNone(d._cible_retour())
        self.assertFalse(d._retour_du())

    def test_premiere_etape_wireguard_plus_haut(self):
        d = daemon([provider("a"), gere(), provider("c")], transports=["openvpn", "wireguard"])
        d._current_provider_idx = 2
        self.assertEqual(d._cible_retour(), (1, "wireguard"))


class SondeTest(unittest.TestCase):

    def sonde(self, d, pret=(REGLAGES, None, ("hote",)), poignee=True):
        d._reglages_sonde = lambda idx: pret
        d._sonder_poignee = mock.Mock(return_value=poignee)
        d._retour_en_cours = True
        d._sonder_retour()

    def test_reussie_tunnel_remplace(self):
        d = daemon()
        proc = d.openvpn_process
        self.sonde(d)
        self.assertEqual(d._retour_vers, (0, "wireguard", None, ("hote",)))
        self.assertTrue(proc.terminated, "tunnel de secours non arrêté")
        self.assertEqual(d._reconnect_reason, "retour sur la première étape")
        self.assertFalse(d._retour_en_cours)
        self.assertFalse(d._stop_vpn, "la boucle doit reprendre d'elle-même")

    def test_sans_poignee_le_tunnel_ne_bouge_pas(self):
        d = daemon()
        self.sonde(d, poignee=False)
        self.assertIsNone(d._retour_vers)
        self.assertFalse(d.openvpn_process.terminated, "tunnel coupé pour rien")
        self.assertEqual(d._cause_etape, m_gestion_wg.CAUSE_SERVEURS)
        self.assertGreater(d._retour_prochain, time.time())

    def test_sans_reglages_cause_mise_a_jour(self):
        d = daemon()
        d._cause_etape = "api_unreachable"

        def reglages(_idx):
            d._wg_cause = m_gestion_wg.CAUSE_PLEINS
        d._reglages_sonde = reglages
        d._sonder_poignee = mock.Mock()
        d._sonder_retour()
        d._sonder_poignee.assert_not_called()
        self.assertEqual(d._cause_etape, m_gestion_wg.CAUSE_PLEINS)

    def test_tunnel_tombe_pendant_la_sonde(self):
        d = daemon()
        d._reglages_sonde = lambda idx: (REGLAGES, None, ("hote",))

        def poignee(*_a):
            d._tunnel_up = False
            return True
        d._sonder_poignee = poignee
        d._sonder_retour()
        self.assertIsNone(d._retour_vers)

    def test_exception_ne_bloque_pas_les_suivantes(self):
        d = daemon()
        d._retour_en_cours = True
        d._reglages_sonde = mock.Mock(side_effect=KeyError("x"))
        d._sonder_retour()
        self.assertFalse(d._retour_en_cours)
        self.assertGreater(d._retour_prochain, 0)

    def test_conf_tire_au_hasard_parmi_les_lisibles(self):
        d = daemon([provider_wg("a", 2), provider("b")])
        d._chemin_conf = lambda p, i: f"/p/{i}.conf"
        d._preparer_wg = lambda chemin: None if chemin == "/p/0.conf" else REGLAGES
        self.assertEqual(d._reglages_sonde(0), (REGLAGES, 1, None))

    def test_interface_retiree_meme_si_le_pont_echoue(self):
        d = daemon()
        d._lancer_pont = mock.Mock(side_effect=OSError("x"))
        with mock.patch("daemon.wireguard._run") as run:
            self.assertFalse(d._sonder_poignee(REGLAGES, 997, 996))
        run.assert_any_call("ip", "link", "del", "dev", "tun-kksonde")


class WatchdogTest(unittest.TestCase):

    def test_la_sonde_ne_bloque_pas_la_surveillance(self):
        """La surveillance émet le ping de systemd : elle n'attend jamais."""
        d = daemon()
        d._sonder_retour = mock.Mock()
        with mock.patch("threading.Thread") as thread:
            d._lancer_sonde()
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()
        d._sonder_retour.assert_not_called()
        self.assertTrue(d._retour_en_cours)


if __name__ == "__main__":
    unittest.main()
