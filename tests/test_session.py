"""Boucle VPN commune aux deux transports (daemon/session.py) : étapes
fournisseur × transport, ordre réglable, secours de WireGuard par OpenVPN,
quarantaines séparées, statut et watchdog.  Les sessions sont simulées : la
logique propre à chaque transport est testée dans test_openvpn.py et
test_wireguard.py."""

import json
import time
import unittest
import unittest.mock

import daemon.session as m_session
from tests.helpers import FakeDaemon, FakeProc, no_sleep, provider, provider_wg


def boucle(providers, issues, **config):
    """Lance la boucle avec des sessions simulées ; renvoie (daemon,
    essais), chaque essai valant (fournisseur, transport, compte)."""
    d = FakeDaemon(config={"providers": providers, "random_account": False, **config})
    essais = []
    suite = iter(issues)

    def session(transport):
        def jouer(*_a):
            essais.append((d._current_provider_idx, transport, d._current_account_idx))
            return next(suite, "arret")
        return jouer
    d._session_wireguard = session("wireguard")
    d._session_openvpn = session("openvpn")
    d._compte_wireguard = lambda: (f"/p/{d._current_account_idx}.conf", "x",
                                   d._current_account_idx) if d._comptes() else None
    d._get_active_creds = lambda: ("/p/a.ovpn", "u", "p", "x",
                                   d._current_account_idx) if d._comptes() else None
    d._utilisateur_vpn = lambda: (997, 996)
    d._check_socks_port = lambda: True
    d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
    d._ipv6_block_off = lambda: None
    with no_sleep(m_session):
        d._vpn_loop()
    return d, essais


class OrdreDesTransportsTest(unittest.TestCase):

    def test_wireguard_d_abord_par_defaut(self):
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1)], ["arret"])
        self.assertEqual(essais, [(0, "wireguard", 0)])

    def test_openvpn_d_abord_si_demande(self):
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1)],
                           ["arret"], transports=["openvpn", "wireguard"])
        self.assertEqual(essais, [(0, "openvpn", 0)])

    def test_secours_openvpn_quand_wireguard_est_epuise(self):
        d, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=2),
                            provider("autre", 1)],
                           ["echec", "echec", "identifiants", "identifiants", "arret"])
        self.assertEqual(essais, [(0, "wireguard", 0), (0, "wireguard", 0),
                                  (0, "openvpn", 0), (0, "openvpn", 1),
                                  (1, "openvpn", 0)])
        self.assertTrue(d.has_log("ivpn : WireGuard épuisé → OpenVPN", "WARN"))

    def test_wireguard_seul(self):
        """« wireguard » seul : les comptes OpenVPN ne sont jamais essayés."""
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1),
                            provider("ovpn", 1)],
                           ["refus", "arret"], transports=["wireguard"])
        self.assertEqual(essais, [(0, "wireguard", 0)])

    def test_openvpn_seul(self):
        _, essais = boucle([provider_wg("ivpn", 2, ovpn="/dev/null", n_accounts=1)],
                           ["arret"], transports=["openvpn"])
        self.assertEqual(essais, [(0, "openvpn", 0)])

    def test_fournisseur_openvpn_inchange(self):
        """Une configuration d'avant la v4.0.0 (pas de « wireguard ») se
        comporte comme avant, malgré l'ordre par défaut."""
        _, essais = boucle([provider("a", 2), provider("b", 1)],
                           ["identifiants", "identifiants", "arret"])
        self.assertEqual(essais, [(0, "openvpn", 0), (0, "openvpn", 1), (1, "openvpn", 0)])

    def test_wireguard_absent_de_la_machine(self):
        """Module noyau ou wg manquant : l'étape est perdue, OpenVPN prend
        le relais tout de suite, sans quarantaine."""
        d, essais = boucle([provider_wg("ivpn", 3, ovpn="/dev/null", n_accounts=1)],
                           ["absent", "arret"])
        self.assertEqual(essais, [(0, "wireguard", 0), (0, "openvpn", 0)])
        self.assertEqual(d._account_cooldown, {})

    def test_ovpn_refuse_passe_a_l_etape_suivante(self):
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=2)],
                           ["arret"], transports=["openvpn", "wireguard"])
        self.assertEqual(essais[0][1], "openvpn")
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=2)],
                           ["refus", "arret"], transports=["openvpn", "wireguard"])
        self.assertEqual(essais, [(0, "openvpn", 0), (0, "wireguard", 0)],
                         "un .ovpn refusé vaut pour tous ses comptes")

    def test_coupures_openvpn_changent_d_etape(self):
        """Pertes répétées : OpenVPN change d'étape (mêmes serveurs pour tous
        ses comptes), WireGuard de .conf (un serveur chacun)."""
        n = m_session.RECONNECT_MAX + 1
        _, essais = boucle([provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=3)],
                           ["coupure"] * n + ["arret"], transports=["openvpn", "wireguard"])
        self.assertEqual(essais[-1], (0, "wireguard", 0))
        _, essais = boucle([provider_wg("m", 2)], ["coupure"] * n + ["arret"])
        self.assertEqual(essais[-1], (0, "wireguard", 1))

    def test_valeur_illisible_vaut_le_defaut(self):
        for valeur in (None, [], ["ssh"], "wireguard", ["openvpn", "openvpn"]):
            self.assertEqual(m_session.ordre_transports({"transports": valeur}),
                             ["wireguard", "openvpn"], valeur)


class OrdreParFournisseurTest(unittest.TestCase):
    """v4.1.0 : un fournisseur peut imposer son ordre (clé « transports »)."""

    def test_ordre_propre_au_fournisseur(self):
        lent = {**provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1),
                "transports": ["openvpn", "wireguard"]}
        _, essais = boucle([lent, provider_wg("proton", 1, ovpn="/dev/null", n_accounts=1)],
                           ["refus", "refus", "arret"])
        self.assertEqual(essais, [(0, "openvpn", 0), (0, "wireguard", 0),
                                  (1, "wireguard", 0)])

    def test_prime_sur_le_reglage_general(self):
        seul = {**provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1),
                "transports": ["openvpn"]}
        _, essais = boucle([seul], ["arret"], transports=["wireguard"])
        self.assertEqual(essais, [(0, "openvpn", 0)])

    def test_secours_dans_l_ordre_du_fournisseur(self):
        p = {**provider_wg("ivpn", 1, ovpn="/dev/null", n_accounts=1),
             "transports": ["openvpn", "wireguard"]}
        d, essais = boucle([p], ["identifiants", "arret"])
        self.assertEqual(essais, [(0, "openvpn", 0), (0, "wireguard", 0)])
        self.assertTrue(d.has_log("ivpn : OpenVPN épuisé → WireGuard", "WARN"))

    def test_valeur_illisible_vaut_le_reglage_general(self):
        for valeur in (None, [], ["ssh"], "openvpn", ["openvpn", "openvpn"]):
            self.assertEqual(m_session.ordre_transports(
                {"transports": ["openvpn"]}, {"transports": valeur}), ["openvpn"], valeur)
        self.assertEqual(m_session.ordre_transports({}, {"name": "x"}),
                         ["wireguard", "openvpn"])


class QuarantaineParTransportTest(unittest.TestCase):

    def test_cles_separees(self):
        d = FakeDaemon(config={"providers": [
            provider_wg("ivpn", 2, ovpn="/dev/null", n_accounts=2)]})
        d._entrer_fournisseur(0, "wireguard")
        d._mettre_en_quarantaine(0)
        self.assertGreater(d._cooldown_restant(0), 0)
        d._entrer_fournisseur(0, "openvpn")
        self.assertEqual(d._cooldown_restant(0), 0,
                         "le .conf 1 a mis le compte OpenVPN 1 en quarantaine")
        self.assertIn((0, 0, "wireguard"), d._account_cooldown)

    def test_statut_de_l_etape_courante(self):
        d = FakeDaemon(config={"providers": [
            provider_wg("ivpn", 2, ovpn="/dev/null", n_accounts=2)]})
        d._entrer_fournisseur(0, "wireguard")
        d._mettre_en_quarantaine(1)
        st = d._status_snapshot()
        self.assertEqual((st["transport"], st["accounts_cooldown"].keys()),
                         ("wireguard", {"2"}))
        d._entrer_fournisseur(0, "openvpn")
        self.assertEqual(d._status_snapshot()["accounts_cooldown"], {})
        json.dumps(d._status_snapshot())

    def test_succes_leve_la_quarantaine_du_bon_compte(self):
        d = FakeDaemon(config={"providers": [
            provider_wg("ivpn", 2, ovpn="/dev/null", n_accounts=2)]})
        d._entrer_fournisseur(0, "openvpn")
        d._mettre_en_quarantaine(0)
        d._entrer_fournisseur(0, "wireguard")
        d._mettre_en_quarantaine(0)
        for nom in ("_apply_vpn_dns", "_apply_dns_split", "_circuit_quality_check"):
            setattr(d, nom, lambda: None)
        d._current_account_idx = 0           # relégué en fin d'ordre, mais connecté
        d._tunnel_monte()
        self.assertEqual(list(d._account_cooldown), [(0, 0)])

    def _remonter(self, **etat):
        d = FakeDaemon(_last_circuit_kbs=733.0, _last_circuit_at=1000.0, **etat)
        for nom in ("_apply_vpn_dns", "_apply_dns_split", "_circuit_quality_check"):
            setattr(d, nom, lambda: None)
        d._tunnel_monte()
        return d

    def test_mesure_a_refaire_oubliee_au_nouveau_circuit(self):
        d = self._remonter()
        self.assertEqual((d._last_circuit_kbs, d._last_circuit_at), (0.0, 0.0))
        self.assertFalse(d._circuit_mesure_passee)

    def test_mesure_du_demarrage_gardee_pour_le_statut(self):
        """Une seule mesure par démarrage : l'effacer afficherait « non
        mesuré » jusqu'au prochain redémarrage du service."""
        d = self._remonter(_circuit_controle_fait=True)
        self.assertEqual(d._last_circuit_kbs, 733.0)
        self.assertTrue(d._circuit_mesure_passee)

    def test_aucune_mesure_rien_a_signaler(self):
        d = self._remonter(_circuit_controle_fait=True)
        d._last_circuit_kbs, d._last_circuit_at = 0.0, 0.0
        d._tunnel_monte()
        self.assertFalse(d._circuit_mesure_passee)


class ProcessusCourantTest(unittest.TestCase):

    def test_processus_selon_le_transport(self):
        d = FakeDaemon()
        d.openvpn_process, d.pont_process = FakeProc(), FakeProc()
        d._transport = "wireguard"
        self.assertIs(d._processus_vpn(), d.pont_process)
        d._transport = "openvpn"
        self.assertIs(d._processus_vpn(), d.openvpn_process)

    def test_relance_legere_vise_le_pont(self):
        d = FakeDaemon(_transport="wireguard")
        d.openvpn_process = FakeProc(returncode=None)
        d.openvpn_process._rc = None
        d.pont_process = FakeProc(returncode=None)
        d.pont_process._rc = None
        d._new_tor_circuit = lambda: None
        self.assertTrue(d._vpn_is_active())
        d._restart_vpn()
        self.assertTrue(d.pont_process.terminated)
        self.assertFalse(d.openvpn_process.terminated)
        self.assertTrue(d._circuit_retry)

    def test_arret_des_deux_transports(self):
        d = FakeDaemon()
        appels = []
        d._stop_openvpn = lambda: appels.append("openvpn")
        d._stop_wireguard = lambda: appels.append("wireguard")
        d._stop_vpn_process()
        self.assertEqual(sorted(appels), ["openvpn", "wireguard"])


class EtapeTest(unittest.TestCase):

    def test_fournisseur_sans_transport_saute(self):
        _, essais = boucle([{"name": "vide"}, provider_wg("m", 1)], ["arret"])
        self.assertEqual(essais, [(1, "wireguard", 0)])

    def test_tout_epuise_revient_au_premier(self):
        d = FakeDaemon(config={"providers": [provider_wg("m", 1), provider("o", 1)],
                               "random_account": False})
        d._entrer_fournisseur(0)
        self.assertTrue(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._transport), (1, "openvpn"))
        self.assertFalse(d._try_failover())
        self.assertEqual((d._current_provider_idx, d._transport), (0, "wireguard"))

    def test_quarantaine_expire(self):
        d = FakeDaemon(config={"providers": [provider_wg("m", 2)]})
        d._entrer_fournisseur(0)
        d._account_cooldown[(0, 0, "wireguard")] = time.time() - 1
        self.assertEqual(d._cooldown_restant(0), 0)


if __name__ == "__main__":
    unittest.main()


class HasardParFournisseurTest(unittest.TestCase):

    def ordre(self, general, propre):
        p = provider("a", 4)
        if propre is not None:
            p["random_account"] = propre
        d = FakeDaemon(config={"providers": [p], "random_account": general})
        d._current_provider_idx, d._transport = 0, "openvpn"
        with unittest.mock.patch("random.shuffle") as tirage:
            d._plan_accounts()
        return tirage.called

    def test_reglage_general_par_defaut(self):
        self.assertTrue(self.ordre(True, None))
        self.assertFalse(self.ordre(False, None))

    def test_le_fournisseur_l_emporte(self):
        self.assertFalse(self.ordre(True, False))
        self.assertTrue(self.ordre(False, True))

    def test_valeur_illisible_ignoree(self):
        self.assertTrue(self.ordre(True, "non"))


class SeuilsCircuitTest(unittest.TestCase):
    """Seuils du circuit (v4.8.0) : fixes, puis relatifs à l'historique de
    la machine, sans jamais assouplir un seuil fixe."""

    @staticmethod
    def histo(debits=(), latences=()):
        return ([{"t": 1, "kbs": k, "ms": None} for k in debits]
                + [{"t": 1, "kbs": None, "ms": m} for m in latences])

    def test_centile_au_rang_le_plus_proche(self):
        v = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
        self.assertEqual(m_session.centile(v, 30), 300)
        self.assertEqual(m_session.centile(v, 70), 700)
        self.assertEqual(m_session.centile(v, 50), 500)
        self.assertEqual(m_session.centile([5, 1, 3], 50), 3)
        self.assertEqual(m_session.centile([7], 1), 7)
        with self.assertRaises(ValueError):
            m_session.centile([], 50)

    def test_seuils_fixes_sans_relatif(self):
        h = self.histo(range(1000, 2000, 50), range(100, 1100, 50))
        self.assertEqual(m_session.seuils_circuit(250, 600, 0, h), (250, 600))

    def test_historique_trop_court(self):
        h = self.histo([900] * 9, [300] * 9)
        self.assertEqual(m_session.seuils_circuit(250, 600, 30, h), (250, 600))

    def test_relatif_durcit(self):
        h = self.histo(range(100, 1100, 100), range(100, 1100, 100))
        self.assertEqual(m_session.seuils_circuit(250, 900, 30, h), (300, 700))

    def test_relatif_n_assouplit_jamais(self):
        """Mauvaise garde : tout l'historique est lent.  Le plancher de débit
        et le plafond de latence tiennent."""
        h = self.histo([60] * 20, [1500] * 20)
        self.assertEqual(m_session.seuils_circuit(150, 800, 30, h), (150, 800))

    def test_relatif_seul(self):
        """Pas de seuil fixe : le relatif s'applique tel quel."""
        h = self.histo(range(100, 1100, 100), range(100, 1100, 100))
        self.assertEqual(m_session.seuils_circuit(0, 0, 20, h), (200, 800))


class LatenceCircuitTest(unittest.TestCase):
    """Mesure de la latence : médiane des ouvertures de connexion à travers
    le tunnel, sans vraie connexion ici."""

    def mesurer(self, durees, budget=None, cibles=None):
        d = FakeDaemon()
        suite = iter(durees)
        jointes = [] if cibles is None else cibles

        def ouvrir(iface, adresse):
            jointes.append(adresse)
            return next(suite)
        d._ouvrir_connexion = ouvrir
        if budget is not None:
            d._LAT_BUDGET = budget
        # Aucune résolution de nom (v4.9.0) : une requête DNS ferait échouer.
        with unittest.mock.patch.object(m_session.socket, "getaddrinfo",
                                        side_effect=AssertionError("DNS")):
            return m_session.SessionMixin._measure_tunnel_latency(d, "tun0")

    def test_mediane(self):
        self.assertEqual(self.mesurer([400, 410, 380, 900, 420, 395, 405, 390, 415, 2000]),
                         405)

    def test_refus_ecartes(self):
        self.assertEqual(self.mesurer([-1, -1, 300, 310, 320, 330, 340, 350, 360, 370]),
                         330)

    def test_trop_peu_d_echantillons(self):
        self.assertEqual(self.mesurer([-1] * 5 + [300] * 5), -1.0)

    def test_que_des_depassements(self):
        """Le tunnel ne passe rien : pas une latence."""
        self.assertEqual(self.mesurer([3000.0] * 10), -1.0)

    def test_depassements_comptes_comme_lents(self):
        self.assertEqual(self.mesurer([3000.0] * 6 + [400] * 4), 3000.0)

    def test_cibles_par_adresse(self):
        """Les adresses de la surveillance, jamais un nom de test de débit."""
        jointes = []
        self.mesurer([400] * 10, cibles=jointes)
        self.assertEqual(set(jointes), {("1.1.1.1", 443)})
        self.assertNotIn("speed.cloudflare.com", repr(m_session.SessionMixin._LAT_CIBLES))

    def test_cible_suivante_si_la_premiere_refuse(self):
        jointes = []
        self.assertEqual(self.mesurer([-1] + [300] * 9, cibles=jointes), 300)
        self.assertEqual(jointes[0], ("1.1.1.1", 443))
        self.assertEqual(set(jointes[1:]), {("9.9.9.9", 443)})

    def test_pas_de_melange_apres_une_mesure(self):
        """Un refus isolé ne change plus de cible : la médiane reste celle
        d'un seul hôte."""
        jointes = []
        self.mesurer([300, -1] + [300] * 8, cibles=jointes)
        self.assertEqual(set(jointes), {("1.1.1.1", 443)})

    def test_arret_si_le_tunnel_tombe(self):
        d = FakeDaemon()
        appels = []
        d._ouvrir_connexion = lambda iface, adresse: appels.append(1) or 400.0
        r = m_session.SessionMixin._measure_tunnel_latency(
            d, "tun0", still_valid=lambda: len(appels) < 3)
        self.assertEqual((r, len(appels)), (-1.0, 3))

    def test_ouverture_liee_au_tunnel(self):
        """SO_BINDTODEVICE avant connect : jamais par la route par défaut."""
        faux = unittest.mock.MagicMock()
        with unittest.mock.patch.object(m_session.socket, "socket", return_value=faux):
            ms = m_session.SessionMixin._ouvrir_connexion(FakeDaemon(), "tun0",
                                                          ("104.16.0.1", 443))
        self.assertGreaterEqual(ms, 0)
        appels = [c[0] for c in faux.method_calls]
        self.assertLess(appels.index("setsockopt"), appels.index("connect"))
        self.assertEqual(faux.setsockopt.call_args[0][2], b"tun0")
        faux.close.assert_called_once()

    def test_ouverture_lente_ou_refusee(self):
        for erreur, attendu in ((m_session.socket.timeout(), 3000.0),
                                (ConnectionRefusedError(), -1.0)):
            faux = unittest.mock.MagicMock()
            faux.connect.side_effect = erreur
            with unittest.mock.patch.object(m_session.socket, "socket", return_value=faux):
                self.assertEqual(m_session.SessionMixin._ouvrir_connexion(
                    FakeDaemon(), "tun0", ("104.16.0.1", 443)), attendu)
            faux.close.assert_called_once()


def ecrire_historique(contenu):
    """Comme le daemon : dossier d'état en 0755, que le groupe ne modifie pas."""
    m_session._write_private(m_session.CIRCUITS_FILE, contenu, dir_mode=0o755)


class ControleCircuitLatenceTest(unittest.TestCase):
    """Contrôle du circuit avec latence et seuil relatif (v4.8.0)."""

    def setUp(self):
        m_session.CIRCUITS_FILE.unlink(missing_ok=True)

    tearDown = setUp

    def _daemon(self, ms, kbs, **cfg):
        # Réglages d'avant la v4.9.0 sauf mention contraire : débit à 250,
        # pas de critère de latence.
        d = FakeDaemon(config={"circuit_check": True, "circuit_min_kbs": 250,
                               "circuit_max_ms": 0, "circuit_max_retries": 3, **cfg})
        d._tunnel_up, d._tun_iface = True, "tun0"
        d.openvpn_process = FakeProc(returncode=None)
        d.ordre = []
        d._measure_tunnel_latency = (
            lambda iface="", still_valid=None: d.ordre.append("latence") or ms)
        d._measure_tunnel_speed = (
            lambda iface="", still_valid=None: d.ordre.append("debit") or kbs)
        d.newnym = []
        d._new_tor_circuit = lambda: d.newnym.append(1)
        return d

    def _run(self, d):
        with no_sleep(m_session):
            d._circuit_quality_check()
        return d

    def test_latence_mesuree_avant_le_debit(self):
        d = self._run(self._daemon(400.0, 800.0))
        self.assertEqual(d.ordre, ["latence", "debit"])
        self.assertTrue(d.has_log("Débit OK : 800 KB/s (~6.4 Mbps), latence 400 ms", "OK"))
        self.assertEqual((d._last_circuit_kbs, d._last_circuit_ms), (800.0, 400.0))
        snap = d._status_snapshot()
        self.assertEqual((snap["last_circuit_ms"], snap["circuit_threshold_kbs"],
                          snap["circuit_threshold_ms"]), (400, 250, 0))

    def test_latence_elevee_sans_telecharger(self):
        """Rejeté sur la latence : les 4,5 Mo du débit ne sont pas téléchargés."""
        d = self._run(self._daemon(640.0, 900.0, circuit_max_ms=512))
        self.assertEqual(d.ordre, ["latence"])
        self.assertEqual(d.newnym, [1])
        self.assertTrue(d.openvpn_process.terminated)
        self.assertTrue(d.has_log("Latence élevée : 640 ms > 512 ms — nouveau tirage", "WARN"))
        self.assertEqual(d._reconnect_reason,
                         "circuit Tor trop lent à répondre, nouveau tirage")

    def test_latence_seule(self):
        d = self._run(self._daemon(300.0, 10.0, circuit_min_kbs=0, circuit_max_ms=500))
        self.assertEqual(d.ordre, ["latence"])
        self.assertTrue(d.has_log("Latence OK : 300 ms", "OK"))
        self.assertTrue(d._circuit_controle_fait)

    def test_latence_seule_impossible(self):
        d = self._run(self._daemon(-1.0, 10.0, circuit_min_kbs=0, circuit_max_ms=500))
        self.assertEqual(d.newnym, [])
        self.assertTrue(d.has_log("Mesure de la latence impossible — critère ignoré", "WARN"))
        self.assertTrue(d._circuit_controle_fait)

    def test_debit_impossible_latence_gardee(self):
        d = self._run(self._daemon(380.0, -1.0))
        self.assertTrue(d.has_log("Mesure du débit impossible", "WARN"))
        self.assertEqual((d._last_circuit_kbs, d._last_circuit_ms), (0.0, 380.0))
        self.assertGreater(d._last_circuit_at, 0, "âge de la mesure inconnu")

    def test_latence_impossible_debit_decide(self):
        d = self._run(self._daemon(-1.0, 100.0, circuit_max_ms=500))
        self.assertEqual(d.ordre, ["latence", "debit"])
        self.assertTrue(d.has_log("Débit faible", "WARN"))

    def test_sans_critere_de_latence_rien_d_alarmant(self):
        d = self._run(self._daemon(-1.0, 400.0))
        self.assertFalse(d.has_log("latence", "WARN"))
        self.assertTrue(d.has_log("Débit OK", "OK"))

    def test_plafond_d_essais_sur_la_latence(self):
        d = self._daemon(900.0, 900.0, circuit_max_ms=500)
        d._circuit_attempts = 3
        self._run(d)
        self.assertEqual(d.newnym, [])
        self.assertTrue(d.has_log("[circuit] Circuit conservé après 3 essais — Latence "
                                  "élevée : 900 ms > 500 ms", "WARN"))

    def test_defauts_latence_seule_sans_telechargement(self):
        """v4.9.0 : par défaut, la latence seule — aucun test de débit."""
        from constants import DEFAULT_CONFIG
        d = self._daemon(400.0, 10.0, circuit_min_kbs=DEFAULT_CONFIG["circuit_min_kbs"],
                         circuit_max_ms=DEFAULT_CONFIG["circuit_max_ms"])
        self._run(d)
        self.assertEqual(d.ordre, ["latence"])
        self.assertTrue(d.has_log("Latence OK : 400 ms", "OK"))
        d = self._run(self._daemon(1600.0, 10.0, circuit_min_kbs=0, circuit_max_ms=1500))
        self.assertEqual((d.ordre, d.newnym), (["latence"], [1]))

    def test_tout_desactive(self):
        d = self._run(self._daemon(900.0, 10.0, circuit_min_kbs=0))
        self.assertEqual(d.ordre, [])

    def test_historique_note_chaque_tirage(self):
        for ms, kbs in ((400.0, 800.0), (700.0, 900.0), (-1.0, 300.0)):
            self._run(self._daemon(ms, kbs, circuit_max_ms=600))
        h = FakeDaemon()._historique_circuits()
        self.assertEqual([(e["ms"], e["kbs"]) for e in h],
                         [(400, 800.0), (700, None), (None, 300.0)])

    def test_tunnel_tombe_rien_n_est_note(self):
        d = self._daemon(400.0, 800.0)
        d._measure_tunnel_speed = lambda iface="", still_valid=None: (
            setattr(d, "_tunnel_up", False) or 800.0)
        self._run(d)
        self.assertEqual(FakeDaemon()._historique_circuits(), [])

    def test_seuil_relatif_applique(self):
        maintenant = time.time()
        ecrire_historique(json.dumps(
            [{"t": maintenant, "kbs": k, "ms": m}
             for k, m in zip(range(100, 1100, 100), range(100, 1100, 100))]))
        d = self._run(self._daemon(400.0, 290.0, circuit_relative_pct=30))
        self.assertEqual(d._seuils_circuit, (300.0, 700.0))
        self.assertTrue(d.has_log("Débit faible : 290 KB/s (~2.3 Mbps) < 300 KB/s", "WARN"))
        d = self._run(self._daemon(750.0, 900.0, circuit_relative_pct=30))
        self.assertTrue(d.has_log("Latence élevée : 750 ms > 700 ms", "WARN"))

    def test_historique_borne_et_nettoye(self):
        maintenant = time.time()
        entrees = ([{"t": maintenant - 90 * 86400, "kbs": 1.0, "ms": 1.0}]
                   + ["n'importe quoi", {"t": "x"}, {"t": maintenant, "kbs": True, "ms": None}]
                   + [{"t": maintenant, "kbs": float(i), "ms": None} for i in range(1, 80)])
        ecrire_historique(json.dumps(entrees))
        h = FakeDaemon()._historique_circuits()
        self.assertEqual(len(h), m_session.HISTO_MAX)
        self.assertEqual(h[-1]["kbs"], 79.0)
        self.assertTrue(all(e["kbs"] >= 30 for e in h))

    def test_historique_illisible(self):
        for contenu in ("{", '{"a": 1}', "[1, 2]"):
            ecrire_historique(contenu)
            self.assertEqual(FakeDaemon()._historique_circuits(), [])
