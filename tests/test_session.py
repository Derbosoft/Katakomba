"""Boucle VPN commune aux deux transports (daemon/session.py) : étapes
fournisseur × transport, ordre réglable, secours de WireGuard par OpenVPN,
quarantaines séparées, statut et watchdog.  Les sessions sont simulées : la
logique propre à chaque transport est testée dans test_openvpn.py et
test_wireguard.py."""

import json
import time
import unittest

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
