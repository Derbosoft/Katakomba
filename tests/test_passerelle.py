"""Passerelle (v4.13.0) : blocage permanent, mode passerelle, réservation des
comptes, état lisible depuis l'hôte par vsock.

Le comportement des règles posées (ce qui passe, ce qui est bloqué, service
arrêté) est rejoué sur un vrai noyau dans tests_noyau/test_nettoyage.py."""

import json
import os
import socket
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import daemon.core as m_core
import daemon.dns as m_dns
import daemon.firewall as m_firewall
import daemon.permanent as m_permanent
import daemon.session as m_session
import statut_vsock
from tests.helpers import FakeDaemon, Recorder, patched_run, patched_subprocess, provider
from tests.test_session import boucle

LAN = {"lan_auto": True, "lan_iface": "ens19", "lan_gateway": "10.0.0.1",
       "lan_subnet": "10.0.0.0/24", "lan_dhcp": False}


def _marquer(chemin, present: bool):
    chemin.parent.mkdir(parents=True, exist_ok=True)
    if present:
        chemin.write_text("")
    else:
        chemin.unlink(missing_ok=True)


class _AvecTor(unittest.TestCase):
    """debian-tor simulé, réglages de l'administrateur retirés après chaque test."""

    def setUp(self):
        self._pwd = m_firewall.pwd
        m_firewall.pwd = types.SimpleNamespace(
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=112))
        self.addCleanup(setattr, m_firewall, "pwd", self._pwd)
        for chemin in (m_core.BLOCAGE_PERMANENT, m_core.MODE_PASSERELLE):
            self.addCleanup(_marquer, chemin, False)

    def permanent(self, actif=True):
        _marquer(m_core.BLOCAGE_PERMANENT, actif)

    def passerelle(self, actif=True):
        _marquer(m_core.MODE_PASSERELLE, actif)


class BlocagePermanentTest(_AvecTor):

    def test_impose_le_blocage_meme_desactive(self):
        d = FakeDaemon(config={"kill_switch": False})
        with patched_run(Recorder()):
            self.assertFalse(d._kill_switch_on())
        self.permanent()
        d = FakeDaemon(config={"kill_switch": False})
        r = Recorder()
        with patched_run(r):
            self.assertTrue(d._kill_switch_on())
        self.assertTrue(r.ran("iptables -I OUTPUT 1 -j KATAKOMBA_KILL"))

    def test_jamais_leve_par_le_daemon(self):
        self.permanent()
        d = FakeDaemon()
        with patched_run(Recorder()):
            self.assertTrue(d._kill_switch_on())
        r = Recorder()
        with patched_run(r):
            d._kill_switch_off()
            d._kill_switch_off(force=True)
        self.assertEqual(r.calls, [], "blocage permanent retiré")
        self.assertTrue(d._kill_active)

    def test_pose_ratee_garde_les_regles_du_demarrage(self):
        """Sans le réglage, une pose refusée retire tout (jamais à moitié) ;
        en blocage permanent, mieux vaut les règles du démarrage que rien."""
        self.permanent()
        d = FakeDaemon()
        r = Recorder({"ip6tables-restore": (1, "")})
        with patched_run(r):
            self.assertFalse(d._kill_switch_on())
        self.assertFalse(r.ran("-X KATAKOMBA_KILL"), r.dump())

    def test_revérifie_meme_si_tor_reste_en_root(self):
        self.permanent()
        d = FakeDaemon(config={"kill_switch": False}, _kill_renonce=True)
        with patched_run(Recorder()):
            self.assertTrue(d._verifier_blocage())
        self.assertTrue(d._kill_active)

    def test_filtrage_lan_garde_a_l_arret(self):
        self.permanent()
        d = FakeDaemon(config=LAN, _lan_active=True, _lan_iface="ens19",
                       _lan_tun="tun-katakomba")
        r = Recorder()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertFalse(r.ran("-X KATAKOMBA_LAN_FWD"), r.dump())
        self.assertFalse(r.ran("-D FORWARD -j KATAKOMBA_LAN_FWD"))
        self.assertTrue(r.ran("iptables -A KATAKOMBA_LAN_FWD -i ens19 -j DROP"))
        self.assertTrue(r.ran("-t nat -X KATAKOMBA_LAN_DNS"), "DNS des clients : retiré")
        self.assertFalse(d._lan_active)

    def test_filtrage_lan_retire_sans_le_reglage(self):
        d = FakeDaemon(config=LAN, _lan_active=True, _lan_iface="ens19",
                       _lan_tun="tun-katakomba")
        r = Recorder()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertTrue(r.ran("iptables -X KATAKOMBA_LAN_FWD"))

    def test_nettoyage_au_demarrage_garde_le_filtrage_lan(self):
        for actif in (False, True):
            self.permanent(actif)
            d = FakeDaemon(config=LAN)
            r = Recorder()
            with patched_run(r):
                d.cleanup_stale_rules()
            self.assertEqual(r.ran("KATAKOMBA_LAN_FWD"), not actif, r.dump())
            self.assertTrue(r.ran("-t nat -X KATAKOMBA_LAN_DNS"))

    def test_filtrage_lan_revérifie_tunnel_absent(self):
        self.permanent()
        d = FakeDaemon(config=LAN)
        with patched_run(Recorder()):
            self.assertTrue(d._kill_switch_on())
        r = Recorder({"iptables -S KATAKOMBA_LAN_FWD": (1, "")})
        with patched_run(r):
            d._verifier_blocage()
        self.assertTrue(r.ran("iptables -A KATAKOMBA_LAN_FWD -i ens19 -o tun-katakomba -j RETURN"),
                        r.dump())
        self.assertTrue(d.has_log("filtrage des clients modifié ou retiré", "WARN"))

    def test_carte_lan_permanente(self):
        self.assertEqual(FakeDaemon(config=LAN)._iface_lan_permanente(), "ens19")
        for cfg in ({**LAN, "lan_auto": False}, {**LAN, "lan_iface": "lo"},
                    {**LAN, "lan_iface": "docker0"}, {**LAN, "lan_iface": ""}):
            self.assertEqual(FakeDaemon(config=cfg)._iface_lan_permanente(), "", cfg)

    def test_statut(self):
        d = FakeDaemon()
        st = d._status_snapshot()
        self.assertIs(st["kill_switch_permanent"], False)
        self.assertIs(st["gateway_mode"], False)
        self.permanent()
        self.passerelle()
        st = d._status_snapshot()
        self.assertIs(st["kill_switch_permanent"], True)
        self.assertIs(st["gateway_mode"], True)


class PoseAuDemarrageTest(_AvecTor):
    """python3 -m daemon.permanent poser : katakomba-blocage.service."""

    def _poser(self, config):
        class Daemon(FakeDaemon):
            def __init__(self):
                super().__init__(config=config)
        sauve = m_permanent.Daemon
        m_permanent.Daemon = Daemon
        self.addCleanup(setattr, m_permanent, "Daemon", sauve)
        r = Recorder()
        with patched_run(r):
            code = m_permanent.main(["permanent", "poser"])
        return code, r

    def test_sans_le_reglage_rien(self):
        code, r = self._poser(LAN)
        self.assertEqual(code, 0)
        self.assertEqual(r.calls, [])

    def test_blocage_et_filtrage_lan(self):
        self.permanent()
        code, r = self._poser({**LAN, "kill_switch": False})
        self.assertEqual(code, 0)
        for parent, chaine in (("OUTPUT", "KATAKOMBA_KILL"), ("FORWARD", "KATAKOMBA_KILL_FWD"),
                               ("FORWARD", "KATAKOMBA_LAN_FWD")):
            self.assertTrue(r.ran(f"iptables -I {parent} 1 -j {chaine}"), chaine)
        self.assertTrue(r.ran("ip6tables -I FORWARD 1 -j KATAKOMBA_KILL6_FWD"))

    def test_sans_partage_lan_blocage_seul(self):
        self.permanent()
        code, r = self._poser({})
        self.assertEqual(code, 0)
        self.assertTrue(r.ran("KATAKOMBA_KILL"))
        self.assertFalse(r.ran("KATAKOMBA_LAN_FWD"))

    def test_echec_signale_a_systemd(self):
        self.permanent()

        class Daemon(FakeDaemon):
            def __init__(self):
                super().__init__(config=LAN)
        sauve = m_permanent.Daemon
        m_permanent.Daemon = Daemon
        self.addCleanup(setattr, m_permanent, "Daemon", sauve)
        with patched_run(Recorder({"iptables-restore": (1, "")})):
            self.assertEqual(m_permanent.main(["permanent", "poser"]), 1)
        self.assertEqual(m_permanent.main(["permanent"]), 2)


class ModePasserelleDnsTest(_AvecTor):

    def test_sans_resolved_pas_d_avertissement(self):
        self.passerelle()
        d = FakeDaemon()
        sauve = m_dns.shutil.which
        m_dns.shutil.which = lambda n: None
        self.addCleanup(setattr, m_dns.shutil, "which", sauve)
        with patched_run(Recorder()):
            d._check_dns_stack()
        self.assertFalse([l for l in d.logs if l[0] in ("WARN", "ERROR")], d.log_dump())
        self.assertTrue(d.has_log("Mode passerelle", "INFO"))

    def test_dns_du_vpn_filtre_et_garde_pour_le_partage(self):
        """Pas de resolvectl, mais la liste filtrée sert à KATAKOMBA_LAN_DNS."""
        self.passerelle()
        d = FakeDaemon(_vpn_dns_ips=["10.8.0.1", "192.168.1.1"])
        r = Recorder({"route get 10.8.0.1": (0, "10.8.0.1 dev tun-katakomba src 10.8.0.2"),
                      "route get 192.168.1.1": (0, "192.168.1.1 dev eth0 src 192.168.1.20"),
                      "is-active": (3, "inactive")})
        appels = Recorder()
        with patched_run(r), patched_subprocess(m_dns, appels):
            d._apply_vpn_dns()
        self.assertEqual(d._vpn_dns_ips, ["10.8.0.1"])
        self.assertFalse(appels.ran("resolvectl"), appels.dump())
        self.assertEqual(d._lan_dns_cible(), "10.8.0.1")

    def test_pas_de_dns_split(self):
        self.passerelle()
        sauve = m_dns.RESOLVED_DROP_IN
        m_dns.RESOLVED_DROP_IN = m_core.STATE_DIR / "katakomba-split.conf"
        self.addCleanup(setattr, m_dns, "RESOLVED_DROP_IN", sauve)
        d = FakeDaemon(config={"local_dns": "192.168.1.1", "excluded_domains": ["lan"]})
        appels = Recorder()
        with patched_run(Recorder()), patched_subprocess(m_dns, appels):
            d._apply_dns_split()
        self.assertFalse(m_dns.RESOLVED_DROP_IN.exists())
        self.assertFalse(appels.ran("systemctl"))
        self.assertTrue(d.has_log("DNS split ignoré"))


class ReservationTest(unittest.TestCase):
    """Script de réservation : plusieurs passerelles, un même lot de comptes."""

    def setUp(self):
        self.hook = m_session.HOOK_RESERVATION
        self.hook.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.hook.parent, 0o755)
        self.addCleanup(self.hook.unlink, missing_ok=True)

    def poser_hook(self, mode=0o755):
        self.hook.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(self.hook, mode)

    def test_sans_script_rien_n_est_appele(self):
        d = FakeDaemon()
        r = Recorder()
        with patched_run(r):
            self.assertTrue(d._reserver_compte("ivpn", "openvpn", 0, ("/p.ovpn", "u", "p")))
        self.assertEqual(r.calls, [])

    def test_accorde_puis_libere_au_changement(self):
        self.poser_hook()
        d = FakeDaemon()
        r = Recorder()
        with patched_run(r):
            self.assertTrue(d._reserver_compte("ivpn", "openvpn", 0, ("/p.ovpn", "bob", "x")))
            self.assertTrue(d._reserver_compte("ivpn", "openvpn", 0, ("/p.ovpn", "bob", "x")))
            self.assertTrue(d._reserver_compte("ivpn", "openvpn", 1, ("/p.ovpn", "alice", "y")))
            d._liberer_compte()
        actions = [c.split()[1] for c in r.calls]
        self.assertEqual(actions, ["reserver", "reserver", "liberer", "reserver", "liberer"])
        self.assertIn(" ivpn openvpn 1 ", r.calls[0])
        self.assertIn(" ivpn openvpn 1 ", r.calls[2], "le compte quitté est libéré")
        self.assertIsNone(d._compte_reserve)
        self.assertEqual(len(d.logged("réservé par le script")), 2, "pas de redite")

    def test_empreinte_sans_l_identifiant(self):
        e = FakeDaemon._empreinte_compte("openvpn", ("/p.ovpn", "p1234567", "secret"))
        self.assertRegex(e, r"^[0-9a-f]{16}$")
        self.assertNotIn("1234567", e)
        self.assertEqual(e, FakeDaemon._empreinte_compte("openvpn", ("/autre.ovpn", "p1234567", "z")),
                         "même compte, même empreinte d'une passerelle à l'autre")
        self.assertEqual(FakeDaemon._empreinte_compte("wireguard", ("/a/b/ch.conf", "x", 0)),
                         FakeDaemon._empreinte_compte("wireguard", ("/c/ch.conf", "y", 3)))

    def test_refus_motive(self):
        self.poser_hook()
        d = FakeDaemon()
        with patched_run(Recorder({"reserver": (1, "pris par gw-2\n")})):
            self.assertFalse(d._reserver_compte("ivpn", "openvpn", 2, ("/p.ovpn", "u", "p")))
        self.assertTrue(d.has_log("Compte 3 (ivpn) refusé par le script de réservation "
                                  "(pris par gw-2)", "WARN"), d.log_dump())
        self.assertIsNone(d._compte_reserve)

    def test_script_aux_droits_douteux_refuse_tout(self):
        for mode in (0o775, 0o757, 0o644):
            self.poser_hook(mode)
            d = FakeDaemon()
            r = Recorder()
            with patched_run(r):
                self.assertFalse(d._reserver_compte("ivpn", "openvpn", 0, ("/p", "u", "p")))
                self.assertFalse(d._reserver_compte("ivpn", "openvpn", 1, ("/p", "v", "p")))
            self.assertEqual(r.calls, [], oct(mode))
            self.assertEqual(len(d.logged("refusé : lui et son dossier", "ERROR")), 1)

    def test_lien_symbolique_refuse(self):
        cible = self.hook.with_name("vrai")
        cible.write_text("#!/bin/sh\n")
        os.chmod(cible, 0o755)
        self.addCleanup(cible.unlink)
        self.hook.symlink_to(cible)
        self.assertIs(FakeDaemon()._hook_reservation(), False)

    def test_compte_refuse_passe_au_suivant_en_quarantaine(self):
        self.poser_hook()
        r = Recorder({" 1 ": (1, "occupé")})
        with patched_run(r):
            d, essais = boucle([provider("ivpn", 3)], ["arret"])
        self.assertEqual(essais, [(0, "openvpn", 1)], "compte 1 réservé ailleurs : jamais essayé")
        self.assertIn((0, 0), d._account_cooldown)
        self.assertEqual(r.calls[-1].split()[1], "liberer", "boucle finie : compte libéré")


class _Conn:
    def __init__(self, famille, pair=(2, 1234), recu=b""):
        self.family = famille
        self._pair = pair
        self._recu = [recu[i:i + 5] for i in range(0, len(recu), 5)]

    def getpeername(self):
        return self._pair

    def settimeout(self, _s):
        pass

    def recv(self, _n):
        return self._recu.pop(0) if self._recu else b""


class VsockTest(unittest.TestCase):
    AF_VSOCK = getattr(socket, "AF_VSOCK", 40)

    def test_l_hote_seul(self):
        self.assertTrue(statut_vsock.pair_admis(_Conn(self.AF_VSOCK, (2, 5000))))
        for conn in (_Conn(self.AF_VSOCK, (3, 5000)), _Conn(self.AF_VSOCK, (1, 5000)),
                     _Conn(socket.AF_UNIX, "")):
            self.assertFalse(statut_vsock.pair_admis(conn))

    def test_premiere_ligne_bornee(self):
        self.assertEqual(statut_vsock.lire_commande(_Conn(self.AF_VSOCK, recu=b"status\nip\n")),
                         "status")
        trop = statut_vsock.lire_commande(_Conn(self.AF_VSOCK, recu=b"x" * 500))
        self.assertLessEqual(len(trop), statut_vsock.LIGNE_MAX + 1)

    def test_commandes(self):
        appels = []

        def executer(*cmd, delai):
            appels.append(cmd)
            return {"ip": (0, "185.1.2.3\n"), "doctor": (1, '{"code": 1}'),
                    "restart": (0, "Service redémarré.\n")}[cmd[2]]
        st = statut_vsock.repondre("status", executer, statut=lambda: {"tunnel_up": True})
        self.assertEqual(st, {"tunnel_up": True})
        self.assertEqual(statut_vsock.repondre("ip", executer), {"ip": "185.1.2.3"})
        self.assertEqual(statut_vsock.repondre("doctor", executer), {"code": 1})
        self.assertEqual(statut_vsock.repondre("restart", executer), {"ok": True})
        self.assertEqual([c[2] for c in appels], ["ip", "doctor", "restart"])
        self.assertIn("--json", appels[1])

    def test_rien_d_autre(self):
        appels = []
        for cmd in ("stop", "set kill-switch off", "status;reboot", "", "RESTART"):
            r = statut_vsock.repondre(cmd, lambda *c, delai: appels.append(c))
            self.assertEqual(r["erreur"], "commande inconnue", cmd)
        self.assertEqual(appels, [])

    def test_erreurs_lisibles(self):
        def statut():
            raise FileNotFoundError
        self.assertIn("erreur", statut_vsock.repondre("status", statut=statut))
        r = statut_vsock.repondre("ip", lambda *c, delai: (1, "Pas de tunnel : IP non demandée."))
        self.assertEqual(r, {"erreur": "Pas de tunnel : IP non demandée."})
        self.assertEqual(json.dumps(statut_vsock.repondre("doctor", lambda *c, delai: (1, ""))),
                         '{"erreur": "diagnostic illisible"}')


class VsockRestartTest(unittest.TestCase):
    """v4.14.0 : « restart » retiré, ou réservé à un secret partagé."""
    SECRET = "0123456789abcdef0123456789abcdef"

    def setUp(self):
        self.dossier = Path(tempfile.mkdtemp())
        self.chemin = self.dossier / "vsock-restart"
        self.appels = []
        self.journal = []
        patch = mock.patch.object(statut_vsock, "_journal", self.journal.append)
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        for f in self.dossier.iterdir():
            f.unlink()
        self.dossier.rmdir()

    def _ecrire(self, texte, droits=0o600):
        self.chemin.write_text(texte)
        os.chmod(self.chemin, droits)

    def _reglage(self):
        return statut_vsock.reglage_restart(str(self.chemin), proprietaire=os.getuid())

    def _restart(self, ligne):
        def executer(*cmd, delai):
            self.appels.append(cmd)
            return 0, ""
        return statut_vsock.repondre(ligne, executer, reglage=self._reglage)

    def test_absent_ouvert_comme_en_4_13(self):
        self.assertEqual(self._reglage(), ("on", None))
        self.assertEqual(self._restart("restart"), {"ok": True})

    def test_desactive(self):
        self._ecrire("off\n")
        for ligne in ("restart", f"restart {self.SECRET}"):
            self.assertEqual(self._restart(ligne)["erreur"],
                             "restart désactivé sur cette machine")
        self.assertEqual(self.appels, [])

    def test_secret(self):
        self._ecrire(f"secret {self.SECRET}\n")
        for ligne in ("restart", "restart faux-secret-de-16c", f"restart {self.SECRET}x",
                      f"restart {self.SECRET[:-1]}"):
            self.assertIn("secret requis", self._restart(ligne)["erreur"], ligne)
        self.assertEqual(self.appels, [])
        self.assertEqual(len(self.journal), 4, "chaque refus au journal")
        self.assertNotIn(self.SECRET[:8], " ".join(self.journal))
        self.assertEqual(self._restart(f"restart {self.SECRET}"), {"ok": True})
        self.assertEqual(len(self.appels), 1)

    def test_la_ligne_avec_le_secret_tient_dans_la_lecture(self):
        secret = "a" * 48
        self._ecrire(f"secret {secret}\n")
        recu = statut_vsock.lire_commande(
            _Conn(socket.AF_UNIX, recu=f"restart {secret}\n".encode()))
        self.assertEqual(self._restart(recu), {"ok": True})

    def test_reglage_douteux_ferme(self):
        """Un réglage abîmé ou à la portée d'un autre compte ne rouvre pas restart."""
        for texte, droits in ((f"secret {self.SECRET}", 0o644), ("on", 0o640),
                              ("secret court", 0o600), ("secret", 0o600),
                              ("ouvert", 0o600), ("", 0o600)):
            self._ecrire(texte, droits)
            self.assertEqual(self._reglage(), ("off", None), (texte, oct(droits)))
        self._ecrire("on\n")
        self.assertEqual(statut_vsock.reglage_restart(str(self.chemin),
                                                      proprietaire=os.getuid() + 1),
                         ("off", None), "autre propriétaire")
        self.chemin.unlink()
        cible = self.dossier / "cible"
        cible.write_text("on\n")
        os.chmod(cible, 0o600)
        self.chemin.symlink_to(cible)
        self.assertEqual(self._reglage(), ("off", None), "lien symbolique")
        cible.unlink()
        self.assertEqual(self._reglage(), ("off", None), "lien pendant")

    def test_les_autres_commandes_ne_prennent_pas_d_argument(self):
        self._ecrire(f"secret {self.SECRET}\n")
        for ligne in (f"status {self.SECRET}", "doctor x", "ip x"):
            self.assertEqual(self._restart(ligne)["erreur"], "commande inconnue", ligne)
        self.assertEqual(self.appels, [])


if __name__ == "__main__":
    unittest.main()
