"""Pare-feu : blocage hors tunnel, blocage IPv6, partage LAN, plage DHCP de dnsmasq."""

import ipaddress
import pathlib
import types
import unittest

import daemon.firewall as m_firewall
from tests.helpers import FakeDaemon, FakeProc, Recorder, patched_run


LAN_CFG = {"lan_iface": "ens19", "lan_gateway": "10.0.0.1",
           "lan_subnet": "10.0.0.0/24", "lan_dhcp": False}


def lan_rec(**extra):
    """Enregistreur réaliste : « iptables -C » renvoie 1 quand la règle est
    absente (sinon le code saute à raison le -A qui suit)."""
    return Recorder({"-t nat -C": (1, ""), **extra})


class KillSwitchTest(unittest.TestCase):
    """Blocage hors tunnel : seuls le tunnel, Tor et le réseau local sortent.

    Le comportement réel des règles (ce qui passe, ce qui est bloqué) a été
    vérifié sur un noyau, dans un espace réseau isolé ; ces tests en gardent
    la forme et l'ordre."""

    TOR_UID = 112

    def setUp(self):
        self._pwd = m_firewall.pwd
        m_firewall.pwd = types.SimpleNamespace(
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=self.TOR_UID))

    def tearDown(self):
        m_firewall.pwd = self._pwd

    def _poser(self, rec=None, **cfg):
        """« -S » ne liste rien : chaîne pas encore branchée (cas réel)."""
        d = FakeDaemon(config=cfg)
        r = rec or Recorder()
        with patched_run(r):
            ok = d._kill_switch_on()
        return d, r, ok

    @staticmethod
    def _chaine(r, chaine):
        return [c.split(f" -A {chaine} ", 1)[1] for c in r.calls if f" -A {chaine} " in c]

    def test_quatre_chaines_construites_puis_branchees(self):
        d, r, ok = self._poser()
        self.assertTrue(ok)
        self.assertTrue(d._kill_active)
        for outil, parent, chaine in (("iptables", "OUTPUT", "KATAKOMBA_KILL"),
                                      ("iptables", "FORWARD", "KATAKOMBA_KILL_FWD"),
                                      ("ip6tables", "OUTPUT", "KATAKOMBA_KILL6"),
                                      ("ip6tables", "FORWARD", "KATAKOMBA_KILL6_FWD")):
            self.assertTrue(r.ran(f"{outil} :{chaine} - [0:0]"), chaine)
            self.assertTrue(r.ran(f"{outil} -I {parent} 1 -j {chaine}"), chaine)
        # Tout ou rien : aucun branchement avant la dernière règle construite.
        dernier_a = max(i for i, c in enumerate(r.calls) if " -A " in c)
        premier_i = min(i for i, c in enumerate(r.calls) if " -I " in c)
        self.assertLess(dernier_a, premier_i, "chaîne branchée avant d'être complète")

    def test_chaines_remplacees_d_un_seul_tenant(self):
        """iptables-restore --noflush : une chaîne déjà en place (gardée d'un
        lancement précédent) n'est jamais vide ni à moitié remplie.  Aucune
        commande ne la vide ou ne la remplit règle par règle."""
        _, r, _ = self._poser()
        restaurations = [c for c in r.calls if "-restore" in c]
        self.assertEqual(restaurations, ["iptables-restore --noflush -w 5",
                                         "ip6tables-restore --noflush -w 5"])
        self.assertTrue(r.ran("iptables *filter") and r.ran("iptables COMMIT"))
        self.assertFalse([c for c in r.calls if c.split()[1] in ("-F", "-X", "-N")],
                         "chaîne vidée ou recréée hors de la restauration")

    def test_ordre_des_regles_en_sortie(self):
        _, r, _ = self._poser()
        regles = self._chaine(r, "KATAKOMBA_KILL")
        self.assertEqual(regles[:2], ["-o lo -j RETURN", "-o tun+ -j RETURN"])
        self.assertIn(f"-m owner --uid-owner {self.TOR_UID} -j RETURN", regles)
        self.assertEqual(regles[-1], "-j REJECT", "le REJECT final n'est pas en dernier")
        refus_dns = regles.index("-p udp --dport 53 -j REJECT")
        lan = regles.index("-d 192.168.0.0/16 -j RETURN")
        self.assertLess(refus_dns, lan,
                        "le DNS partirait vers le routeur, donc vers le FAI")
        self.assertIn("-p udp --sport 68 --dport 67 -j RETURN", regles, "bail DHCP perdu")

    def test_tcp_refuse_par_reset(self):
        """Sans reset, une connexion IPv6 bloquée attend l'expiration (vérifié)."""
        _, r, _ = self._poser()
        for chaine in ("KATAKOMBA_KILL", "KATAKOMBA_KILL6"):
            regles = self._chaine(r, chaine)
            self.assertEqual(regles[-2], "-p tcp -j REJECT --reject-with tcp-reset", chaine)
            self.assertIn("-p tcp --dport 53 -j REJECT --reject-with tcp-reset", regles)

    def test_jamais_established_sans_ctdir_reply(self):
        """Un ESTABLISHED nu laisserait continuer une connexion sortante
        ouverte à découvert avant la pose du blocage."""
        _, r, _ = self._poser()
        for c in r.calls:
            if "ESTABLISHED" in c and "KATAKOMBA_KILL" in c:
                self.assertIn("--ctdir REPLY", c)

    def test_forward_sans_owner_ni_boucle_locale(self):
        _, r, _ = self._poser()
        for chaine in ("KATAKOMBA_KILL_FWD", "KATAKOMBA_KILL6_FWD"):
            regles = self._chaine(r, chaine)
            self.assertTrue(regles)
            self.assertFalse([x for x in regles if "--uid-owner" in x or "-o lo " in x],
                             f"{chaine} : règle propre à la sortie locale")
            self.assertEqual(regles[0], "-o tun+ -j RETURN")
            self.assertEqual(regles[-1], "-j REJECT")

    def test_ipv6_voisinage_et_reseau_local(self):
        _, r, _ = self._poser()
        v6 = self._chaine(r, "KATAKOMBA_KILL6")
        self.assertIn("-p ipv6-icmp --icmpv6-type neighbour-solicitation -j RETURN", v6)
        self.assertIn("-d fe80::/10 -j RETURN", v6)
        self.assertFalse([x for x in v6 if "192.168." in x or "--sport 68" in x])
        self.assertFalse([x for x in self._chaine(r, "KATAKOMBA_KILL") if "::" in x])

    def test_dns_local_et_exclusions_avant_le_refus_dns(self):
        _, r, _ = self._poser(local_dns="192.168.1.53",
                              excluded_ips=["203.0.113.0/24", "2001:db8::/32", "n'importe",
                                            "0.0.0.0/2"])
        v4 = self._chaine(r, "KATAKOMBA_KILL")
        refus = v4.index("-p udp --dport 53 -j REJECT")
        self.assertLess(v4.index("-d 192.168.1.53/32 -j RETURN"), refus)
        self.assertLess(v4.index("-d 203.0.113.0/24 -j RETURN"), refus)
        # Mêmes refus que pour les routes : IPv6, invalide, trop large.
        for refusee in ("2001:db8::/32", "n'importe", "0.0.0.0/2"):
            self.assertFalse(r.ran(refusee), refusee)

    def test_desactive_dans_les_reglages(self):
        d, r, ok = self._poser(kill_switch=False)
        self.assertFalse(ok)
        self.assertEqual(r.calls, [])
        self.assertTrue(d.has_log("désactivé dans les réglages", "WARN"))

    def test_sans_utilisateur_debian_tor_rien_n_est_pose(self):
        """Impossible de laisser passer Tor seul : le poser couperait tout."""
        def absent(_n):
            raise KeyError(_n)
        m_firewall.pwd = types.SimpleNamespace(getpwnam=absent)
        d, r, ok = self._poser()
        self.assertFalse(ok)
        self.assertEqual(r.calls, [])
        self.assertTrue(d.has_log("debian-tor absent", "ERROR"))

    def test_regle_refusee_tout_est_retire(self):
        d, r, ok = self._poser(Recorder({"--uid-owner": (1, "")}))
        self.assertFalse(ok)
        self.assertFalse(d._kill_active)
        self.assertFalse(r.ran(" -I "), "chaîne incomplète branchée")
        self.assertTrue(r.ran("iptables -X KATAKOMBA_KILL"))
        self.assertTrue(d.has_log("INACTIF", "ERROR"))

    def test_branchement_refuse_tout_est_retire(self):
        d, r, ok = self._poser(Recorder({"-I FORWARD 1 -j KATAKOMBA_KILL_FWD": (1, "")}))
        self.assertFalse(ok)
        self.assertFalse(d._kill_active)
        self.assertTrue(r.ran("iptables -D OUTPUT -j KATAKOMBA_KILL"),
                        "la chaîne déjà branchée reste en place")

    def test_deja_branche_pas_de_doublon(self):
        _, r, ok = self._poser(Recorder({
            "iptables -S OUTPUT": (0, "-P OUTPUT ACCEPT\n-A OUTPUT -j KATAKOMBA_KILL\n"),
            "iptables -S FORWARD": (0, "-P FORWARD ACCEPT\n-A FORWARD -j KATAKOMBA_KILL_FWD\n"),
            "ip6tables -S OUTPUT": (0, "-A OUTPUT -j KATAKOMBA_KS6\n-A OUTPUT -j KATAKOMBA_KILL6\n"),
            "ip6tables -S FORWARD": (0, "-A FORWARD -j KATAKOMBA_KILL6_FWD\n")}))
        self.assertTrue(ok)
        self.assertFalse(r.ran(" -I "))

    def test_regle_d_un_tiers_au_dessus_chaine_remise_en_tete(self):
        """Docker insère ses règles en tête de FORWARD : ce qu'elles
        acceptent ne passerait plus par le blocage."""
        d = FakeDaemon()
        r = Recorder({"iptables -S FORWARD": (
            0, "-P FORWARD ACCEPT\n-A FORWARD -j DOCKER-USER\n"
               "-A FORWARD -j KATAKOMBA_KILL_FWD\n-A FORWARD -j ACCEPT\n"
               "-A FORWARD -j KATAKOMBA_KILL_FWD\n")})
        with patched_run(r):
            self.assertIs(d._brancher("iptables", "FORWARD", "KATAKOMBA_KILL_FWD"), True)
        self.assertEqual(r.calls[1:], ["iptables -I FORWARD 1 -j KATAKOMBA_KILL_FWD",
                                       "iptables -D FORWARD 5", "iptables -D FORWARD 3"])

    def test_branchement_impossible(self):
        d = FakeDaemon()
        with patched_run(Recorder({" -I ": (1, "")})):
            self.assertIsNone(d._brancher("iptables", "OUTPUT", "KATAKOMBA_KILL"))

    def test_echec_signale_une_seule_fois(self):
        """La surveillance réessaie toutes les 30 s : pas la même erreur au
        journal à chaque fois."""
        d = FakeDaemon()
        with patched_run(Recorder({"--uid-owner": (1, "")})):
            for _ in range(3):
                self.assertFalse(d._kill_switch_on())
        self.assertEqual(len(d.logged("INACTIF", "ERROR")), 1)

    def test_off_retire_tout(self):
        d, _, _ = self._poser()
        r = Recorder({" -D ": (1, "")})
        with patched_run(r):
            d._kill_switch_off()
        self.assertFalse(d._kill_active)
        for outil, chaine in (("iptables", "KATAKOMBA_KILL"), ("iptables", "KATAKOMBA_KILL_FWD"),
                              ("ip6tables", "KATAKOMBA_KILL6"),
                              ("ip6tables", "KATAKOMBA_KILL6_FWD")):
            self.assertTrue(r.ran(f"{outil} -X {chaine}"), chaine)
        self.assertTrue(d.has_log("levé", "OK"))

    def test_off_sans_activation_ne_fait_rien(self):
        d = FakeDaemon()
        r = Recorder()
        with patched_run(r):
            d._kill_switch_off()
        self.assertEqual(r.calls, [])


class VerifierBlocageTest(unittest.TestCase):
    """v4.7.0 : le blocage n'était posé qu'une fois, jamais revérifié."""

    def setUp(self):
        self._pwd = m_firewall.pwd
        m_firewall.pwd = types.SimpleNamespace(
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=112))
        self.addCleanup(setattr, m_firewall, "pwd", self._pwd)
        self.d = FakeDaemon()
        with patched_run(Recorder()):
            self.assertTrue(self.d._kill_switch_on())
        self.d.logs.clear()

    def _etat(self, **defauts):
        """Réponses d'iptables pour un blocage intact, sauf `defauts`."""
        rep = {}
        for outil, parent, chaine, _v6, _fwd in m_firewall.KILL_CHAINS:
            n = self.d._kill_attendu[chaine]
            rep[f"{outil} -S {chaine}"] = (0, f"-N {chaine}\n" + f"-A {chaine} -j X\n" * n)
            rep[f"{outil} -S {parent}"] = (0, f"-P {parent} ACCEPT\n-A {parent} -j {chaine}\n")
        rep.update(defauts)

        class Exact(Recorder):
            """Réponse par commande EXACTE : « iptables -S KATAKOMBA_KILL »
            est aussi le début de « … -S KATAKOMBA_KILL_FWD »."""
            def __call__(self, *cmd, **kwargs):
                ligne = " ".join(cmd)
                if ligne in rep:
                    self.calls.append(ligne)
                    from tests.helpers import Result
                    return Result(*rep[ligne])
                return super().__call__(*cmd, **kwargs)
        return Exact()

    def test_intact_rien_n_est_touche(self):
        r = self._etat()
        with patched_run(r):
            self.assertFalse(self.d._verifier_blocage())
        self.assertTrue(all(" -S " in c for c in r.calls), r.dump())
        self.assertEqual(self.d.logs, [])

    def test_chaine_videe_tout_est_repose(self):
        r = self._etat(**{"iptables -S KATAKOMBA_KILL": (0, "-N KATAKOMBA_KILL\n")})
        with patched_run(r):
            self.assertTrue(self.d._verifier_blocage())
        self.assertTrue(r.ran("iptables-restore"))
        self.assertTrue(self.d._kill_active)
        self.assertTrue(self.d.has_log("modifié ou retiré par un autre outil", "WARN"))

    def test_chaine_disparue_tout_est_repose(self):
        r = self._etat(**{"ip6tables -S KATAKOMBA_KILL6_FWD": (1, "")})
        with patched_run(r):
            self.assertTrue(self.d._verifier_blocage())
        self.assertTrue(r.ran("ip6tables-restore"))

    def test_branchement_retire_remis(self):
        r = self._etat(**{"iptables -S OUTPUT": (0, "-P OUTPUT ACCEPT\n")})
        with patched_run(r):
            self.assertTrue(self.d._verifier_blocage())
        self.assertTrue(r.ran("iptables -I OUTPUT 1 -j KATAKOMBA_KILL"))
        self.assertFalse(r.ran("-restore"), "chaînes intactes : rien à reconstruire")
        self.assertTrue(self.d.has_log("n'était plus en tête de OUTPUT", "WARN"))

    def test_pose_impossible_au_demarrage_retentee(self):
        d = FakeDaemon()
        with patched_run(Recorder()):
            self.assertTrue(d._verifier_blocage())
        self.assertTrue(d._kill_active)

    def test_desactive_ou_leve_expres_jamais_repose(self):
        for d in (FakeDaemon(config={"kill_switch": False}),
                  FakeDaemon(_kill_renonce=True)):
            r = Recorder()
            with patched_run(r):
                self.assertFalse(d._verifier_blocage())
            self.assertEqual(r.calls, [])

    def test_blocage_ipv6_repose(self):
        d = FakeDaemon(config={"kill_switch": False})
        with patched_run(Recorder()):
            d._ipv6_block_on()
        r = Recorder({"ip6tables -S KATAKOMBA_KS6": (0, "-N KATAKOMBA_KS6\n")})
        with patched_run(r):
            self.assertTrue(d._verifier_blocage())
        self.assertTrue(r.ran("ip6tables-restore"))
        self.assertTrue(d._ipv6_blocked)


class GardeVpnTest(unittest.TestCase):
    """OpenVPN, le pont et les assistants d'API ne parlent qu'à Tor, en local."""

    def setUp(self):
        self._pwd = m_firewall.pwd
        self.addCleanup(setattr, m_firewall, "pwd", self._pwd)
        m_firewall.pwd = types.SimpleNamespace(
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=998))

    def test_tout_sauf_la_boucle_locale_refuse(self):
        d = FakeDaemon(config={"kill_switch": False})     # même sans blocage
        r = Recorder()
        with patched_run(r):
            d._garde_vpn_on()
        for outil, chaine in (("iptables", "KATAKOMBA_VPN"), ("ip6tables", "KATAKOMBA_VPN6")):
            regles = [c.split(f" -A {chaine} ", 1)[1] for c in r.calls if f" -A {chaine} " in c]
            self.assertEqual(regles, [
                "-o lo -j RETURN",
                "-m owner --uid-owner 998 -p tcp -j REJECT --reject-with tcp-reset",
                "-m owner --uid-owner 998 -j REJECT"])
            self.assertTrue(r.ran(f"{outil} -I OUTPUT 1 -j {chaine}"))
        self.assertTrue(d._garde_vpn)

    def test_retrait(self):
        d = FakeDaemon()
        with patched_run(Recorder()):
            d._garde_vpn_on()
        r = Recorder({" -D ": (1, "")})
        with patched_run(r):
            d._garde_vpn_off()
        self.assertTrue(r.ran("iptables -X KATAKOMBA_VPN"))
        self.assertTrue(r.ran("ip6tables -X KATAKOMBA_VPN6"))
        self.assertFalse(d._garde_vpn)

    def test_sans_le_compte_rien_n_est_pose(self):
        def absent(_n):
            raise KeyError(_n)
        m_firewall.pwd = types.SimpleNamespace(getpwnam=absent)
        d, r = FakeDaemon(), Recorder()
        with patched_run(r):
            d._garde_vpn_on()
        self.assertEqual(r.calls, [])

    def test_echec_signale_sans_bloquer(self):
        d = FakeDaemon()
        with patched_run(Recorder({"-restore": (1, "")})):
            d._garde_vpn_on()
        self.assertFalse(d._garde_vpn)
        self.assertTrue(d.has_log("Garde du compte katakomba-vpn", "WARN"))


class Ipv6BlockTest(unittest.TestCase):

    def setUp(self):
        self._pwd = m_firewall.pwd
        self.addCleanup(setattr, m_firewall, "pwd", self._pwd)
        m_firewall.pwd = types.SimpleNamespace(
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=112))

    def test_chaines_creees_et_branchees(self):
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        self.assertTrue(d._ipv6_blocked)
        self.assertTrue(r.ran("ip6tables :KATAKOMBA_KS6 - [0:0]"))
        self.assertTrue(r.ran("ip6tables -I OUTPUT 1 -j KATAKOMBA_KS6"))
        self.assertTrue(r.ran("ip6tables -I FORWARD 1 -j KATAKOMBA_KS6_FWD"))
        # Le tunnel et lo doivent être exemptés AVANT le refus final.
        self.assertTrue(r.ran("-A KATAKOMBA_KS6 -o tun+ -j RETURN"))
        self.assertTrue(r.ran("-A KATAKOMBA_KS6 -j REJECT"))

    def test_memes_regles_que_le_blocage_hors_tunnel(self):
        """v4.7.0 : l'ancienne chaîne jetait tout, voisinage IPv6 compris, et
        laissait continuer les connexions sortantes déjà ouvertes."""
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        regles = [c.split(" -A KATAKOMBA_KS6 ", 1)[1] for c in r.calls
                  if " -A KATAKOMBA_KS6 " in c]
        self.assertEqual(regles[-1], "-j REJECT", f"le refus n'est pas en dernier : {regles}")
        self.assertIn("-p ipv6-icmp --icmpv6-type neighbour-solicitation -j RETURN", regles)
        self.assertIn("-d fe80::/10 -j RETURN", regles)
        self.assertIn("-m owner --uid-owner 112 -j RETURN", regles)
        for regle in regles:
            if "ESTABLISHED" in regle:
                self.assertIn("--ctdir REPLY", regle)
        self.assertFalse([c for c in r.calls if " DROP" in c])

    def test_idempotent(self):
        d = FakeDaemon(_tun_iface="tun0")
        with patched_run(Recorder()):
            d._ipv6_block_on()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_on()
        self.assertEqual(r.calls, [], "règles réinstallées une seconde fois")

    def test_echec_output_annule_l_activation(self):
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder({"-I OUTPUT": (1, ""), " -D ": (1, "")})
        with patched_run(r):
            d._ipv6_block_on()
        self.assertFalse(d._ipv6_blocked)
        self.assertTrue(d.has_log("Blocage IPv6 INACTIF", "ERROR"))
        self.assertTrue(r.ran("ip6tables -X KATAKOMBA_KS6"), "chaîne laissée")

    def test_regles_refusees(self):
        d = FakeDaemon(_tun_iface="tun0")
        r = Recorder({"-restore": (1, "")})
        with patched_run(r):
            d._ipv6_block_on()
        self.assertFalse(d._ipv6_blocked)
        self.assertFalse(r.ran(" -I "))
        self.assertTrue(d.has_log("Blocage IPv6 INACTIF", "ERROR"))

    def test_off_supprime_et_reinitialise(self):
        d = FakeDaemon(_tun_iface="tun0")
        with patched_run(Recorder()):
            d._ipv6_block_on()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_off()
        self.assertFalse(d._ipv6_blocked)
        self.assertTrue(r.ran("-D OUTPUT -j KATAKOMBA_KS6"))
        self.assertTrue(r.ran("-X KATAKOMBA_KS6"))
        self.assertTrue(r.ran("-D FORWARD -j KATAKOMBA_KS6_FWD"))
        self.assertTrue(r.ran("-X KATAKOMBA_KS6_FWD"))

    def test_off_sans_activation_ne_fait_rien(self):
        d = FakeDaemon()
        r = Recorder()
        with patched_run(r):
            d._ipv6_block_off()
        self.assertEqual(r.calls, [])


class LanSharingTest(unittest.TestCase):
    """Correctif #5 : les règles suivent le nom de l'interface tunnel."""

    def _daemon(self, **cfg):
        d = FakeDaemon(config={**LAN_CFG, **cfg}, _tun_iface="tun0")
        d._get_default_gateway = lambda: ("192.168.50.1", "eth0")
        d._interface_existe = lambda nom: nom in ("ens19", "eth0", "lo", "docker0")
        return d

    def test_activation_pose_les_regles(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertTrue(d._lan_active)
        self.assertEqual(d._lan_tun, "tun0")
        self.assertTrue(r.ran("ip addr add 10.0.0.1/24 dev ens19"))
        self.assertTrue(r.ran("sysctl -w net.ipv4.ip_forward=1"))
        self.assertTrue(r.ran("-t nat -A POSTROUTING", "-s 10.0.0.0/24 -o tun0 -j MASQUERADE"))
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun0 -j RETURN"))
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -j DROP"))

    def test_drop_en_dernier(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            d._setup_lan_sharing()
        chain = [c for c in r.calls if "-A KATAKOMBA_LAN_FWD" in c]
        self.assertTrue(chain[-1].endswith("-i ens19 -j DROP"),
                        f"le DROP n'est pas en dernier : {chain}")

    def test_refuse_l_interface_uplink(self):
        """Flusher l'uplink couperait tout le réseau : refus catégorique."""
        d = self._daemon(lan_iface="eth0")          # = interface de la route par défaut
        r = lan_rec()
        with patched_run(r):
            self.assertFalse(d._setup_lan_sharing())
        self.assertFalse(d._lan_active)
        self.assertEqual(r.calls, [], "des commandes ont été exécutées malgré le refus")
        self.assertTrue(d.has_log("porte la route par défaut", "ERROR"))

    def test_refuse_les_interfaces_systeme_ou_virtuelles(self):
        """Vider les adresses de « lo » couperait Tor ; docker0, d'autres services."""
        for iface in ("lo", "docker0", "absente0", "eth1\nx"):
            d = self._daemon(lan_iface=iface)
            r = lan_rec()
            with patched_run(r):
                self.assertFalse(d._setup_lan_sharing(), iface)
            self.assertEqual(r.calls, [], iface)
            self.assertTrue(d.has_log("refusée", "ERROR"), iface)

    def test_refuse_sans_interface(self):
        d = self._daemon(lan_iface="")
        with patched_run(lan_rec()):
            self.assertFalse(d._setup_lan_sharing())
        self.assertTrue(d.has_log("aucune interface configurée", "ERROR"))

    def test_refuse_sous_reseau_invalide(self):
        d = self._daemon(lan_subnet="pas-un-reseau")
        with patched_run(lan_rec()):
            self.assertFalse(d._setup_lan_sharing())
        self.assertTrue(d.has_log("sous-réseau invalide", "ERROR"))

    def test_echec_ip_addr_add(self):
        d = self._daemon()
        with patched_run(lan_rec(**{"addr add": (1, "")})):
            self.assertFalse(d._setup_lan_sharing())
        self.assertFalse(d._lan_active)

    def test_rappel_sans_changement_ne_refait_rien(self):
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertEqual(r.calls, [], "règles reconstruites sans raison")
        self.assertEqual(d.logs[-1][1], "Partage LAN actif : ens19 (10.0.0.1/24) → tun0.")

    def test_changement_de_tunnel_reconstruit(self):
        """Le cœur de #5 : tun0 -> tun1 doit réécrire NAT et FORWARD."""
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        d._tun_iface = "tun1"
        r = lan_rec()
        with patched_run(r):
            self.assertTrue(d._setup_lan_sharing())
        self.assertEqual(d._lan_tun, "tun1")
        self.assertTrue(r.ran("-t nat -D POSTROUTING", "-o tun0 -j MASQUERADE"),
                        "ancienne règle NAT tun0 non supprimée")
        self.assertTrue(r.ran("-t nat -A POSTROUTING", "-o tun1 -j MASQUERADE"),
                        "nouvelle règle NAT tun1 absente")
        self.assertTrue(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun1 -j RETURN"))
        self.assertFalse(r.ran("-A KATAKOMBA_LAN_FWD -i ens19 -o tun0"),
                         "RETURN encore posé sur l'ancienne interface")
        self.assertTrue(d.has_log("interface tunnel changée", "WARN"))

    def test_teardown_cible_l_interface_creee(self):
        """La règle NAT doit être retirée avec _lan_tun, pas avec _tun_iface."""
        d = self._daemon()
        with patched_run(lan_rec()):
            d._setup_lan_sharing()
        d._tun_iface = "tun9"                      # le tunnel a encore bougé
        r = lan_rec()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertTrue(r.ran("-t nat -D POSTROUTING", "-o tun0 -j MASQUERADE"),
                        f"mauvaise interface visée : {r.dump()}")
        self.assertFalse(r.ran("-o tun9"))
        self.assertFalse(d._lan_active)
        self.assertEqual(d._lan_tun, "")

    def test_teardown_sans_activation_ne_fait_rien(self):
        d = self._daemon()
        r = lan_rec()
        with patched_run(r):
            d._teardown_lan_sharing()
        self.assertEqual(r.calls, [])

    def test_masquerade_non_dupliquee(self):
        """-C avant -A : si la règle existe déjà, ne pas l'empiler."""
        d = self._daemon()
        r = Recorder({"-t nat -C": (0, "")})   # règle déjà présente
        with patched_run(r):
            d._setup_lan_sharing()
        self.assertEqual(r.count("-t nat -A POSTROUTING"), 0,
                         "règle NAT ajoutée alors qu'elle existait")


class VerifierLanTest(unittest.TestCase):
    """Adresse de la carte LAN retirée par systemd-networkd : reposée."""

    def _daemon(self):
        d = FakeDaemon(config=LAN_CFG, _tun_iface="tun0")
        d._get_default_gateway = lambda: ("192.168.50.1", "eth0")
        d._interface_existe = lambda nom: nom == "ens19"
        with patched_run(lan_rec()):
            self.assertTrue(d._setup_lan_sharing())
        return d

    def test_adresse_memorisee(self):
        d = self._daemon()
        self.assertEqual((d._lan_iface, d._lan_adresse), ("ens19", "10.0.0.1/24"))

    def test_adresse_presente(self):
        d = self._daemon()
        r = Recorder({"addr show": (0, b"3: ens19    inet 10.0.0.1/24 scope global ens19\\"
                                       b"       valid_lft forever preferred_lft forever\n")})
        with patched_run(r):
            self.assertFalse(d._verifier_lan())
        self.assertFalse(r.ran("addr replace"))

    def test_adresse_retiree_reposee(self):
        d = self._daemon()
        r = Recorder({"addr show": (0, b"")})
        with patched_run(r):
            self.assertTrue(d._verifier_lan())
        self.assertTrue(r.ran("ip addr replace 10.0.0.1/24 dev ens19"))
        self.assertTrue(r.ran("ip link set ens19 up"))
        self.assertTrue(d.has_log("reposée", "WARN"))

    def test_carte_debranchee(self):
        d = self._daemon()
        r = Recorder({"addr show": (1, b"")})
        with patched_run(r):
            self.assertFalse(d._verifier_lan())
        self.assertFalse(r.ran("addr replace"))

    def test_partage_inactif(self):
        d = FakeDaemon(config=LAN_CFG)
        r = Recorder()
        with patched_run(r):
            self.assertFalse(d._verifier_lan())
        self.assertEqual(r.calls, [])

    def test_oublie_au_demontage(self):
        d = self._daemon()
        with patched_run(lan_rec()):
            d._teardown_lan_sharing()
        self.assertEqual((d._lan_iface, d._lan_adresse), ("", ""))


class DnsmasqRangeTest(unittest.TestCase):
    """Bornes DHCP de dnsmasq.

    On exerce la VRAIE méthode et on inspecte la ligne de commande construite :
    le thread est exécuté de façon synchrone et Popen est capturé.  Recalculer
    les bornes dans le test ne testerait que le test.
    """

    def _dnsmasq_cmd(self, subnet, gw="10.0.0.1", dhcp=True, dns=()):
        import tempfile
        d = FakeDaemon(config={**LAN_CFG, "lan_dhcp": dhcp}, _vpn_dns_ips=list(dns))
        captured = {}

        class SyncThread:
            def __init__(self, target=None, daemon=None):
                self._target = target

            def start(self):
                self._target()

        def fake_popen(cmd, **kw):
            captured["cmd"] = list(cmd)
            return FakeProc()

        saved = (m_firewall.shutil.which, m_firewall.threading.Thread,
                 m_firewall.subprocess.Popen, m_firewall.LAN_DNSMASQ_PID)
        m_firewall.shutil.which = lambda n: "/usr/sbin/dnsmasq"
        m_firewall.threading.Thread = SyncThread
        m_firewall.subprocess.Popen = fake_popen
        with tempfile.TemporaryDirectory() as tmp:
            # Jamais le vrai /etc/katakomba : la méthode fait unlink().
            m_firewall.LAN_DNSMASQ_PID = pathlib.Path(tmp) / "dnsmasq.pid"
            try:
                d._start_lan_dnsmasq("ens19", gw,
                                     ipaddress.ip_network(subnet, strict=False))
            finally:
                (m_firewall.shutil.which, m_firewall.threading.Thread,
                 m_firewall.subprocess.Popen, m_firewall.LAN_DNSMASQ_PID) = saved
        return d, captured.get("cmd")

    def _plage(self, subnet):
        _, cmd = self._dnsmasq_cmd(subnet)
        if cmd is None:
            return None
        for a in cmd:
            if a.startswith("--dhcp-range="):
                debut, fin, _bail = a.split("=", 1)[1].split(",")
                return (debut, fin)
        return None

    def test_pas_de_serveur_dns(self):
        """Les clients reçoivent le DNS du VPN ; dnsmasq n'a aucun amont à servir."""
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24")
        self.assertIn("--port=0", cmd)

    def test_dns_du_vpn_remis_aux_clients(self):
        """v4.7.0 : 1.1.1.1 était remis en dur — les requêtes de tout le
        réseau partagé allaient à un tiers, même quand le VPN a son DNS."""
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24", dns=["pas-une-ip", "10.8.0.1", "10.8.0.2"])
        self.assertIn("--dhcp-option=6,10.8.0.1", cmd)

    def test_sans_dns_du_vpn_repli(self):
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24")
        self.assertIn("--dhcp-option=6,1.1.1.1", cmd)

    def test_slash_24_plage_centrale(self):
        self.assertEqual(self._plage("10.0.0.0/24"), ("10.0.0.100", "10.0.0.200"))

    def test_slash_28_plage_reduite(self):
        self.assertEqual(self._plage("10.0.0.0/28"), ("10.0.0.4", "10.0.0.11"))

    def test_slash_30_deux_hotes(self):
        self.assertEqual(self._plage("10.0.0.0/30"), ("10.0.0.1", "10.0.0.2"))

    def test_slash_31_trop_petit_pas_de_dnsmasq(self):
        d, cmd = self._dnsmasq_cmd("10.0.0.0/31")
        self.assertIsNone(cmd, "dnsmasq lancé sur un sous-réseau sans hôte")
        self.assertTrue(d.has_log("trop petit pour le DHCP", "WARN"))

    def test_slash_8_instantane_sans_explosion_memoire(self):
        """Un /8 = 16 M d'adresses : le calcul doit rester arithmétique."""
        import time
        t0 = time.monotonic()
        plage = self._plage("10.0.0.0/8")
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertEqual(plage, ("10.0.0.100", "10.0.0.200"))

    def test_plage_dans_le_sous_reseau(self):
        for subnet in ("10.0.0.0/24", "192.168.5.0/26", "172.16.0.0/20"):
            debut, fin = self._plage(subnet)
            net = ipaddress.ip_network(subnet)
            self.assertIn(ipaddress.ip_address(debut), net, subnet)
            self.assertIn(ipaddress.ip_address(fin), net, subnet)
            self.assertLessEqual(ipaddress.ip_address(debut),
                                 ipaddress.ip_address(fin), subnet)

    def test_options_dhcp_essentielles(self):
        _, cmd = self._dnsmasq_cmd("10.0.0.0/24", gw="10.0.0.1")
        joined = " ".join(cmd)
        self.assertIn("--interface=ens19", joined)
        self.assertIn("--bind-interfaces", joined)
        self.assertIn("--dhcp-option=3,10.0.0.1", joined)   # passerelle
        self.assertIn("--no-resolv", joined)
        self.assertIn("--pid-file=", joined)

    def test_dnsmasq_absent_avertit(self):
        d = FakeDaemon(config={**LAN_CFG, "lan_dhcp": True})
        saved = m_firewall.shutil.which
        m_firewall.shutil.which = lambda n: None
        try:
            d._start_lan_dnsmasq("ens19", "10.0.0.1",
                                 ipaddress.ip_network("10.0.0.0/24"))
        finally:
            m_firewall.shutil.which = saved
        self.assertTrue(d.has_log("dnsmasq non installé", "WARN"))


if __name__ == "__main__":
    unittest.main()
