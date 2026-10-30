"""WireGuard : lecture des .conf, interface, pont, session, décisions de la
boucle propres à WireGuard, contrôle du circuit sur le pont.  La logique
commune aux deux transports (ordre des comptes, quarantaine, mesure du
débit) est testée dans test_openvpn.py et test_session.py."""

import base64
import os
import pathlib
import sys
import tempfile
import time
import unittest

import daemon.session as m_session
import daemon.wireguard as m_wireguard
from tests.helpers import (FakeDaemon, FakeProc, Recorder, no_sleep,
                           patched_run, patched_subprocess, provider_wg)
from validation import analyser_wg, conf_wg_noyau

CLE_A = base64.b64encode(bytes(range(32))).decode()
CLE_B = base64.b64encode(bytes(range(32, 64))).decode()
PROTON = f"""[Interface]
# Bouncing = 1
PrivateKey = {CLE_A}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# NL-FREE#153
PublicKey = {CLE_B}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.107.56.211:51820
PersistentKeepalive = 25
"""
IVPN = f"""# Katakomba-Emballage = ivpn
# Katakomba-Serveur = 95.211.198.169:80
# Katakomba-Cible = 95.211.198.167:15351
# Katakomba-UUID = 27de860d-5601-412d-8b71-baa048a94b98
# Katakomba-Session = jeton
[Interface]
PrivateKey = {CLE_A}
Address = 172.30.112.166/32
DNS = 172.16.0.1
[Peer]
PublicKey = {CLE_B}
AllowedIPs = 0.0.0.0/0
Endpoint = 95.211.198.167:2049
"""
# Format du générateur de configuration de Mullvad (mullvad.net).
MULLVAD = f"""[Interface]
# Device: Happy Fish
PrivateKey = {CLE_A}
Address = 10.66.12.34/32,fc00:bbbb:bbbb:bb01::3:c22/128
DNS = 10.64.0.1

[Peer]
PublicKey = {CLE_B}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 185.65.134.82:51820
"""


class AnalyserWgTest(unittest.TestCase):
    """Le daemon lit en root des .conf que le groupe peut écrire."""

    def test_proton(self):
        r, refus, avert = analyser_wg(PROTON)
        self.assertEqual((refus, avert), ([], []))
        self.assertEqual(r["emballage"], "proton")
        self.assertEqual(r["serveur"], "185.107.56.211:443", "Stealth : TCP 443, même IP")
        self.assertEqual(r["adresse"], "10.2.0.2")
        self.assertEqual(r["dns"], ["10.2.0.1"])
        self.assertEqual(r["endpoint"], ("185.107.56.211", 51820))

    def test_fins_de_ligne_windows(self):
        """Les fichiers de Proton ont des « \\r\\n » : la clé ne doit pas les garder."""
        r, refus, _ = analyser_wg(PROTON.replace("\n", "\r\n"))
        self.assertEqual(refus, [])
        self.assertEqual(r["cle_privee"], CLE_A)

    def test_ivpn(self):
        r, refus, _ = analyser_wg(IVPN)
        self.assertEqual(refus, [])
        self.assertEqual((r["emballage"], r["serveur"], r["cible"]),
                         ("ivpn", "95.211.198.169:80", "95.211.198.167:15351"))
        self.assertEqual(r["uuid"], "27de860d-5601-412d-8b71-baa048a94b98")

    def test_mullvad_reconnu_sans_commentaire(self):
        r, refus, avert = analyser_wg(MULLVAD)
        self.assertEqual((refus, avert), ([], []))
        self.assertEqual(r["emballage"], "mullvad")
        self.assertEqual(r["serveur"], "185.65.134.82:443",
                         "udp-over-tcp : TCP 443, même IP")
        self.assertEqual(r["adresse"], "10.66.12.34")
        self.assertEqual(r["dns"], ["10.64.0.1"])

    def test_mullvad_reconnu_a_l_ipv6_seule(self):
        r, _, _ = analyser_wg(MULLVAD.replace("DNS = 10.64.0.1\n", ""))
        self.assertEqual(r["emballage"], "mullvad")
        r, _, _ = analyser_wg(MULLVAD.replace(",fc00:bbbb:bbbb:bb01::3:c22/128", ""))
        self.assertEqual(r["emballage"], "mullvad", "DNS seul")

    def test_mullvad_reglages_explicites(self):
        r, refus, _ = analyser_wg("# Katakomba-Serveur = 185.65.134.82:80\n" + MULLVAD)
        self.assertEqual(refus, [])
        self.assertEqual(r["serveur"], "185.65.134.82:80")
        r, _, _ = analyser_wg("# Katakomba-Emballage = proton\n" + MULLVAD)
        self.assertEqual(r["emballage"], "proton", "le commentaire l'emporte")
        r, _, _ = analyser_wg("# Katakomba-Emballage = mullvad\n" + PROTON)
        self.assertEqual((r["emballage"], r["serveur"]), ("mullvad", "185.107.56.211:443"))

    def test_ivpn_incomplet_refuse(self):
        for retirer in ("# Katakomba-Cible", "# Katakomba-UUID", "# Katakomba-Serveur"):
            texte = "\n".join(l for l in IVPN.splitlines() if not l.startswith(retirer))
            r, refus, _ = analyser_wg(texte)
            self.assertIsNone(r, retirer)
            self.assertTrue(refus)

    def test_cle_mal_formee_refusee_sans_la_recopier(self):
        texte = PROTON.replace(CLE_A, "secretABCDEF")
        r, refus, _ = analyser_wg(texte)
        self.assertIsNone(r)
        self.assertTrue(any("privatekey" in m for m in refus))
        self.assertFalse(any("secretABCDEF" in m for m in refus), "clé recopiée dans un message")

    def test_nom_de_domaine_refuse(self):
        """Rien n'est résolu hors de Tor : une adresse IP, jamais un nom."""
        r, refus, _ = analyser_wg(PROTON.replace("185.107.56.211:51820", "nl.example.net:51820"))
        self.assertIsNone(r)
        self.assertTrue(any("Endpoint" in m for m in refus))

    def test_scripts_de_wg_quick_ignores(self):
        texte = PROTON.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nPostUp = rm -rf /\nPreDown = x")
        r, refus, avert = analyser_wg(texte)
        self.assertEqual(refus, [])
        self.assertEqual(len(avert), 2)
        self.assertNotIn("rm -rf", repr(r))

    def test_deux_pairs_refuses(self):
        r, refus, _ = analyser_wg(PROTON + f"\n[Peer]\nPublicKey = {CLE_A}\nEndpoint = 1.2.3.4:1\n")
        self.assertIsNone(r)
        self.assertTrue(any("exactement un pair" in m for m in refus))

    def test_champs_obligatoires(self):
        for champ in ("PrivateKey", "Address", "PublicKey", "Endpoint"):
            texte = "\n".join(l for l in PROTON.splitlines() if not l.startswith(champ))
            self.assertIsNone(analyser_wg(texte)[0], champ)

    def test_ipv6_seule_refusee(self):
        r, refus, _ = analyser_wg(PROTON.replace("10.2.0.2/32", "fd00::2/128"))
        self.assertIsNone(r)

    def test_section_inconnue_refusee(self):
        self.assertIsNone(analyser_wg(PROTON + "\n[Autre]\nX = 1\n")[0])

    def test_mtu_borne(self):
        self.assertEqual(analyser_wg(PROTON.replace("DNS", "MTU = 1380\nDNS"))[0]["mtu"], 1380)
        r, _, avert = analyser_wg(PROTON.replace("DNS", "MTU = 9000\nDNS"))
        self.assertIsNone(r["mtu"])
        self.assertTrue(avert)

    def test_emballage_inconnu(self):
        self.assertIsNone(analyser_wg("# Katakomba-Emballage = autre\n" + PROTON)[0])

    def test_fichier_trop_gros(self):
        self.assertIsNone(analyser_wg(PROTON + "#" * 70000)[0])

    def test_conf_remise_a_wg(self):
        """Réécrite par le daemon : pair joint par le pont, rien d'autre."""
        r, _, _ = analyser_wg(PROTON.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nPostUp = x"))
        texte = conf_wg_noyau(r, "127.0.0.1:51871")
        self.assertIn("Endpoint = 127.0.0.1:51871", texte)
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", texte)
        self.assertIn(f"PrivateKey = {CLE_A}", texte)
        for absent in ("PostUp", "DNS", "Address", "185.107.56.211", "::/0"):
            self.assertNotIn(absent, texte)


class Installation:
    """SCRIPT_DIR factice, avec un providers/<nom>/<fichier>."""

    def __init__(self, contenu=PROTON, nom="compte0.conf"):
        self.tmp = tempfile.TemporaryDirectory()
        self.racine = pathlib.Path(self.tmp.name)
        self.dossier = self.racine / "providers" / "vpn-a"
        self.dossier.mkdir(parents=True)
        self.chemin = self.dossier / nom
        self.chemin.write_text(contenu)
        self._saved = m_wireguard.SCRIPT_DIR
        m_wireguard.SCRIPT_DIR = self.racine

    def fermer(self):
        m_wireguard.SCRIPT_DIR = self._saved
        self.tmp.cleanup()


class ConfActiveTest(unittest.TestCase):

    def setUp(self):
        self.inst = Installation()
        self.addCleanup(self.inst.fermer)

    def _d(self, comptes):
        return FakeDaemon(config={"providers": [{"name": "vpn-a", "wireguard": comptes}]},
                          _transport="wireguard")

    def test_chemin_resolu_sous_script_dir(self):
        d = self._d([{"conf": "providers/vpn-a/compte0.conf"}])
        self.assertEqual(d._compte_wireguard(), (str(self.inst.chemin), "vpn-a", 0))

    def test_chemin_hors_de_providers_refuse(self):
        for chemin in ("/etc/shadow", "providers/../../etc/shadow", "providers/vpn-a/../x.conf"):
            d = self._d([{"conf": chemin}])
            self.assertIsNone(d._compte_wireguard(), chemin)
        self.assertTrue(d.has_log("chemin du .conf refusé", "ERROR"))

    def test_fichier_absent(self):
        d = self._d([{"conf": "providers/vpn-a/absent.conf"}])
        self.assertIsNone(d._compte_wireguard())
        self.assertTrue(d.has_log("introuvable", "ERROR"))

    def test_sans_compte_ou_hors_bornes(self):
        self.assertIsNone(self._d([])._compte_wireguard())
        d = self._d([{"conf": "providers/vpn-a/compte0.conf"}])
        d._current_account_idx = 3
        self.assertIsNone(d._compte_wireguard())
        self.assertIsNone(FakeDaemon(config={"providers": []})._compte_wireguard())

    def test_entree_sans_fichier(self):
        self.assertIsNone(self._d([{"u": "ancien", "p": "format"}])._compte_wireguard())


class PreparerWgTest(unittest.TestCase):

    def setUp(self):
        self.inst = Installation()
        self.addCleanup(self.inst.fermer)

    def test_conf_propre_acceptee(self):
        d = FakeDaemon()
        self.assertEqual(d._preparer_wg(str(self.inst.chemin))["adresse"], "10.2.0.2")

    def test_lien_symbolique_refuse(self):
        lien = self.inst.dossier / "lien.conf"
        lien.symlink_to(self.inst.chemin)
        d = FakeDaemon()
        self.assertIsNone(d._preparer_wg(str(lien)))
        self.assertTrue(d.has_log("illisible", "ERROR"))

    def test_fichier_special_refuse(self):
        fifo = self.inst.dossier / "tube.conf"
        os.mkfifo(fifo)
        self.assertIsNone(FakeDaemon()._preparer_wg(str(fifo)))

    def test_refus_journalise_sans_valeur(self):
        self.inst.chemin.write_text(PROTON.replace(CLE_A, "pasunecle"))
        d = FakeDaemon()
        self.assertIsNone(d._preparer_wg(str(self.inst.chemin)))
        self.assertTrue(d.has_log("refusé", "ERROR"))
        self.assertFalse(d.has_log("pasunecle"), "valeur recopiée dans le journal")


class ConfigurerWgTest(unittest.TestCase):

    def setUp(self):
        self.reglages = analyser_wg(PROTON)[0]
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = m_wireguard.WG_CONF_RUN
        m_wireguard.WG_CONF_RUN = pathlib.Path(self.tmp.name) / "wg" / "kk.conf"
        self.addCleanup(setattr, m_wireguard, "WG_CONF_RUN", self._saved)

    def _configurer(self, rec, **reglages):
        d = FakeDaemon(_tun_iface="tun-katakomba")
        lu = []

        def enregistrer(*cmd):
            if cmd[:2] == ("wg", "setconf"):
                lu.append(pathlib.Path(cmd[3]).read_text())
            return rec(*cmd)
        with patched_run(enregistrer):
            issue = d._configurer_wg({**self.reglages, **reglages})
        return d, issue, lu

    def test_sequence(self):
        rec = Recorder()
        d, issue, lu = self._configurer(rec)
        self.assertEqual(issue, "", d.log_dump())
        attendu = ["ip link del dev tun-katakomba",
                   "ip link add dev tun-katakomba type wireguard",
                   f"wg setconf tun-katakomba {m_wireguard.WG_CONF_RUN}",
                   "ip addr add 10.2.0.2/32 dev tun-katakomba",
                   "ip link set dev tun-katakomba mtu 1320",
                   "ip link set dev tun-katakomba up"]
        self.assertEqual(rec.calls, attendu)
        self.assertIn("Endpoint = 127.0.0.1:51871", lu[0])
        self.assertFalse(m_wireguard.WG_CONF_RUN.exists(), "clé privée laissée sur le disque")
        self.assertFalse(any("route" in c for c in rec.calls),
                         "routes posées avant la poignée de main")

    def test_mtu_du_conf(self):
        rec = Recorder()
        self._configurer(rec, mtu=1400)
        self.assertTrue(rec.ran("mtu 1400"))

    def test_fichier_de_cle_prive(self):
        modes = []
        rec = Recorder()

        def enregistrer(*cmd):
            if cmd[:2] == ("wg", "setconf"):
                modes.append(os.stat(cmd[3]).st_mode & 0o777)
            return rec(*cmd)
        d = FakeDaemon(_tun_iface="tun-katakomba")
        with patched_run(enregistrer):
            d._configurer_wg(self.reglages)
        self.assertEqual(modes, [0o600])

    def test_echec_de_wg_ne_journalise_pas_sa_sortie(self):
        rec = Recorder({"wg setconf": (1, f"Key is not the correct length: `{CLE_A}`")})
        d, issue, _ = self._configurer(rec)
        self.assertEqual(issue, "interface")
        self.assertFalse(d.has_log(CLE_A), "clé recopiée dans le journal")
        self.assertEqual(rec.calls[-1], "ip link del dev tun-katakomba")
        self.assertFalse(m_wireguard.WG_CONF_RUN.exists())

    def test_wg_absent(self):
        def sans_wg(*cmd):
            if cmd[0] == "wg":
                raise FileNotFoundError("wg")
            return Recorder()(*cmd)
        d = FakeDaemon(_tun_iface="tun-katakomba")
        with patched_run(sans_wg):
            # « absent » : la boucle passe alors à OpenVPN, s'il est là.
            self.assertEqual(d._configurer_wg(self.reglages), "absent")
        self.assertTrue(d.has_log("wireguard-tools", "ERROR"))
        self.assertFalse(m_wireguard.WG_CONF_RUN.exists())

    def test_module_absent(self):
        d, issue, _ = self._configurer(Recorder({"type wireguard": (2, "")}))
        self.assertEqual(issue, "absent")
        self.assertTrue(d.has_log("module", "ERROR"))


class LancerPontTest(unittest.TestCase):

    def _lancer(self, texte):
        appels = []

        def popen(cmd, **kw):
            appels.append((cmd, kw))
            return FakeProc("12:00:01 Connecté (TLSv1.3).\n")
        d = FakeDaemon()
        with patched_subprocess(m_wireguard, Recorder(), popen=popen):
            d._lancer_pont(analyser_wg(texte)[0], 997, 996)
        return appels[0], d

    def test_sans_droit_et_isole(self):
        (cmd, kw), _ = self._lancer(PROTON)
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (997, 996, []))
        self.assertEqual(cmd[:2], [sys.executable, "-I"], "Python non isolé")
        self.assertTrue(cmd[2].endswith("/pont_wg.py"))
        self.assertEqual(kw["cwd"], "/")
        self.assertNotIn("PYTHONPATH", kw["env"])

    def test_arguments_proton(self):
        (cmd, _), _ = self._lancer(PROTON)
        args = " ".join(cmd[3:])
        self.assertIn("--emballage proton --serveur 185.107.56.211:443", args)
        self.assertIn("--socks 127.0.0.1:9050", args)
        self.assertIn("--ecoute 127.0.0.1:51871", args)
        self.assertNotIn(CLE_A, args, "clé privée en argument (visible de tous)")

    def test_arguments_ivpn(self):
        (cmd, _), _ = self._lancer(IVPN)
        args = " ".join(cmd[3:])
        self.assertIn("--emballage ivpn --serveur 95.211.198.169:80", args)
        self.assertIn("--cible 95.211.198.167:15351", args)
        self.assertIn("--uuid 27de860d-5601-412d-8b71-baa048a94b98", args)
        self.assertNotIn(CLE_A, args)

    def test_arguments_mullvad(self):
        (cmd, _), _ = self._lancer(MULLVAD)
        self.assertEqual(cmd[3:7], ["--emballage", "mullvad",
                                    "--serveur", "185.65.134.82:443"])
        self.assertNotIn("--cible", cmd)
        self.assertNotIn(CLE_A, " ".join(cmd))

    def test_journal_du_pont(self):
        _, d = self._lancer(PROTON)
        for _ in range(100):
            if d.logs:
                break
            time.sleep(0.01)
        self.assertTrue(d.has_log("[pont] Connecté (TLSv1.3).", "INFO"), d.log_dump())


class PoigneeTest(unittest.TestCase):

    def _age(self, sortie, rc=0):
        d = FakeDaemon(_tun_iface="tun-katakomba")
        with patched_run(Recorder({"latest-handshakes": (rc, sortie)})):
            return d._poignee_age()

    def test_jamais(self):
        self.assertIsNone(self._age(f"{CLE_B}\t0\n"))

    def test_recente(self):
        self.assertLess(self._age(f"{CLE_B}\t{int(time.time()) - 10}\n"), 15)

    def test_interface_absente(self):
        self.assertIsNone(self._age("", rc=1))

    def test_sortie_illisible(self):
        self.assertIsNone(self._age("n'importe quoi\n"))


class ProcVivant(FakeProc):
    """Pont qui tourne `n` sondages, puis s'arrête (ou jusqu'à terminate)."""

    def __init__(self, n=10**9):
        super().__init__("")
        self.reste = n

    def poll(self):
        if self.terminated or self.reste <= 0:
            return 0
        self.reste -= 1
        return None


class SessionTest(unittest.TestCase):
    """_session_wireguard : du .conf à la chute du tunnel."""

    def setUp(self):
        self.inst = Installation()
        self.addCleanup(self.inst.fermer)

    def _session(self, proc, poignee, monte=True, **etat):
        d = FakeDaemon(_tun_iface="tun-katakomba", **etat)
        d.appels = []
        d._configurer_wg = lambda r: d.appels.append("configurer") or ""
        d._demonter_tunnel = lambda: d.appels.append("demonter")
        d._revert_vpn_dns = lambda: d.appels.append("dns")

        def actif(r):
            d.appels.append("actif")
            d._tunnel_up = monte
            if monte:
                d._reconnect_reason = ""        # comme le vrai _tunnel_actif
            return monte
        d._tunnel_actif = actif
        ages = iter(poignee)
        d._poignee_age = lambda: next(ages, None)
        with patched_subprocess(m_wireguard, Recorder(), popen=lambda *a, **k: proc), \
                no_sleep(m_session, m_wireguard):
            issue = d._session_wireguard(str(self.inst.chemin), 997, 996)
        return d, issue

    def test_aucune_poignee_de_main(self):
        proc = ProcVivant()
        d, issue = self._session(proc, [])
        self.assertEqual(issue, "echec")
        self.assertNotIn("actif", d.appels)
        self.assertTrue(proc.terminated, "pont laissé en vie")
        self.assertEqual(d.appels[-2:], ["dns", "demonter"])
        self.assertTrue(d.has_log("aucune poignée de main", "WARN"))

    def test_monte_puis_pont_arrete(self):
        proc = ProcVivant(n=5)
        d, issue = self._session(proc, [None, 3.0] + [5.0] * 10)
        self.assertEqual(issue, "coupure")
        self.assertEqual(d.appels[:2], ["configurer", "actif"])
        self.assertFalse(d._tunnel_up)
        self.assertEqual(d._reconnect_reason, "connexion VPN interrompue")

    def test_poignees_qui_cessent(self):
        proc = ProcVivant()
        d, issue = self._session(proc, [1.0, 30.0, 250.0])
        self.assertEqual(issue, "coupure")
        self.assertTrue(d.has_log("tunnel mort", "WARN"))
        self.assertTrue(proc.terminated)

    def test_arret_pendant_la_surveillance_sans_fausse_alerte(self):
        """L'arrêt supprime l'interface : plus de poignée de main lisible, ce
        qui ne dit rien de l'état du tunnel."""
        d, _ = self._session(ProcVivant(n=2), [3.0])
        self.assertFalse(d.has_log("tunnel mort"), d.log_dump())

    def test_arret_demande(self):
        proc = ProcVivant()
        d, issue = self._session(proc, [], _stop_vpn=True)
        self.assertEqual(issue, "arret")
        self.assertIn("demonter", d.appels)

    def test_conf_refuse(self):
        self.inst.chemin.write_text("[Interface]\n")
        d, issue = self._session(ProcVivant(), [])
        self.assertEqual(issue, "refus")
        self.assertNotIn("configurer", d.appels)

    def test_dns_du_conf_retenu(self):
        d, _ = self._session(ProcVivant(n=2), [1.0])
        self.assertEqual(d._vpn_dns_ips, ["10.2.0.1"])


class TunnelActifTest(unittest.TestCase):

    def test_routes_puis_dns_et_quarantaine_levee(self):
        d = FakeDaemon(config={"block_ipv6": True}, _tun_iface="tun-katakomba",
                       _transport="wireguard")
        d.appels = []
        d._monter_tunnel = lambda t: d.appels.append(("monter", t)) or True
        for nom in ("_apply_vpn_dns", "_apply_dns_split", "_ipv6_block_on",
                    "_circuit_quality_check"):
            setattr(d, nom, (lambda n: lambda: d.appels.append(n))(nom))
        d._account_cooldown[(0, 0, "wireguard")] = time.time() + 900
        d._auth_passes = 1
        self.assertTrue(d._tunnel_actif(analyser_wg(PROTON)[0]))
        tunnel = d.appels[0][1]
        self.assertEqual(tunnel["ifconfig"], ("10.2.0.2", "255.255.255.255"))
        self.assertEqual(tunnel["routes"], [], "aucune route poussée : tout le trafic")
        self.assertEqual(d.appels[1:4], ["_apply_vpn_dns", "_apply_dns_split", "_ipv6_block_on"])
        self.assertTrue(d._tunnel_up)
        self.assertEqual(d._account_cooldown, {})
        self.assertEqual(d._auth_passes, 0)

    def test_montage_impossible(self):
        d = FakeDaemon()
        d._monter_tunnel = lambda t: False
        self.assertFalse(d._tunnel_actif(analyser_wg(PROTON)[0]))
        self.assertFalse(d._tunnel_up)
        self.assertEqual(d._reconnect_reason, "tunnel impossible à monter")


class BoucleTest(unittest.TestCase):
    """Décisions de la boucle, sessions simulées."""

    def _boucle(self, issues, config=None, providers=None):
        cfg = {"providers": providers or [provider_wg("a", 3), provider_wg("b", 2)],
               "random_account": False, **(config or {})}
        d = FakeDaemon(config=cfg)
        d.essais = []
        sequence = iter(issues)

        def session(chemin, uid, gid):
            d.essais.append((d._current_provider_idx, d._current_account_idx))
            issue = next(sequence, "arret")
            if issue == "circuit":
                d._circuit_retry = True
                return "coupure"
            return issue
        d._compte_wireguard = lambda: (f"/p/{d._current_provider_idx}/{d._current_account_idx}.conf",
                                  cfg["providers"][d._current_provider_idx]["name"],
                                  d._current_account_idx)
        d._session_wireguard = session
        d._utilisateur_vpn = lambda: (997, 996)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session, m_wireguard):
            d._vpn_loop()
        return d

    def test_echec_retente_puis_conf_suivant(self):
        d = self._boucle(["echec", "echec", "arret"])
        self.assertEqual(d.essais, [(0, 0), (0, 0), (0, 1)])
        self.assertIn((0, 0, "wireguard"), d._account_cooldown,
                      "conf abandonné non mis en quarantaine")
        self.assertTrue(d.has_log("mis en quarantaine"))

    def test_coupure_garde_le_meme_conf(self):
        d = self._boucle(["coupure", "coupure", "arret"])
        self.assertEqual(d.essais, [(0, 0)] * 3)
        self.assertEqual(d._account_cooldown, {})

    def test_coupures_repetees_passent_au_conf_suivant(self):
        n = m_session.RECONNECT_MAX + 1
        d = self._boucle(["coupure"] * n + ["arret"])
        self.assertEqual(d.essais[-1], (0, 1))

    def test_conf_refuse_passe_au_suivant_tout_de_suite(self):
        d = self._boucle(["refus", "arret"])
        self.assertEqual(d.essais, [(0, 0), (0, 1)])

    def test_interface_impossible_abandonne(self):
        d = self._boucle(["interface", "coupure"])
        self.assertEqual(len(d.essais), 1)
        self.assertEqual(d._reconnect_reason, "interface tunnel impossible à créer")

    def test_circuit_retire_garde_le_meme_conf(self):
        d = self._boucle(["circuit", "arret"])
        self.assertEqual(d.essais, [(0, 0), (0, 0)])
        self.assertTrue(d.has_log("circuit Tor neuf", "WARN"))

    def test_reconnexion_desactivee(self):
        d = self._boucle(["coupure", "coupure"], config={"auto_reconnect": False})
        self.assertEqual(len(d.essais), 1)

    def test_tout_echoue_deux_passes_puis_abandon(self):
        d = self._boucle(["echec"] * 100, providers=[provider_wg("a", 1)])
        passes = m_session.AUTH_PASS_MAX
        self.assertEqual(len(d.essais), m_session.ECHECS_PAR_CONF * passes)
        self.assertTrue(d.has_log("Aucun compte n'a pu se connecter après", "ERROR"))

    def test_fournisseurs_dans_l_ordre(self):
        d = self._boucle(["refus"] * 4 + ["arret"])
        self.assertEqual([p for p, _ in d.essais], [0, 0, 0, 1, 1])

    def test_fournisseur_inutilisable_saute(self):
        d = FakeDaemon(config={"providers": [provider_wg("a", 1), provider_wg("b", 1)]})
        essais = []
        d._compte_wireguard = lambda: (None if d._current_provider_idx == 0
                                  else ("/p/b.conf", "b", 0))
        d._session_wireguard = lambda *a: essais.append(d._current_provider_idx) or "arret"
        d._utilisateur_vpn = lambda: (1, 1)
        d._check_socks_port = lambda: True
        d._get_default_gateway = lambda: ("192.168.1.1", "eth0")
        d._ipv6_block_off = lambda: None
        with no_sleep(m_session, m_wireguard):
            d._vpn_loop()
        self.assertEqual(essais, [1])

    def test_compte_impose(self):
        d = FakeDaemon(config={"providers": [provider_wg("a", 3)], "random_account": True})
        vu = []
        d._compte_wireguard = lambda: vu.append(d._current_account_idx) or None
        d._etape_suivante = lambda: False
        d._vpn_loop(0, 0)
        self.assertEqual(vu, [0])


class CircuitQualityTest(unittest.TestCase):
    """Correctifs #2 (thread périmé) et le comportement de re-tirage."""

    def _daemon(self, kbs, **cfg):
        d = FakeDaemon(config={"circuit_check": True, "circuit_min_kbs": 250,
                               "circuit_max_retries": 3, **cfg})
        d._tunnel_up, d._tun_iface, d._transport = True, "tun0", "wireguard"
        d.pont_process = FakeProc(returncode=None)
        d.pont_process._rc = None                       # vivant
        d._measure_tunnel_speed = lambda iface="", still_valid=None: kbs
        d.newnym = []
        d._new_tor_circuit = lambda: d.newnym.append(1)
        return d

    def _run(self, d):
        with no_sleep(m_session, m_wireguard):
            d._circuit_quality_check()
        return d

    def test_debit_suffisant_conserve_le_circuit(self):
        d = self._run(self._daemon(400.0))
        self.assertTrue(d.has_log("Débit OK", "OK"))
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.pont_process.terminated)
        self.assertEqual(d._circuit_attempts, 0)

    def test_debit_faible_retire_un_circuit(self):
        d = self._run(self._daemon(100.0))
        self.assertEqual(d.newnym, [1], "NEWNYM non demandé")
        self.assertTrue(d.pont_process.terminated, "pont non relancé")
        self.assertTrue(d._circuit_retry, "la reconnexion n'est pas marquée « circuit »")
        self.assertEqual(d._circuit_attempts, 1)
        self.assertTrue(d.has_log("Débit faible", "WARN"))

    def test_seuil_exact_accepte(self):
        d = self._run(self._daemon(250.0))
        self.assertTrue(d.has_log("Débit OK", "OK"))
        self.assertEqual(d.newnym, [])

    def test_plafond_d_essais_respecte(self):
        d = self._daemon(50.0)
        d._circuit_attempts = 3
        self._run(d)
        self.assertEqual(d.newnym, [], "re-tirage au-delà du plafond")
        self.assertFalse(d.pont_process.terminated)
        self.assertTrue(d.has_log("circuit conservé", "WARN"))

    def test_mesure_impossible_conserve(self):
        d = self._run(self._daemon(-1.0))
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.pont_process.terminated)
        self.assertTrue(d.has_log("Mesure du débit impossible", "WARN"))

    def test_desactive_ne_mesure_pas(self):
        d = self._daemon(10.0, circuit_check=False)
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [])

    def test_seuil_zero_desactive(self):
        d = self._daemon(10.0, circuit_min_kbs=0)
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [])

    def test_tunnel_ferme_avant_mesure(self):
        d = self._daemon(10.0)
        d._tunnel_up = False
        called = []
        d._measure_tunnel_speed = lambda **k: called.append(1) or 10.0
        self._run(d)
        self.assertEqual(called, [], "mesure lancée alors que le tunnel est fermé")

    def test_processus_remplace_pendant_la_mesure(self):
        """#2 : un thread périmé ne doit PAS tuer le tunnel qui a pris la place."""
        d = self._daemon(50.0)
        ancien = d.pont_process
        nouveau = FakeProc(returncode=None)
        nouveau._rc = None

        def mesure_puis_remplacement(iface="", still_valid=None):
            d.pont_process = nouveau          # reconnexion pendant la mesure
            return 50.0

        d._measure_tunnel_speed = mesure_puis_remplacement
        self._run(d)
        self.assertFalse(nouveau.terminated, "le NOUVEAU tunnel a été tué")
        self.assertFalse(ancien.terminated)
        self.assertEqual(d.newnym, [], "NEWNYM demandé sur un résultat périmé")
        self.assertFalse(d._circuit_retry)
        self.assertTrue(d.has_log("Tunnel renouvelé pendant la mesure", "WARN"))

    def test_tunnel_tombe_pendant_la_mesure(self):
        d = self._daemon(50.0)

        def mesure_puis_chute(iface="", still_valid=None):
            d._tunnel_up = False
            return 50.0

        d._measure_tunnel_speed = mesure_puis_chute
        self._run(d)
        self.assertEqual(d.newnym, [])
        self.assertFalse(d.pont_process.terminated)

    def test_interface_capturee_avant_la_mesure(self):
        d = self._daemon(400.0)
        vues = []
        d._measure_tunnel_speed = lambda iface="", still_valid=None: (vues.append(iface), 400.0)[1]
        self._run(d)
        self.assertEqual(vues, ["tun0"])


if __name__ == "__main__":
    unittest.main()
