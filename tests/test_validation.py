"""Listes blanches .ovpn / torrc : ce qui passe, ce qui est refusé, ce qui
est journalisé.  Le daemon et le GUI partagent ces règles (validation.py)."""

import unittest

import validation
from validation import analyser_ovpn, analyser_torrc

# Configuration de fournisseur réaliste (forme courante chez les fournisseurs grand public), sans secret.
OVPN_FOURNISSEUR = """\
client
dev tun
proto tcp
remote 198.51.100.1 443
remote 198.51.100.2 443
remote-random
resolv-retry infinite
nobind
cipher AES-256-GCM
auth SHA512
verb 3
tun-mtu 1500
mssfix 0
persist-key
persist-tun
reneg-sec 0
remote-cert-tls server
auth-user-pass
auth-nocache
pull-filter ignore "route-ipv6"
pull-filter ignore "ifconfig-ipv6"
comp-lzo no
key-direction 1
setenv CLIENT_CERT 0
ignore-unknown-option block-outside-dns
block-outside-dns
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-auth>
"""


class OvpnTest(unittest.TestCase):

    def test_configuration_de_fournisseur_acceptee(self):
        self.assertEqual(analyser_ovpn(OVPN_FOURNISSEUR), ([], []))

    def test_bloc_connection_accepte(self):
        refus, _ = analyser_ovpn("client\n<connection>\nremote a 1194 udp\n"
                                 "</connection>\n")
        self.assertEqual(refus, [])

    def test_bloc_jamais_referme_refuse(self):
        refus, _ = analyser_ovpn("client\n<ca>\n-----BEGIN\n")
        self.assertTrue(refus)

    def test_bloc_inconnu_refuse(self):
        refus, _ = analyser_ovpn("<plugin>\nx\n</plugin>\n")
        self.assertTrue(refus)

    def test_numero_de_ligne_indique(self):
        refus, _ = analyser_ovpn("client\ndev tun\nplugin /x.so\n")
        self.assertTrue(refus[0].startswith("ligne 3"), refus)

    def test_casse_differente_refusee(self):
        """OpenVPN est sensible à la casse ; refuser l'inconnu reste sûr."""
        self.assertTrue(analyser_ovpn("Plugin /x.so\n")[0])

    def test_aucun_contenu_arbitraire_dans_les_messages(self):
        for piege in ("motdepasse-root", "root:$6$hash:1:0:::",
                      '"secret avec espaces" x'):
            refus, _ = analyser_ovpn(piege + "\n")
            self.assertTrue(refus)
            for m in refus:
                self.assertNotIn("motdepasse", m)
                self.assertNotIn("hash", m)
                self.assertNotIn("secret", m)


class TorrcTest(unittest.TestCase):

    def test_torrc_d_installation_accepte(self):
        texte = ("SocksPort 9050\nControlPort 9051\nCookieAuthentication 1\n"
                 "DataDirectory /var/lib/katakomba/tor_data\n"
                 "AvoidDiskWrites 1\nSafeLogging 1\nClientUseIPv6 0\n"
                 "TestSocks 1\nLongLivedPorts 1194,443\n"
                 "LearnCircuitBuildTimeout 0\nMaxCircuitDirtiness 3600\n"
                 "CircuitBuildTimeout 60\nNewCircuitPeriod 60\n"
                 "KeepalivePeriod 60\nNumEntryGuards 3\n"
                 "GuardLifetime 2 months\n# commentaire\n")
        self.assertEqual(analyser_torrc(texte), [])

    def test_insensible_a_la_casse(self):
        self.assertEqual(analyser_torrc("safelogging 1\nNUMENTRYGUARDS 3\n"), [])

    def test_execution_refusee(self):
        for ligne in ("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
                      "ServerTransportPlugin x exec /bin/sh"):
            self.assertTrue(analyser_torrc(ligne + "\n"), ligne)

    def test_ecritures_de_fichier_refusees(self):
        for ligne in ("Log notice file /etc/x", "l notice file /etc/x",
                      "PidFile /etc/x", "CookieAuthFile /etc/x",
                      "ControlPortWriteToFile /etc/x", "%include /etc/shadow",
                      "HiddenServiceDir /etc/x"):
            self.assertTrue(analyser_torrc(ligne + "\n"), ligne)

    def test_prefixes_plus_et_slash(self):
        self.assertEqual(analyser_torrc("+SocksPort 9050\n/ExcludeNodes\n"), [])
        self.assertTrue(analyser_torrc("+Log notice file /x\n"))

    def test_continuation_refusee(self):
        self.assertTrue(analyser_torrc("SafeLogging 1\\\nLog notice file /x\n"))

    def test_contenu_arbitraire_jamais_cite(self):
        refus = analyser_torrc("root:$6$hashsecret:1:0:::\n")
        self.assertTrue(refus)
        self.assertFalse(any("hashsecret" in m for m in refus))


class ReglagesConfigTest(unittest.TestCase):
    """config.json est modifiable par le groupe et par l'import : le daemon
    revalide tout avec ces fonctions, les mêmes que le GUI."""

    def test_exclusion_trop_large_vers_internet(self):
        for large in ("0.0.0.0/1", "0.0.0.0/2", "128.0.0.0/2", "8.0.0.0/8", "1.0.0.0/15"):
            net, err = validation.verifier_exclusion(large)
            self.assertEqual(net, "", large)
            self.assertIn("trop large", err, large)

    def test_exclusion_locale_sans_limite(self):
        for local in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"):
            self.assertEqual(validation.verifier_exclusion(local), (local, ""))

    def test_exclusion_publique_etroite(self):
        self.assertEqual(validation.verifier_exclusion("8.8.0.0/16"), ("8.8.0.0/16", ""))
        self.assertEqual(validation.verifier_exclusion("1.2.3.4"), ("1.2.3.4/32", ""))

    def test_domaine_sans_injection(self):
        for mauvais in ("x\nDNSStubListenerExtra=0.0.0.0", "a b", "-a.com", "a..b", "é.fr",
                        "a" * 64 + ".com"):
            self.assertEqual(validation.verifier_domaine(mauvais)[0], "", repr(mauvais))
        self.assertEqual(validation.verifier_domaine("..Corp.Example"), (".corp.example", ""))

    def test_dns_local(self):
        self.assertEqual(validation.verifier_dns("192.168.1.53"), ("192.168.1.53", ""))
        self.assertEqual(validation.verifier_dns("192.168.1.53\nDNSSEC=no")[0], "")

    def test_chemin_ovpn(self):
        self.assertTrue(validation.chemin_ovpn_sur("providers/vpn-a/a.ovpn"))
        for mauvais in ("/etc/shadow", "providers/../x/y", "providers/a/b/c.ovpn",
                        "providers/.a/b.ovpn", "providers/a/b\0.ovpn", "autre/a/b.ovpn"):
            self.assertFalse(validation.chemin_ovpn_sur(mauvais), mauvais)

    def test_interface_lan(self):
        self.assertTrue(validation.interface_lan_admissible("enp3s0"))
        for mauvais in ("lo", "tun0", "docker0", "wg0", "virbr0", "br-1a2b", "veth9",
                        "a\nb", "x" * 16, ""):
            self.assertFalse(validation.interface_lan_admissible(mauvais), repr(mauvais))


class FinDeBlocTest(unittest.TestCase):
    """OpenVPN sort d'un bloc de données sur toute ligne qui COMMENCE par la
    balise de fin, et lit ses lignes par morceaux de 255 octets (vérifié sur
    OpenVPN 2.7.0).  Ce qu'il lit ensuite comme directives doit avoir été
    contrôlé : sinon un « plugin » caché derrière passait la validation."""

    def _refus(self, texte):
        return analyser_ovpn(texte)[0]

    def test_texte_apres_la_balise_de_fin(self):
        refus = self._refus("client\n<ca>\nMIIB\n</ca>x\nplugin /tmp/x.so\n</ca>\n")
        self.assertTrue(any("texte après </ca>" in m for m in refus), refus)
        self.assertTrue(any("plugin" in m for m in refus), "directive cachée non vue")

    def test_ligne_decoupee_par_openvpn(self):
        for n in (255, 300, 510):
            refus = self._refus(f"client\n<ca>\n{'b' * n}</ca>\nplugin /tmp/x.so\n</ca>\n")
            self.assertTrue(refus, n)

    def test_retour_chariot_ne_coupe_pas_la_ligne(self):
        """splitlines() y voyait deux lignes courtes ; OpenVPN en lit une
        seule, de 260 octets, dont le second morceau est « </ca> »."""
        refus = self._refus("client\n<ca>\n" + "b" * 200 + "\r" + "c" * 54
                            + "</ca>\nplugin /tmp/x.so\n</ca>\n")
        self.assertTrue(refus)

    def test_longueur_comptee_en_octets(self):
        self.assertTrue(self._refus("client\n<ca>\n" + "é" * 128 + "\n</ca>\n"))
        self.assertFalse(self._refus("client\n<ca>\n" + "b" * 254 + "\n</ca>\n"))

    def test_fichiers_ordinaires_inchanges(self):
        self.assertEqual(analyser_ovpn(OVPN_FOURNISSEUR), ([], []))
        self.assertEqual(analyser_ovpn(OVPN_FOURNISSEUR.replace("\n", "\r\n")), ([], []))
        self.assertFalse(self._refus("client\n<ca>\nMIIB\n  </ca>  \nremote a 1\n"))

    def test_copie_sortie_du_bloc_comme_openvpn(self):
        copie = validation.preparer_copie_ovpn("<ca>\nx\n</ca>\nuser nobody\n")
        self.assertIn("# user nobody", copie)

    def test_copie_conserve_les_retours_chariot(self):
        """OpenVPN lit la copie : elle doit être découpée comme le texte
        validé, pas renormalisée."""
        texte = "client\r\nremote a 1\r\n"
        self.assertEqual(validation.preparer_copie_ovpn(texte), texte)


class PushTest(unittest.TestCase):
    """Ce que le serveur VPN pousse : le daemon décide de ce qu'il accepte."""

    PUSH = ["redirect-gateway def1", "dhcp-option DNS 10.8.0.1", "route-gateway 10.8.0.1",
            "topology subnet", "ping 10", "ifconfig 10.8.0.2 255.255.255.0"]

    def test_reglages_du_tunnel(self):
        r = validation.analyser_push(self.PUSH + ["tun-mtu 1400"])
        self.assertEqual(r["ifconfig"], ("10.8.0.2", "255.255.255.0"))
        self.assertEqual((r["topology"], r["tun_mtu"], r["dns"]), ("subnet", 1400, ["10.8.0.1"]))
        self.assertEqual(r["refus"], [])

    def test_route_hors_du_tunnel_refusee(self):
        """Un serveur malveillant apprendrait l'adresse réelle."""
        for route in ("route 192.0.2.0 255.255.255.0 net_gateway",
                      "route 192.0.2.0 255.255.255.0 remote_host",
                      "route 198.51.100.7 255.255.255.255 203.0.113.1"):
            r = validation.analyser_push(self.PUSH + [route])
            self.assertEqual(r["routes"], [], route)
            self.assertTrue(r["refus"], route)

    def test_route_dans_le_tunnel_admise(self):
        r = validation.analyser_push(self.PUSH + ["route 10.9.0.0 255.255.0.0",
                                                  "route 10.10.0.0 255.255.0.0 10.8.0.1",
                                                  "route 10.11.0.0 255.255.0.0 vpn_gateway"])
        self.assertEqual([str(n) for n in r["routes"]],
                         ["10.9.0.0/16", "10.10.0.0/16", "10.11.0.0/16"])

    def test_topologie_net30_et_ovpn(self):
        r = validation.analyser_push(["ifconfig 10.8.0.6 10.8.0.5", "route 10.8.0.1"],
                                     "client\ntun-mtu 1300\n")
        self.assertEqual((r["topology"], r["tun_mtu"]), ("net30", 1300))
        self.assertEqual([str(n) for n in r["routes"]], ["10.8.0.1/32"])

    def test_dns_nouvelle_syntaxe(self):
        r = validation.analyser_push(self.PUSH + ["dns server 0 address 10.8.0.53"])
        self.assertIn("10.8.0.53", r["dns"])

    def test_mtu_en_chiffres_non_ascii(self):
        """« ² » passe isdigit() mais int() lève : le montage du tunnel
        s'arrêtait sur une exception, poussée par le serveur."""
        for valeur in ("²", "١٤٠٠", "1４00"):
            r = validation.analyser_push(self.PUSH + [f"tun-mtu {valeur}"])
            self.assertIsNone(r["tun_mtu"], valeur)

    def test_masque_du_tunnel_trop_large(self):
        """Un tunnel en /0 rendrait toutes les exclusions « locales »."""
        for masque in ("0.0.0.0", "128.0.0.0", "254.0.0.0"):
            r = validation.analyser_push(["topology subnet", f"ifconfig 10.8.0.2 {masque}"])
            self.assertIsNone(r["ifconfig"], masque)
            self.assertTrue(any("trop large" in m for m in r["refus"]), masque)
        r = validation.analyser_push(["topology subnet", "ifconfig 10.8.0.2 255.0.0.0"])
        self.assertEqual(r["ifconfig"], ("10.8.0.2", "255.0.0.0"))

    def test_sans_ifconfig(self):
        self.assertIsNone(validation.analyser_push(["redirect-gateway def1"])["ifconfig"])


class CopieOvpnTest(unittest.TestCase):
    """OpenVPN sans droit : « user nobody » le ferait échouer au démarrage."""

    def test_directives_neutralisees_hors_des_blocs(self):
        copie = validation.preparer_copie_ovpn(
            "client\nuser nobody\ngroup nogroup\ndev tun\nmlock\nremote a 443\n"
            "<key>\nuser x\n</key>\n")
        for d in ("user nobody", "group nogroup", "dev tun", "mlock"):
            self.assertIn(f"# {d}    # katakomba", copie, d)
        self.assertIn("remote a 443\n", copie)
        self.assertIn("<key>\nuser x\n</key>", copie, "contenu d'un bloc modifié")


if __name__ == "__main__":
    unittest.main()
