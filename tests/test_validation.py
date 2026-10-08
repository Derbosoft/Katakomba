"""Listes blanches .ovpn / torrc : ce qui passe, ce qui est refusé, ce qui
est journalisé.  Le daemon et le GUI partagent ces règles (validation.py)."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
