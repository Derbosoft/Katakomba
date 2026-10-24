"""Fuzzing des analyseurs exposés à un tiers : le .ovpn (fournisseur, fichier
importé), les options poussées par le serveur VPN, le torrc, les réglages de
config.json.  Bibliothèque standard seulement, graines fixes : un échec se
rejoue à l'identique.

Le .ovpn est confronté à un MODÈLE de la lecture d'OpenVPN 2.7 (vérifié sur
le vrai binaire, voir tests_noyau/test_openvpn_lecture.py) : si validation.py
accepte un fichier, OpenVPN ne doit y lire aucune directive hors liste
blanche.  C'est ainsi qu'ont été trouvées les fins de bloc par préfixe et les
lignes découpées par morceaux de 255 octets (v3.13.0)."""

import ipaddress
import random
import unittest

import validation
from validation import (OVPN_AUTORISEES, OVPN_BLOCS, _RAISONS, _TORRC_RAISONS,
                        analyser_ovpn, analyser_push, analyser_torrc)

GRAINES = range(8)
PAR_GRAINE = 400


# ── Modèle de la lecture d'OpenVPN 2.7 (options.c) ───────────────────────────

_ESPACES_C = b" \t\n\v\f\r"     # isspace() en locale C
_TAMPON = 255                    # OPTION_LINE_SIZE - 1


def _morceaux(donnees: bytes):
    """fgets(ligne, 256) : jusqu'au « \\n » inclus, 255 octets au plus."""
    i = 0
    while i < len(donnees):
        j = donnees.find(b"\n", i)
        fin = len(donnees) if j < 0 else j + 1
        fin = min(fin, i + _TAMPON)
        yield donnees[i:fin]
        i = fin


def _jetons_openvpn(ligne: bytes) -> list:
    """parse_line() : espaces, guillemets " et ' en début de jeton seulement
    (ailleurs, ce sont des caractères ordinaires), barre oblique inverse
    (sauf entre '), commentaire # ou ; en début de jeton seulement."""
    jetons, cour, i, n = [], None, 0, len(ligne)
    while i < n:
        c = ligne[i:i + 1]
        if cour is None:
            if c in (b" ", b"\t", b"\n", b"\v", b"\f", b"\r"):
                i += 1
                continue
            if c in (b"#", b";"):
                break
            cour = b""
        if c in (b" ", b"\t", b"\n", b"\v", b"\f", b"\r"):
            jetons.append(cour)
            cour = None
        elif c in (b'"', b"'") and cour == b"":
            fin = ligne.find(c, i + 1)
            if fin < 0:
                return None                 # guillemet non fermé : erreur
            morceau = ligne[i + 1:fin]
            if c == b'"':
                morceau = morceau.replace(b"\\\\", b"\\").replace(b'\\"', b'"')
            cour += morceau
            i = fin
        elif c == b"\\" and i + 1 < n:
            cour += ligne[i + 1:i + 2]
            i += 1
        else:
            cour += c
        i += 1
    if cour is not None:
        jetons.append(cour)
    return jetons


def lecture_openvpn(texte: str):
    """Ce qu'OpenVPN fait du fichier, dans l'ordre : ("directive", nom) pour
    chaque directive lue, ("fatal", raison) s'il s'arrête sur une erreur."""
    bloc = None
    for m in _morceaux(texte.encode("utf-8", "replace")):
        if bloc is not None:
            if m.lstrip(_ESPACES_C).startswith(b"</" + bloc + b">"):
                bloc = None
            continue
        if len(m) == _TAMPON and not m.endswith(b"\n"):
            yield "fatal", "Maximum option line length"
            return
        p = _jetons_openvpn(m)
        if p is None:
            yield "fatal", "No closing quotation"
            return
        if not p:
            continue
        if len(p) == 1 and p[0][:1] == b"<" and p[0][-1:] == b">":
            tag = p[0][1:-1]
            if tag not in (b"connection", b"/connection"):
                bloc = tag
            continue
        nom = p[0][2:] if p[0].startswith(b"--") else p[0]
        if nom == b"setenv" and len(p) >= 3 and p[1] == b"opt":
            nom = p[2][2:] if p[2].startswith(b"--") else p[2]
        yield "directive", nom.decode("utf-8", "replace")
    if bloc is not None:
        yield "fatal", "Endtag missing"


def directives_vues_par_openvpn(texte: str):
    """Noms des directives qu'OpenVPN lirait, ou None s'il refuserait le
    fichier avant d'en appliquer aucune (ligne trop longue, guillemet…)."""
    noms = []
    for genre, valeur in lecture_openvpn(texte):
        if genre == "fatal":
            return None
        noms.append(valeur)
    return noms


# ── Générateurs ───────────────────────────────────────────────────────────────

_PERMISES = sorted(OVPN_AUTORISEES - {"script-security"})
_DANGEREUSES = sorted(_RAISONS)
_ESPACES = [" ", "\t", "  ", "\v", "\f", "\xa0", " ", "\x85", "\r"]


def _ligne_de_bloc(rng, bloc):
    choix = rng.random()
    if choix < 0.5:
        return "".join(rng.choice("ABCDEFabcdef0123456789+/=") for _ in range(rng.choice((4, 64, 76))))
    if choix < 0.65:
        return "b" * rng.choice((200, 250, 253, 254, 255, 256, 300, 509, 510))
    if choix < 0.75:
        return f"</{bloc}>" + rng.choice(("x", " x", "\t", "</ca>", " # z", "\r"))
    if choix < 0.85:
        return "b" * rng.randint(150, 300) + rng.choice(("\r", "\x85", "\v", "")) + \
            "c" * rng.randint(0, 120) + f"</{bloc}>"
    return rng.choice(_ESPACES) + f"</{bloc}>" + rng.choice(("", " ", "\r"))


def _directive(rng):
    nom = rng.choice(_DANGEREUSES if rng.random() < 0.3 else _PERMISES)
    if rng.random() < 0.15:
        nom = "--" + nom
    if rng.random() < 0.1:
        nom = f'"{nom}"'
    if rng.random() < 0.08:
        nom = "setenv opt " + nom
    arg = rng.choice(("", " 1", " /tmp/x.so", ' "a b"', " a#b", " x;y", " \\x"))
    return rng.choice(["", " ", "\t", "\v"]) + nom + arg


def ovpn_aleatoire(rng) -> str:
    lignes = ["client"]
    for _ in range(rng.randint(1, 14)):
        tirage = rng.random()
        if tirage < 0.45:
            lignes.append(_directive(rng))
        elif tirage < 0.55:
            lignes.append(rng.choice(("# commentaire", "; plugin /x.so", "", "   ")))
        elif tirage < 0.65:
            lignes += ["<connection>", _directive(rng), "</connection>"]
        else:
            bloc = rng.choice(sorted(OVPN_BLOCS))
            lignes.append(f"<{bloc}>")
            lignes += [_ligne_de_bloc(rng, bloc) for _ in range(rng.randint(0, 4))]
            if rng.random() < 0.9:
                lignes.append(f"</{bloc}>")
    sep = rng.choice(("\n", "\n", "\r\n"))
    return sep.join(lignes) + sep


class OvpnFuzzTest(unittest.TestCase):

    def test_rien_n_echappe_a_la_validation(self):
        vus = acceptes = 0
        for graine in GRAINES:
            rng = random.Random(graine)
            for k in range(PAR_GRAINE):
                texte = ovpn_aleatoire(rng)
                refus, avert = analyser_ovpn(texte)
                self.assertIsInstance(refus, list)
                self.assertTrue(all(isinstance(m, str) for m in refus + avert))
                noms = directives_vues_par_openvpn(texte)
                if noms is None:
                    continue
                vus += 1
                hors_liste = [n for n in noms if n not in OVPN_AUTORISEES]
                if not refus:
                    acceptes += 1
                    self.assertEqual(hors_liste, [], f"graine {graine}, fichier {k} :\n{texte!r}")
        # Le générateur doit produire des cas des deux sortes, sinon il ne
        # prouve rien.
        self.assertGreater(vus, 500)
        self.assertGreater(acceptes, 100)

    def test_le_modele_reconnait_les_failles_corrigees(self):
        """Le modèle lit bien comme OpenVPN 2.7 : il voit la directive cachée
        des trois formes corrigées en v3.13.0."""
        for texte in ("client\n<ca>\n</ca>x\nplugin /x.so\n",
                      "client\n<ca>\n" + "b" * 255 + "</ca>\nplugin /x.so\n",
                      "client\n<ca>\n" + "b" * 200 + "\r" + "c" * 54 + "</ca>\nplugin /x.so\n"):
            self.assertIn("plugin", directives_vues_par_openvpn(texte))
            self.assertTrue(analyser_ovpn(texte)[0])

    def test_copie_lue_comme_le_texte_valide(self):
        """OpenVPN lit la copie, pas l'original : mêmes directives."""
        rng = random.Random(99)
        for _ in range(500):
            texte = ovpn_aleatoire(rng)
            if analyser_ovpn(texte)[0]:
                continue
            avant = directives_vues_par_openvpn(texte)
            apres = directives_vues_par_openvpn(validation.preparer_copie_ovpn(texte))
            if avant is None:
                continue
            neutralisees = set(validation.OVPN_GEREES_PAR_LE_DAEMON)
            self.assertEqual([n for n in avant if n not in neutralisees], apres)


# ── Options poussées par le serveur ──────────────────────────────────────────

_NOMBRES = ["0", "1", "576", "1500", "65535", "65536", "-1", "²", "١٤٠٠", "1e3", "0x10", ""]
_ADRESSES = ["10.8.0.2", "10.8.0.1", "0.0.0.0", "255.255.255.255", "255.255.255.0",
             "128.0.0.0", "1.2.3.4", "::1", "10.8.0", "999.1.1.1", "vpn_gateway",
             "net_gateway", "remote_host", "default", "10.8.0.2:53", "[::1]:53"]


def push_aleatoire(rng) -> list:
    options = []
    for _ in range(rng.randint(0, 12)):
        nom = rng.choice(("ifconfig", "topology", "tun-mtu", "route", "route-gateway",
                          "dhcp-option", "dns", "redirect-gateway", "ping", "", "route"))
        args = [rng.choice(_ADRESSES + _NOMBRES + ["subnet", "net30", "p2p", "DNS",
                                                    "server", "address"])
                for _ in range(rng.randint(0, 4))]
        options.append(" ".join([nom] + args))
    return options


class PushFuzzTest(unittest.TestCase):

    def test_jamais_d_exception_et_resultat_borne(self):
        for graine in GRAINES:
            rng = random.Random(1000 + graine)
            for _ in range(PAR_GRAINE):
                options = push_aleatoire(rng)
                r = analyser_push(options, rng.choice(("", "tun-mtu ²\n", "topology subnet\n")))
                self.assertIn(r["topology"], ("net30", "p2p", "subnet"))
                self.assertTrue(r["tun_mtu"] is None or 576 <= r["tun_mtu"] <= 65535, options)
                if r["ifconfig"]:
                    for a in r["ifconfig"]:
                        ipaddress.IPv4Address(a)
                    if r["topology"] == "subnet":
                        net = ipaddress.IPv4Network("/".join(r["ifconfig"]), strict=False)
                        self.assertGreaterEqual(net.prefixlen, validation.TUNNEL_PREFIXE_MIN)
                for net in r["routes"]:
                    self.assertIsInstance(net, ipaddress.IPv4Network)
                    self.assertGreater(net.prefixlen, 0)
                for d in r["dns"]:
                    ipaddress.IPv4Address(d)
                self.assertTrue(all(isinstance(m, str) for m in r["refus"]))

    def test_aucune_route_hors_du_tunnel(self):
        """net_gateway, remote_host ou une passerelle étrangère : jamais."""
        rng = random.Random(7)
        for _ in range(2000):
            options = push_aleatoire(rng)
            passerelle = rng.choice(("net_gateway", "remote_host", "203.0.113.9"))
            options.append(f"route 198.51.100.0 255.255.255.0 {passerelle}")
            r = analyser_push(options)
            gw = [o.split()[1] for o in options
                  if o.startswith("route-gateway ") and len(o.split()) > 1]
            if passerelle == "203.0.113.9" and "203.0.113.9" in gw:
                continue            # passerelle annoncée : le daemon route par dev tun
            if r["ifconfig"] and r["topology"] == "subnet":
                net = ipaddress.IPv4Network("/".join(r["ifconfig"]), strict=False)
                if ipaddress.IPv4Address("203.0.113.9") in net:
                    continue
            self.assertNotIn(ipaddress.IPv4Network("198.51.100.0/24"), r["routes"], options)


# ── torrc et réglages ────────────────────────────────────────────────────────

class TorrcFuzzTest(unittest.TestCase):

    def test_option_dangereuse_toujours_refusee(self):
        rng = random.Random(3)
        sures = sorted(validation.TORRC_AUTORISEES)
        for _ in range(3000):
            lignes = [rng.choice(sures) + " 1" for _ in range(rng.randint(0, 5))]
            cle = rng.choice(sorted(_TORRC_RAISONS))
            cle = "".join(c.upper() if rng.random() < 0.5 else c for c in cle)
            cle = rng.choice(("", "+", "/")) + cle
            lignes.insert(rng.randint(0, len(lignes)),
                          rng.choice(("", " ", "\t")) + cle + rng.choice((" x", "\tx", "")))
            self.assertTrue(analyser_torrc("\n".join(lignes)), lignes)

    def test_jamais_d_exception(self):
        rng = random.Random(4)
        alphabet = "SocksPort Log #\\\n\r\t\x00é+/ 9050"
        for _ in range(3000):
            texte = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
            self.assertIsInstance(analyser_torrc(texte), list)


class ReglagesFuzzTest(unittest.TestCase):

    def test_jamais_d_exception(self):
        rng = random.Random(5)
        alphabet = "0123456789./:abcdefx-\n\x00 \t%[]é"
        for _ in range(4000):
            saisie = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            for f in (validation.verifier_exclusion, validation.verifier_dns,
                      validation.verifier_domaine):
                valeur, erreur = f(saisie)
                self.assertIsInstance(valeur, str)
                self.assertIsInstance(erreur, str)
            self.assertIsInstance(validation.composant_sur(saisie), bool)
            self.assertIsInstance(validation.chemin_ovpn_sur(saisie), bool)
            self.assertIsInstance(validation.interface_lan_admissible(saisie), bool)

    def test_valeurs_admises_bien_formees(self):
        rng = random.Random(6)
        alphabet = "0123456789./:abcdef-\n "
        for _ in range(4000):
            saisie = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 25)))
            valeur, erreur = validation.verifier_exclusion(saisie)
            if valeur:
                net = ipaddress.ip_network(valeur)
                self.assertEqual(net.version, 4)
                self.assertTrue(net.prefixlen >= validation.PREFIXE_PUBLIC_MIN
                                or validation.exclusion_locale(net), saisie)
            valeur, _ = validation.verifier_domaine(saisie)
            if valeur:
                self.assertNotIn("\n", valeur)
                self.assertNotIn(" ", valeur)
            if validation.composant_sur(saisie):
                self.assertNotIn("/", saisie)
                self.assertNotIn(saisie, (".", ".."))


if __name__ == "__main__":
    unittest.main()
