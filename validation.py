"""
Validation des fichiers fournis par le groupe katakomba : .ovpn, .conf
WireGuard et torrc.

Le daemon tourne en root et passe ces fichiers à OpenVPN, à wg et à Tor, eux
aussi en root.  Or le groupe katakomba peut les écrire (c'est ce qui permet
au GUI de tourner sans privilège).  Sans contrôle, écrire un fichier de
configuration suffirait à faire exécuter du code en root :

  .ovpn  « plugin /x.so » charge une bibliothèque — vérifié sur OpenVPN
         2.7.0, même avec --script-security 1 : le constructeur de la
         bibliothèque s'exécute avant toute connexion.
  .conf  wg-quick exécute PostUp/PreDown ; le daemon n'emploie pas wg-quick
         et réécrit lui-même ce qu'il remet à wg (conf_wg_noyau).
  torrc  « ClientTransportPlugin x exec /chemin » lance un programme.

On procède donc par LISTE BLANCHE : pour un .ovpn ou un torrc, une directive
absente de la liste fait refuser le fichier entier (une liste noire serait à
refaire à chaque version d'OpenVPN ou de Tor : la 2.7 a ajouté dns-updown,
qui exécute un script) ; pour un .conf, seules les valeurs connues et
contrôlées sont reprises.

Les messages produits sont sûrs à journaliser : ils ne recopient jamais le
contenu d'une ligne, seulement un nom pris dans un vocabulaire fixe.  Sans
cette précaution, un fichier pointant sur /etc/shadow ferait recopier ses
lignes dans le journal, lisible par le groupe adm — et une clé privée
WireGuard mal formée y finirait.
"""

import ipaddress
import re
import shlex

from i18n import N_, _

# ── OpenVPN ───────────────────────────────────────────────────────────────────

# Directives de client sans effet de bord hors du tunnel : ni exécution, ni
# chargement de bibliothèque, ni écriture de fichier.
OVPN_AUTORISEES = frozenset("""
    client pull tls-client dev dev-type proto proto-force remote remote-random
    remote-random-hostname port rport lport nobind bind local float
    resolv-retry connect-retry connect-retry-max connect-timeout
    server-poll-timeout persist-key persist-tun persist-remote-ip
    persist-local-ip
    ca capath cert key pkcs12 extra-certs crl-verify dh tls-auth tls-crypt
    tls-crypt-v2 key-direction secret askpass pkcs11-id verify-hash
    peer-fingerprint
    auth cipher data-ciphers data-ciphers-fallback ncp-ciphers ncp-disable
    keysize tls-cipher tls-ciphersuites tls-groups tls-cert-profile
    tls-version-min tls-version-max tls-timeout tls-exit hand-window
    tran-window reneg-sec reneg-bytes reneg-pkts replay-window
    mute-replay-warnings remote-cert-tls remote-cert-ku remote-cert-eku
    ns-cert-type verify-x509-name x509-track
    auth-user-pass auth-nocache auth-retry auth-token auth-token-user
    static-challenge
    comp-lzo compress allow-compression comp-noadapt
    tun-mtu tun-mtu-extra tun-mtu-max link-mtu mssfix fragment mtu-disc
    sndbuf rcvbuf txqueuelen fast-io tcp-nodelay tcp-queue-limit mark
    bind-dev
    ping ping-restart ping-exit ping-timer-rem keepalive inactive
    explicit-exit-notify session-timeout
    verb mute echo setenv setenv-safe ignore-unknown-option
    redirect-gateway redirect-private route route-ipv6 route-gateway
    route-ipv6-gateway route-metric route-delay route-nopull route-noexec
    route-table max-routes allow-pull-fqdn allow-recursive-routing
    pull-filter dhcp-option dns block-ipv6 ifconfig ifconfig-ipv6
    ifconfig-nowarn ifconfig-noexec topology tun-ipv6 lladdr
    push-peer-info remap-usr1 disable-dco disable-occ key-method nice mlock
    user group socks-proxy socks-proxy-retry
    block-outside-dns register-dns dhcp-release dhcp-renew dhcp-pre-release
    ip-win32 route-method win-sys tap-sleep windows-driver
""".split())

# Directives qui exécutent un programme externe.
OVPN_SCRIPTS = frozenset("""
    up down up-restart down-pre route-up route-pre-down ipchange
    client-connect client-disconnect learn-address auth-user-pass-verify
    tls-verify dns-updown iproute
""".split())

# Refus motivés : la raison est affichée telle quelle.
_RAISONS = {
    "plugin":            N_("charge une bibliothèque (code exécuté en root)"),
    "pkcs11-providers":  N_("charge une bibliothèque (code exécuté en root)"),
    "providers":         N_("charge un module OpenSSL (code exécuté en root)"),
    "engine":            N_("charge un moteur OpenSSL (code exécuté en root)"),
    "config":            N_("inclut un autre fichier, non contrôlé"),
    "cd":                N_("change le répertoire de travail d'OpenVPN"),
    "chroot":            N_("change la racine d'OpenVPN"),
    "log":               N_("écrit un fichier arbitraire en root"),
    "log-append":        N_("écrit un fichier arbitraire en root"),
    "status":            N_("écrit un fichier arbitraire en root"),
    "writepid":          N_("écrit un fichier arbitraire en root"),
    "tmp-dir":           N_("déplace les fichiers temporaires d'OpenVPN"),
    "replay-persist":    N_("écrit un fichier arbitraire en root"),
    "syslog":            N_("détourne la sortie que le daemon analyse"),
    "daemon":            N_("détache OpenVPN du daemon"),
    "management":        N_("ouvre une interface de pilotage d'OpenVPN"),
    "http-proxy":        N_("incompatible avec le passage par Tor (--socks-proxy)"),
}
for _d in OVPN_SCRIPTS:
    _RAISONS[_d] = N_("exécute un programme externe")

# Vocabulaire connu d'OpenVPN 2.7 (openvpn --help).  Sert UNIQUEMENT à décider
# si un nom de directive refusée peut être cité dans le journal.
_OVPN_CONNUES = OVPN_AUTORISEES | frozenset(_RAISONS) | frozenset("""
    auth-gen-token auth-user-pass-optional bcast-buffers ccd-exclusive
    client-config-dir client-nat client-to-client connect-freq
    connect-freq-initial dev-node disable duplicate-cn genkey gremlin
    hash-size help http-proxy-option ifconfig-ipv6-pool ifconfig-ipv6-push
    ifconfig-pool ifconfig-pool-persist ifconfig-push iroute iroute-ipv6
    keying-material-exporter machine-readable-output management-client
    management-client-auth management-client-group management-client-user
    management-forget-disconnect management-hold management-log-cache
    management-query-passwords management-query-proxy management-query-remote
    management-signal management-up-down max-clients max-routes-per-client
    mktun mode mtu-test multihome override-username passtos
    pkcs11-cert-private pkcs11-id-management pkcs11-pin-cache
    pkcs11-private-mode pkcs11-protected-authentication port-share push
    push-remove push-reset rmtun script-security server server-bridge
    server-ipv6 shaper show-ciphers show-digests show-engines show-gateway
    show-pkcs11-ids show-tls single-session stale-routes-check status-version
    suppress-timestamps test-crypto tls-crypt-v2-max-age tls-crypt-v2-verify
    tls-server up-delay username-as-common-name verify-client-cert version
    vlan-accept vlan-pvid vlan-tagging x509-username-field
""".split())

# Blocs <tag>…</tag> dont le contenu est une donnée (certificat, clé).
OVPN_BLOCS = frozenset("""
    ca cert key extra-certs tls-auth tls-crypt tls-crypt-v2 pkcs12 secret dh
    crl-verify peer-fingerprint auth-user-pass
""".split())


def _nom_sur(nom: str, vocabulaire) -> str:
    return f"« {nom} »" if nom in vocabulaire else _("inconnue")


def _jetons(ligne: str):
    """Découpe une ligne comme OpenVPN : espaces, guillemets, commentaires
    # et ; en début de jeton.  Repli sur un simple split si les guillemets
    sont déséquilibrés — OpenVPN refusera la ligne de toute façon."""
    lex = shlex.shlex(ligne, posix=True)
    lex.whitespace_split = True
    lex.commenters = "#;"
    try:
        return list(lex)
    except ValueError:
        return ligne.split()


# OpenVPN lit son fichier ligne à ligne par morceaux de 255 octets (tampon de
# 256), et clôt un bloc sur toute ligne — tout morceau — qui COMMENCE par la
# balise de fin, une fois ses espaces de tête retirées (vérifié sur 2.7.0).
OVPN_BLOC_LIGNE_MAX = 254


def lignes_ovpn(texte: str) -> list:
    """Les lignes telles qu'OpenVPN les voit : coupées sur « \n » seulement.
    splitlines() coupe aussi sur « \r », « \v », « \x85 »… : une donnée
    de bloc y paraîtrait en deux lignes courtes, quand OpenVPN en lit une
    seule, découpée ailleurs."""
    return texte.split("\n")


def fin_de_bloc(ligne: str, bloc: str) -> bool:
    """La ligne (déjà débarrassée de ses espaces) clôt le bloc pour OpenVPN."""
    return ligne.startswith(f"</{bloc}>")


def analyser_ovpn(texte: str):
    """Renvoie (refus, avertissements) : deux listes de messages.

    Un seul refus suffit à écarter le fichier.  Les avertissements ne
    bloquent rien."""
    refus, avert = [], []
    bloc = None
    secu_signalee = False
    for n, brute in enumerate(lignes_ovpn(texte), 1):
        ligne = brute.strip()
        if bloc is not None:
            # Texte après la balise de fin, ou ligne assez longue pour
            # qu'OpenVPN la lise en morceaux dont l'un commencerait par la
            # balise : OpenVPN sortirait du bloc là où ce contrôle y resterait,
            # et lirait la suite comme des directives jamais contrôlées.
            if fin_de_bloc(ligne, bloc):
                if ligne != f"</{bloc}>":
                    refus.append(_("ligne {n} : texte après </{bloc}>").format(
                        n=n, bloc=bloc))
                bloc = None
            elif len(brute.encode("utf-8", "replace")) > OVPN_BLOC_LIGNE_MAX:
                refus.append(_("ligne {n} : ligne de plus de {max} octets dans "
                               "<{bloc}>").format(n=n, max=OVPN_BLOC_LIGNE_MAX,
                                                  bloc=bloc))
            continue
        if not ligne or ligne[0] in "#;":
            continue
        if ligne.startswith("<") and ligne.endswith(">"):
            tag = ligne[1:-1]
            if tag in ("connection", "/connection"):
                continue      # bloc de directives : contrôlées ligne à ligne
            if tag in OVPN_BLOCS:
                bloc = tag
                continue
            nom_bloc = tag.lstrip("/")
            refus.append((_("ligne {n} : bloc <{bloc}> non autorisé")
                          if nom_bloc in _OVPN_CONNUES else
                          _("ligne {n} : bloc non autorisé")).format(n=n, bloc=nom_bloc))
            continue
        p = _jetons(ligne)
        if not p:
            continue
        # « --plugin » est admis dans un fichier : OpenVPN retire les tirets.
        nom = p[0][2:] if p[0].startswith("--") else p[0]
        # « setenv opt X … » fait traiter X comme une directive à part entière.
        if nom == "setenv" and len(p) >= 3 and p[1] == "opt":
            nom = p[2][2:] if p[2].startswith("--") else p[2]
        if nom == "script-security":
            # Sans effet : le daemon impose le niveau 1 APRÈS --config.
            if not secu_signalee:
                secu_signalee = True
                try:
                    niveau = int(p[1]) if len(p) > 1 else -1
                except ValueError:
                    niveau = -1
                if niveau >= 2:
                    avert.append(_(
                        "Le .ovpn déclare « script-security {niveau} » — sans "
                        "effet, le daemon impose le niveau 1 après --config. "
                        "Supprimez cette ligne : elle n'a aucune utilité ici "
                        "et tenterait d'autoriser l'exécution de code par le "
                        "daemon, en root.").format(niveau=niveau))
            continue
        if nom in OVPN_AUTORISEES:
            continue
        if nom in _RAISONS:
            refus.append(_("ligne {n} : directive « {nom} » refusée — {raison}").format(
                n=n, nom=nom, raison=_(_RAISONS[nom])))
        else:
            refus.append(_("ligne {n} : directive {nom} non autorisée").format(
                n=n, nom=_nom_sur(nom, _OVPN_CONNUES)))
    if bloc is not None:
        refus.append(_("bloc <{bloc}> jamais refermé").format(bloc=bloc))
    return refus, avert


# ── Tor ───────────────────────────────────────────────────────────────────────

# Clés comparées en minuscules : Tor est insensible à la casse.  Pas de
# préfixe accepté — Tor connaît des abréviations (« l » vaut « Log »), que
# seule une comparaison exacte écarte.
_TORRC_LISTE = """
    SocksPort ControlPort CookieAuthentication DataDirectory
    AvoidDiskWrites SafeLogging ClientUseIPv6 ClientUseIPv4 TestSocks
    ConnectionPadding ReducedConnectionPadding CircuitPadding
    ReducedCircuitPadding LongLivedPorts LearnCircuitBuildTimeout
    MaxCircuitDirtiness CircuitBuildTimeout NewCircuitPeriod KeepalivePeriod
    CircuitStreamTimeout CircuitsAvailableTimeout MaxClientCircuitsPending
    NumEntryGuards NumPrimaryGuards NumDirectoryGuards GuardLifetime
    UseEntryGuards EntryNodes ExitNodes MiddleNodes ExcludeNodes
    ExcludeExitNodes StrictNodes NodeFamily EnforceDistinctSubnets
    GeoIPExcludeUnknown ClientPreferIPv6ORPort ClientPreferIPv6DirPort
    FascistFirewall FirewallPorts ReachableAddresses ReachableORAddresses
    ReachableDirAddresses UseMicrodescriptors UseBridges Bridge
    SafeSocks WarnUnsafeSocks WarnPlaintextPorts RejectPlaintextPorts
    SocksTimeout ConnLimit ConstrainedSockets ConstrainedSockSize
    HardwareAccel NumCPUs Sandbox ClientOnly VanguardsLiteEnabled
    ConfluxEnabled ConfluxClientUX DormantClientTimeout
    DormantTimeoutDisabledByIdleStreams DormantOnFirstStartup
    DormantCanceledByStartup FetchDirInfoEarly FetchDirInfoExtraEarly
    PathsNeededToBuildCircuits BandwidthRate BandwidthBurst
"""
TORRC_AUTORISEES = frozenset(k.lower() for k in _TORRC_LISTE.split())

_TORRC_RAISONS = {
    "clienttransportplugin": N_("lance un programme externe (en root)"),
    "servertransportplugin": N_("lance un programme externe (en root)"),
    "%include":              N_("inclut un autre fichier, non contrôlé"),
    "log":                   N_("écrit un fichier arbitraire"),
    "l":                     N_("abréviation de Log : écrit un fichier arbitraire"),
    "pidfile":               N_("écrit un fichier arbitraire"),
    "cookieauthfile":        N_("écrit un fichier arbitraire"),
    "controlportwritetofile": N_("écrit un fichier arbitraire"),
    "controlsocket":         N_("ouvre un socket de pilotage non prévu"),
    "hashedcontrolpassword": N_("ouvre le pilotage de Tor par mot de passe"),
    "user":                  N_("imposé par le daemon"),
    "rundaemon":             N_("détacherait Tor du daemon"),
    "runasdaemon":           N_("détacherait Tor du daemon"),
    "cachedirectory":        N_("déplace les données de Tor"),
    "keydirectory":          N_("déplace les données de Tor"),
    "hiddenservicedir":      N_("crée un service onion non prévu"),
    "orport":                N_("ferait de la machine un relais Tor"),
    "dirport":               N_("ferait de la machine un relais Tor"),
}


def analyser_torrc(texte: str):
    """Liste des refus (vide = torrc acceptable)."""
    refus = []
    for n, brute in enumerate(texte.splitlines(), 1):
        ligne = brute.strip()
        if not ligne or ligne.startswith("#"):
            continue
        if ligne.endswith("\\"):
            # Tor joint la ligne suivante : ce qui serait contrôlé ici ne
            # serait plus ce que Tor lit.  Rien dans le GUI n'en produit.
            refus.append(_("ligne {n} : continuation de ligne (\\) non supportée").format(n=n))
            continue
        cle = ligne.split(None, 1)[0]
        # « +Clé » et « /Clé » : ajout à une liste / remise à zéro, même clé.
        cle = cle.lstrip("+/").lower()
        if cle in TORRC_AUTORISEES:
            continue
        if cle in _TORRC_RAISONS:
            refus.append(_("ligne {n} : option « {cle} » refusée — {raison}").format(
                n=n, cle=cle, raison=_(_TORRC_RAISONS[cle])))
        else:
            refus.append(_("ligne {n} : option inconnue ou non autorisée").format(n=n))
    return refus


# ── Réglages de config.json ───────────────────────────────────────────────────
#
# config.json est inscriptible par le groupe katakomba, donc par tout
# programme lancé sous un compte membre, et il est remplacé par l'import
# d'une sauvegarde.  Le daemon, en root, ne s'en remet donc pas aux contrôles
# du GUI : chaque valeur qu'il utilise passe par les fonctions ci-dessous,
# les mêmes que celles du GUI et de l'import.

# Plages qui ne mènent pas à Internet : les exclure du tunnel ne fait rien
# sortir à découvert.  100.64.0.0/10 : espace partagé (CGNAT, Tailscale).
PLAGES_LOCALES = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "100.64.0.0/10"))
# Une exclusion vers Internet ne couvre jamais plus qu'un /16 (65 536
# adresses).  Sans limite, quatre /2 — plus précis que les routes du tunnel —
# faisaient sortir tout Internet hors du tunnel, avec l'adresse réelle, et le
# kill switch les laissait passer puisqu'il autorise les exclusions.
PREFIXE_PUBLIC_MIN = 16


def verifier_exclusion(saisie):
    """(réseau normalisé, erreur) ; erreur vide si l'exclusion est admise.

    IPv4 seulement : l'exclusion repose sur « --route », une option IPv4 ;
    une entrée IPv6 serait acceptée puis ignorée par OpenVPN, en laissant
    croire que le réseau est exclu du tunnel."""
    saisie = str(saisie).strip()
    if not saisie:
        return "", ""
    try:
        net = ipaddress.ip_network(saisie, strict=False)
    except ValueError:
        return "", _("« {valeur} » n'est pas une adresse ou un réseau "
                     "valide.").format(valeur=saisie)
    if net.version != 4:
        return "", _("« {valeur} » est une adresse IPv6 : l'exclusion du tunnel "
                     "ne gère que l'IPv4.").format(valeur=saisie)
    if net.prefixlen < PREFIXE_PUBLIC_MIN and not exclusion_locale(net):
        return "", _("« {valeur} » est trop large : vers Internet, une exclusion "
                     "ne peut pas dépasser /{min}. Ce trafic sortirait avec votre "
                     "adresse réelle.").format(valeur=net, min=PREFIXE_PUBLIC_MIN)
    return str(net), ""


def exclusion_locale(net) -> bool:
    """Réseau entièrement contenu dans une plage qui ne mène pas à Internet."""
    net = ipaddress.ip_network(net, strict=False)
    return net.version == 4 and any(net.subnet_of(p) for p in PLAGES_LOCALES)


def verifier_dns(saisie):
    """(adresse normalisée, erreur) pour le serveur DNS local."""
    saisie = str(saisie).strip()
    if not saisie:
        return "", ""
    try:
        return str(ipaddress.ip_address(saisie)), ""
    except ValueError:
        return "", _("« {valeur} » n'est pas une adresse IP.").format(valeur=saisie)


# Étiquettes de 1 à 63 caractères, lettres, chiffres et tirets intérieurs.
# Rien d'autre : la valeur est écrite telle quelle dans un fichier de
# configuration de systemd-resolved, où un retour à la ligne ajouterait
# n'importe quel réglage.
_DOMAINE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def verifier_domaine(saisie):
    """(« .domaine » normalisé, erreur) pour le split DNS."""
    brut = str(saisie).strip()
    nom = brut.lower().lstrip(".")
    if not nom:
        return "", ""
    if len(nom) > 253 or not _DOMAINE.fullmatch(nom):
        return "", _("« {valeur} » n'est pas un nom de domaine valide.").format(
            valeur=brut)
    return "." + nom, ""


def composant_sur(c: str) -> bool:
    """Composant de chemin simple : ni remontée, ni séparateur, ni fichier
    caché."""
    return bool(c) and c not in (".", "..") and not c.startswith(".") \
        and not any(x in c for x in ("/", "\\", "\0"))


def chemin_fournisseur_sur(chemin) -> bool:
    """« providers/<fournisseur>/<fichier> », relatif, sans détour.

    Tout autre chemin ferait lire au daemon, en root, un fichier arbitraire
    de la machine."""
    parts = str(chemin).split("/")
    return (len(parts) == 3 and parts[0] == "providers"
            and all(map(composant_sur, parts[1:])))


_INTERFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
# Interfaces que le partage LAN ne doit jamais prendre : il vide leurs
# adresses.  « lo » couperait la machine de Tor (127.0.0.1:9050).
INTERFACES_EXCLUES = ("tun", "virbr", "docker", "wg", "veth", "br-")


def interface_lan_admissible(nom) -> bool:
    """Nom d'interface valide, ni boucle locale ni interface virtuelle.
    (L'interface de sortie est refusée à part : elle dépend de la route.)"""
    nom = str(nom)
    return (bool(_INTERFACE.fullmatch(nom)) and nom != "lo"
            and not nom.startswith(INTERFACES_EXCLUES))


# ── OpenVPN sans privilège (v3.9.0) ───────────────────────────────────────────
#
# OpenVPN tourne sous un utilisateur dédié, sans aucun droit, sur une
# interface tunnel créée par le daemon (--ifconfig-noexec --route-noexec).
# C'est le daemon qui pose l'adresse et les routes, d'après ce que le serveur
# a poussé : il décide donc de ce qu'il accepte.

# Directives neutralisées dans la copie du .ovpn : elles exigeraient des
# droits qu'OpenVPN n'a plus (changer d'utilisateur, verrouiller la mémoire,
# régler l'interface), ou désignent l'interface, que le daemon impose.  Les
# fichiers des fournisseurs pour Linux contiennent souvent « user nobody » :
# sans root, OpenVPN échouerait au démarrage.
OVPN_GEREES_PAR_LE_DAEMON = frozenset("""
    user group dev dev-type dev-node lladdr mark bind-dev txqueuelen mlock
    nice persist-tun tun-ipv6
""".split())


def preparer_copie_ovpn(texte: str) -> str:
    """Copie d'un .ovpn déjà validé, ces directives mises en commentaire.
    Le contenu des blocs de données (<ca>, <key>…) n'est jamais touché."""
    sortie, bloc = [], None
    for brute in lignes_ovpn(texte.rstrip("\n")):
        ligne = brute.strip()
        if bloc is not None:
            if fin_de_bloc(ligne, bloc):
                bloc = None
            sortie.append(brute)
            continue
        if ligne.startswith("<") and ligne.endswith(">") and ligne[1:-1] in OVPN_BLOCS:
            bloc = ligne[1:-1]
            sortie.append(brute)
            continue
        p = _jetons(ligne) if ligne and ligne[0] not in "#;<" else []
        nom = (p[0][2:] if p[0].startswith("--") else p[0]) if p else ""
        if nom in OVPN_GEREES_PAR_LE_DAEMON:
            sortie.append(f"# {ligne}    # katakomba : géré par le daemon")
        else:
            sortie.append(brute)
    return "\n".join(sortie) + "\n"


TUNNEL_PREFIXE_MIN = 8


def _ipv4(valeur):
    try:
        return ipaddress.IPv4Address(valeur)
    except ValueError:
        return None


def analyser_push(options, texte_ovpn: str = "") -> dict:
    """Réglages du tunnel d'après les options poussées par le serveur
    (PUSH_REPLY) et le .ovpn.  Fonction pure : le daemon applique le résultat.

    Renvoie un dict : ifconfig (local, masque ou pair) ou None, topology,
    tun_mtu (ou None), routes (réseaux IPv4 à router DANS le tunnel), dns
    (adresses), refus (messages, à journaliser).

    Une route poussée n'est acceptée que si elle passe par le tunnel :
    « net_gateway », « remote_host » ou une passerelle hors du tunnel
    feraient sortir ce trafic par la connexion normale, et un serveur
    malveillant apprendrait l'adresse réelle.  « redirect-gateway » est
    ignoré : le daemon route toujours tout le trafic dans le tunnel."""
    r = {"ifconfig": None, "topology": "net30", "tun_mtu": None,
         "routes": [], "dns": [], "refus": []}
    route_gateway = None
    poussees = []
    # Le .ovpn d'abord, le serveur ensuite : ce qui est poussé l'emporte.
    for brute in texte_ovpn.splitlines():
        p = _jetons(brute.strip()) if brute.strip()[:1] not in ("#", ";", "<", "") else []
        if p and p[0] in ("topology", "tun-mtu"):
            poussees.append(p)
    poussees += [_jetons(o.strip()) for o in options if o.strip()]

    routes = []
    for p in poussees:
        if not p:
            continue
        nom, args = p[0], p[1:]
        if nom == "topology" and args and args[0] in ("net30", "p2p", "subnet"):
            r["topology"] = args[0]
        # isascii : « ² » ou « ١٢ » passent isdigit(), et int() lèverait.
        elif nom == "tun-mtu" and args and args[0].isascii() and args[0].isdigit() \
                and 576 <= int(args[0]) <= 65535:
            r["tun_mtu"] = int(args[0])
        elif nom == "ifconfig" and len(args) >= 2 and _ipv4(args[0]) and _ipv4(args[1]):
            r["ifconfig"] = (args[0], args[1])
        elif nom == "route-gateway" and args and _ipv4(args[0]):
            route_gateway = args[0]
        elif nom == "route" and args:
            routes.append(args)
        elif nom == "dhcp-option" and len(args) >= 2 and args[0].upper() == "DNS" \
                and _ipv4(args[1]):
            r["dns"].append(args[1])
        elif nom == "dns" and len(args) >= 4 and args[0] == "server" \
                and args[2] == "address":
            ip = args[3].split(":")[0] if args[3].count(":") == 1 else args[3]
            if _ipv4(ip):
                r["dns"].append(ip)

    # Réseau du tunnel : ce qui y est joignable sans sortir de l'interface.
    tunnel = None
    if r["ifconfig"]:
        local, second = r["ifconfig"]
        if r["topology"] == "subnet":
            try:
                tunnel = ipaddress.IPv4Network(f"{local}/{second}", strict=False)
            except ValueError:
                r["refus"].append(f"masque du tunnel invalide : {second}")
                r["ifconfig"] = None
            else:
                # Posé sur l'interface, le réseau du tunnel devient une route
                # « directement connectée » : en /0, toutes les exclusions et
                # routes poussées passeraient pour locales, donc ignorées.
                if tunnel.prefixlen < TUNNEL_PREFIXE_MIN:
                    r["refus"].append(f"masque du tunnel trop large : {second} "
                                      f"(/{tunnel.prefixlen}, au plus /{TUNNEL_PREFIXE_MIN})")
                    r["ifconfig"], tunnel = None, None
        else:
            tunnel = ipaddress.IPv4Network(f"{second}/32")
    for args in routes:
        try:
            masque = args[1] if len(args) > 1 and args[1] != "default" else "255.255.255.255"
            net = ipaddress.IPv4Network(f"{args[0]}/{masque}", strict=False)
        except ValueError:
            r["refus"].append(f"route poussée illisible : {' '.join(args)}")
            continue
        passerelle = args[2] if len(args) > 2 else "vpn_gateway"
        dans_le_tunnel = passerelle in ("vpn_gateway", "default") or (
            _ipv4(passerelle) is not None and (
                passerelle == route_gateway
                or (tunnel is not None and _ipv4(passerelle) in tunnel)))
        if not dans_le_tunnel:
            r["refus"].append(f"route poussée refusée : {net} via {passerelle} — "
                              "elle sortirait hors du tunnel")
            continue
        if net.prefixlen == 0:
            continue            # route par défaut : le daemon la pose lui-même
        if net not in r["routes"]:
            r["routes"].append(net)
    return r


# ── WireGuard ─────────────────────────────────────────────────────────────────
#
# Le daemon lit, en root, des .conf que le groupe peut écrire.  Il n'en passe
# rien tel quel au système : chaque valeur est contrôlée, puis le fichier
# remis à wg est réécrit par le daemon (conf_wg_noyau).  Les clés inconnues
# sont ignorées — elles n'ont aucun effet, rien ne les relit — et les scripts
# de wg-quick (PostUp…) aussi : le daemon n'exécute jamais rien d'un .conf.
#
# Les messages ne recopient jamais une valeur : une clé privée mal formée
# finirait sinon dans le journal.

WG_CONF_MAX = 65536
WG_SCRIPTS = frozenset("preup postup predown postdown".split())
WG_EMBALLAGES = ("proton", "ivpn", "mullvad")
# Fichiers de Mullvad, reconnus sans commentaire « Katakomba-Emballage » :
# DNS de la passerelle, ou adresse IPv6 du réseau interne de Mullvad.
MULLVAD_DNS = ipaddress.ip_address("10.64.0.1")
MULLVAD_IPV6 = ipaddress.ip_network("fc00:bbbb:bbbb:bb01::/64")
WG_MTU_MIN, WG_MTU_MAX = 1280, 1420
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_KATAKOMBA = re.compile(r"#\s*katakomba-([a-z]+)\s*=\s*(\S*)\s*$", re.IGNORECASE)


def cle_wg_valide(valeur: str) -> bool:
    """Clé WireGuard : 32 octets en base64."""
    import base64
    import binascii
    try:
        return len(base64.b64decode(valeur, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _ip_port(valeur: str):
    """« 1.2.3.4:443 » ou « [2001:db8::1]:443 » → (ip, port), ou None.
    Une adresse IP, jamais un nom : rien n'est résolu hors de Tor."""
    hote, sep, port = valeur.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        return None
    try:
        return str(ipaddress.ip_address(hote.strip("[]"))), int(port)
    except ValueError:
        return None


def analyser_wg(texte: str):
    """Lit un .conf WireGuard.  Renvoie (réglages, refus, avertissements) ;
    réglages vaut None si le fichier est refusé.

    Réglages : cle_privee, cle_publique, cle_partagee (ou None), adresse
    (IPv4), dns (liste), mtu (ou None), endpoint (ip, port), emballage,
    serveur et cible (« ip:port »), uuid."""
    refus, avert = [], []
    if len(texte) > WG_CONF_MAX:
        return None, [f"fichier trop volumineux (plus de {WG_CONF_MAX} octets)"], []
    section, pairs, vu = None, 0, {}
    commentaires = {}
    for n, ligne in enumerate(texte.replace("\r", "").split("\n"), 1):
        brute = ligne.strip()
        m = _KATAKOMBA.match(brute)
        if m:
            commentaires[m.group(1).lower()] = m.group(2)
            continue
        brute = brute.split("#", 1)[0].strip()
        if not brute:
            continue
        if brute.startswith("[") and brute.endswith("]"):
            section = brute[1:-1].strip().lower()
            if section == "peer":
                pairs += 1
            elif section != "interface":
                refus.append(f"ligne {n} : section inconnue")
            continue
        nom, sep, valeur = brute.partition("=")
        nom, valeur = nom.strip().lower(), valeur.strip()
        if not sep or section not in ("interface", "peer"):
            refus.append(f"ligne {n} : ligne illisible")
            continue
        if nom in WG_SCRIPTS:
            avert.append(f"ligne {n} : script de wg-quick ignoré (jamais exécuté)")
            continue
        vu[(section, nom)] = (n, valeur)
    if pairs != 1:
        refus.append("il faut exactement un pair ([Peer])"
                     if pairs else "aucun pair ([Peer])")

    def champ(section, nom, requis=True):
        if (section, nom) in vu:
            return vu[(section, nom)][1]
        if requis:
            refus.append(f"{nom} absent de [{section.capitalize()}]")
        return None

    r = {}
    for cle, (section, nom, requis) in {
            "cle_privee": ("interface", "privatekey", True),
            "cle_publique": ("peer", "publickey", True),
            "cle_partagee": ("peer", "presharedkey", False)}.items():
        valeur = champ(section, nom, requis)
        if valeur is not None and not cle_wg_valide(valeur):
            refus.append(f"{nom} mal formée (32 octets en base64 attendus)")
        r[cle] = valeur

    r["adresse"], mullvad = None, False
    for morceau in (champ("interface", "address") or "").split(","):
        try:
            iface = ipaddress.ip_interface(morceau.strip())
        except ValueError:
            refus.append("Address illisible")
            break
        if iface.version == 4 and r["adresse"] is None:
            r["adresse"] = str(iface.ip)
        mullvad |= iface.ip in MULLVAD_IPV6
    if r["adresse"] is None and ("interface", "address") in vu and not refus:
        refus.append("Address : aucune adresse IPv4")

    r["dns"] = []
    for morceau in (champ("interface", "dns", False) or "").split(","):
        morceau = morceau.strip()
        if not morceau:
            continue
        try:
            ip = ipaddress.ip_address(morceau)
        except ValueError:
            avert.append("DNS : nom de domaine de recherche ignoré")
            continue
        if ip.version == 4:
            r["dns"].append(str(ip))
        mullvad |= ip == MULLVAD_DNS

    r["mtu"] = None
    mtu = champ("interface", "mtu", False)
    if mtu is not None:
        if mtu.isdigit() and WG_MTU_MIN <= int(mtu) <= WG_MTU_MAX:
            r["mtu"] = int(mtu)
        else:
            avert.append(f"MTU ignoré (entre {WG_MTU_MIN} et {WG_MTU_MAX} attendu)")

    endpoint = champ("peer", "endpoint")
    r["endpoint"] = _ip_port(endpoint) if endpoint is not None else None
    if endpoint is not None and r["endpoint"] is None:
        refus.append("Endpoint : adresse IP et port attendus (pas de nom de domaine)")

    r["emballage"] = commentaires.get(
        "emballage", "mullvad" if mullvad else "proton").lower()
    if r["emballage"] not in WG_EMBALLAGES:
        refus.append("Katakomba-Emballage inconnu "
                     f"({', '.join(WG_EMBALLAGES)} attendu)")
    for nom in ("serveur", "cible"):
        r[nom] = None
        if nom in commentaires:
            ip_port = _ip_port(commentaires[nom])
            if ip_port is None:
                refus.append(f"Katakomba-{nom.capitalize()} : adresse IP et port attendus")
            else:
                ip, port = ip_port
                r[nom] = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    # Proton (Stealth) et Mullvad (udp-over-tcp) : TCP 443 sur l'IP du serveur.
    if r["serveur"] is None and r["endpoint"] and r["emballage"] != "ivpn":
        ip = r["endpoint"][0]
        r["serveur"] = f"[{ip}]:443" if ":" in ip else f"{ip}:443"
    r["uuid"] = commentaires.get("uuid", "").lower() or None
    if r["emballage"] == "ivpn":
        if not (r["serveur"] and r["cible"]):
            refus.append("emballage ivpn : Katakomba-Serveur et Katakomba-Cible requis")
        if not (r["uuid"] and _UUID.fullmatch(r["uuid"])):
            refus.append("emballage ivpn : Katakomba-UUID absent ou mal formé")
    return (None if refus else r), refus, avert


def conf_wg_noyau(reglages: dict, pont: str) -> str:
    """Fichier remis à « wg setconf » : réécrit d'après les réglages
    contrôlés, le pair joint par le pont local."""
    lignes = ["[Interface]", f"PrivateKey = {reglages['cle_privee']}", "",
              "[Peer]", f"PublicKey = {reglages['cle_publique']}"]
    if reglages.get("cle_partagee"):
        lignes.append(f"PresharedKey = {reglages['cle_partagee']}")
    lignes += ["AllowedIPs = 0.0.0.0/0", f"Endpoint = {pont}",
               "PersistentKeepalive = 25", ""]
    return "\n".join(lignes)
