"""
Validation des fichiers fournis par le groupe katakomba : .ovpn et torrc.

Le daemon tourne en root et passe ces fichiers à OpenVPN et à Tor, eux aussi
en root.  Or le groupe katakomba peut les écrire (c'est ce qui permet au GUI de
tourner sans privilège).  Sans contrôle, écrire un fichier de configuration
suffirait à faire exécuter du code en root :

  .ovpn  « plugin /x.so » charge une bibliothèque — vérifié sur OpenVPN
         2.7.0, même avec --script-security 1 : le constructeur de la
         bibliothèque s'exécute avant toute connexion.
  torrc  « ClientTransportPlugin x exec /chemin » lance un programme.

On procède donc par LISTE BLANCHE : une directive absente de la liste fait
refuser le fichier entier.  Une liste noire serait à refaire à chaque version
d'OpenVPN ou de Tor (la 2.7 a ajouté dns-updown, qui exécute un script).

Les messages produits sont sûrs à journaliser : ils ne recopient jamais le
contenu d'une ligne, seulement un nom pris dans un vocabulaire fixe.  Sans
cette précaution, un fichier pointant sur /etc/shadow ferait recopier ses
lignes dans le journal, lisible par le groupe adm.
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


def analyser_ovpn(texte: str):
    """Renvoie (refus, avertissements) : deux listes de messages.

    Un seul refus suffit à écarter le fichier.  Les avertissements ne
    bloquent rien."""
    refus, avert = [], []
    bloc = None
    secu_signalee = False
    for n, brute in enumerate(texte.splitlines(), 1):
        ligne = brute.strip()
        if bloc is not None:
            if ligne == f"</{bloc}>":
                bloc = None
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


def chemin_ovpn_sur(chemin) -> bool:
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
