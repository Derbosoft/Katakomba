#!/bin/bash
# Katakomba — CLI wrapper
SERVICE="katakomba"
# Emplacement fixe, propriété de root (install.sh).  Il était lu dans
# /etc/katakomba/install_dir, fichier que le groupe katakomba peut
# remplacer : « sudo katakomba gui » aurait alors exécuté n'importe quel code.
DAEMON_DIR="/opt/katakomba"

# Lancé depuis une session SSH ?  sudo efface SSH_CONNECTION : on remonte
# aussi la lignée des processus jusqu'à sshd.
_session_ssh() {
    [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ] && return 0
    local pid=$$ _
    for _ in $(seq 30); do
        pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        if [ -z "$pid" ] || [ "$pid" -le 1 ]; then return 1; fi
        case "$(cat "/proc/$pid/comm" 2>/dev/null)" in sshd*) return 0 ;; esac
    done
    return 1
}

_need_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Cette commande nécessite les droits root."
        echo "Utilisez : sudo katakomba $*"
        exit 1
    fi
}

case "${1:-help}" in

    start)
        _need_root "$@"
        # --essai [MIN] : mise en route à distance sans risque.  Le service
        # s'arrête de lui-même au bout de MIN minutes (5 par défaut) sauf
        # « katakomba confirm » — l'accès revient si quelque chose a coupé
        # la session.
        ESSAI=""
        case "${2:-}" in
            "") ;;
            --essai|--trial)
                ESSAI="${3:-5}"
                if ! [[ "$ESSAI" =~ ^[0-9]{1,3}$ ]] || [ "$ESSAI" -lt 1 ] || [ "$ESSAI" -gt 120 ]; then
                    echo "Durée de l'essai : de 1 à 120 minutes." >&2
                    exit 2
                fi
                ;;
            *) echo "Option inconnue : $2" >&2; exit 2 ;;
        esac
        if [ -z "$ESSAI" ] && _session_ssh; then
            echo "Session SSH détectée : elle reste joignable une fois le tunnel monté."
            echo "Par prudence, pour une première mise en route à distance :"
            echo "    sudo katakomba start --essai     (arrêt automatique dans 5 min sauf"
            echo "                                      « sudo katakomba confirm »)"
        fi
        systemctl reset-failed "$SERVICE" 2>/dev/null || true
        if [ -n "$ESSAI" ]; then
            systemctl stop katakomba-essai.timer 2>/dev/null || true
            systemctl reset-failed katakomba-essai.service 2>/dev/null || true
            systemd-run --quiet --unit=katakomba-essai --on-active="${ESSAI}min" \
                --description="Katakomba : fin de l'essai" \
                /usr/bin/systemctl stop "$SERVICE" || exit 1
        fi
        systemctl start "$SERVICE" && echo "Service démarré."
        if [ -n "$ESSAI" ]; then
            echo "À l'essai : arrêt automatique dans $ESSAI min."
            echo "Vérifiez (katakomba doctor), puis gardez-le :  sudo katakomba confirm"
        fi
        ;;

    confirm|confirmer)
        _need_root "$@"
        if systemctl is-active --quiet katakomba-essai.timer; then
            systemctl stop katakomba-essai.timer
            echo "Service gardé : l'arrêt automatique est annulé."
        else
            echo "Aucun essai en cours."
        fi
        ;;

    stop)
        _need_root "$@"
        systemctl stop katakomba-essai.timer 2>/dev/null || true
        systemctl stop "$SERVICE" && echo "Service arrêté."
        ;;

    restart)
        _need_root "$@"
        systemctl reset-failed "$SERVICE" 2>/dev/null || true
        systemctl restart "$SERVICE" && echo "Service redémarré."
        ;;

    enable)
        _need_root "$@"
        systemctl enable "$SERVICE" && echo "Démarrage automatique activé."
        ;;

    disable)
        _need_root "$@"
        systemctl disable "$SERVICE" && echo "Démarrage automatique désactivé."
        ;;

    gui)
        if [ ! -f "$DAEMON_DIR/main.py" ]; then
            # Paquet katakomba-headless (serveur) : pas d'interface.
            echo "Interface graphique non installée (version sans interface)." >&2
            echo "Configuration en console : katakomba help" >&2
            echo "Pour l'interface : installez le paquet katakomba (avec interface)." >&2
            exit 1
        fi
        # Le GUI tourne en utilisateur normal (groupe katakomba) ; les actions
        # privilégiées passent par polkit depuis le GUI lui-même.
        # Seule option transmise : --arriere-plan (ouverture de session).
        OPTS=()
        for a in "${@:2}"; do
            case "$a" in
                --arriere-plan) OPTS+=("$a") ;;
                *) echo "Option inconnue : $a" >&2; exit 2 ;;
            esac
        done
        # En root, une application GTK n'accède pas à l'écran d'une session
        # Wayland — et n'a aucune raison de le demander.
        if [ "$EUID" -eq 0 ]; then
            echo "Lancez l'interface sans sudo :  katakomba gui" >&2
            echo "(le mot de passe est demandé quand une action l'exige)" >&2
            exit 1
        fi
        #
        # Juste après l'installation, l'utilisateur est inscrit dans le groupe
        # katakomba mais sa session ne le sait pas encore : il faudrait se
        # déconnecter puis se reconnecter.  « sg » ouvre le GUI avec le
        # groupe dès maintenant (sans mot de passe pour un membre du groupe).
        # Absent de certaines distributions (Ubuntu 26.04) : le GUI explique
        # alors qu'il faut rouvrir la session.
        if [ "$EUID" -ne 0 ] && command -v sg &>/dev/null \
           && ! id -nG | tr ' ' '\n' | grep -qx katakomba \
           && getent group katakomba | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"; then
            exec sg katakomba -c "exec python3 '$DAEMON_DIR/main.py' ${OPTS[*]}"
        fi
        exec python3 "$DAEMON_DIR/main.py" "${OPTS[@]}"
        ;;

    autoriser)
        # Donne à un compte l'accès à la configuration (groupe katakomba), ou,
        # avec --statut, la seule lecture de l'état (groupe katakomba-statut :
        # supervision, tableau de bord — sans pouvoir désactiver le blocage
        # hors tunnel).  L'installation accorde le premier à l'administrateur.
        _need_root "$@"
        GROUPE=katakomba
        CIBLE=""
        for a in "${@:2}"; do
            case "$a" in
                --statut|--status) GROUPE=katakomba-statut ;;
                -*) echo "Option inconnue : $a" >&2; exit 2 ;;
                *) CIBLE="$a" ;;
            esac
        done
        [ -n "$CIBLE" ] || CIBLE="${SUDO_USER:-}"
        if [ -z "$CIBLE" ] || ! id "$CIBLE" &>/dev/null; then
            echo "Usage : sudo katakomba autoriser <utilisateur> [--statut]"
            exit 1
        fi
        if ! getent group "$GROUPE" >/dev/null; then
            echo "Groupe $GROUPE absent : réinstallez Katakomba (sudo bash install.sh)." >&2
            exit 1
        fi
        usermod -aG "$GROUPE" "$CIBLE" || exit 1
        if [ "$GROUPE" = katakomba ]; then
            echo "« $CIBLE » peut maintenant configurer Katakomba (katakomba gui, ou en console : katakomba help)."
        else
            echo "« $CIBLE » peut maintenant lire l'état (katakomba status, katakomba doctor),"
            echo "sans pouvoir modifier la configuration."
        fi
        echo "Prise d'effet à la prochaine ouverture de session de ce compte."
        ;;

    uninstall|desinstaller)
        _need_root "$@"
        for PAQ in katakomba katakomba-headless; do
            if dpkg-query -W -f='${Status}' "$PAQ" 2>/dev/null \
                    | grep -q "install ok installed"; then
                echo "Installé par paquet — désinstallez avec :"
                echo "    sudo apt remove $PAQ    (garde vos réglages)"
                echo "    sudo apt purge  $PAQ    (efface tout)"
                exit 1
            fi
        done
        exec bash "$DAEMON_DIR/uninstall.sh" "${@:2}"
        ;;

    status)
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║  Katakomba — État                                    ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo ""
        if systemctl is-active "$SERVICE" &>/dev/null; then
            SINCE=$(systemctl show "$SERVICE" \
                --property=ActiveEnterTimestamp --value 2>/dev/null \
                | sed 's/ [A-Z]*$//')
            echo "  Service    : actif  (depuis $SINCE)"
        else
            STATE=$(systemctl show "$SERVICE" --property=SubState --value 2>/dev/null)
            echo "  Service    : $STATE"
        fi
        if systemctl is-enabled "$SERVICE" &>/dev/null; then
            echo "  Boot auto  : activé"
        else
            echo "  Boot auto  : désactivé"
        fi
        echo ""
        # État précis via le socket du daemon ; repli sur pgrep si absent.
        DSTATUS=$(python3 - << 'PYEOF' 2>/dev/null
import json, socket
try:
    d = None
    for chemin in ("/run/katakomba.sock", "/run/katakomba-statut.sock"):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect(chemin)
            d = json.loads(s.makefile().readline())
            break
        except OSError:
            continue
    if d is None:
        raise OSError("statut illisible")
    tor = "actif (bootstrap OK)" if d["tor_ready"] else \
          ("bootstrap en cours" if d["tor_running"] else "inactif")
    if d["tunnel_up"]:
        up = d["tunnel_uptime"]
        vpn = (f"actif ({d['tunnel_iface']} UP, {d['provider']}, "
               f"{d['rx_kbs']:.0f} KB/s, depuis {up//3600}h{(up%3600)//60:02d})")
    else:
        vpn = "connexion en cours" if d["tor_ready"] else "en attente de Tor"
    print(f"  Tor        : {tor}")
    print(f"  VPN        : {vpn}")
    kbs = d.get("last_circuit_kbs", 0)
    if kbs:
        age = d.get("last_circuit_age", 0)
        quand = f"il y a {age//3600}h{(age%3600)//60:02d}" if age >= 3600 \
                else f"il y a {age//60} min" if age >= 60 else "à l'instant"
        print(f"  Circuit    : {kbs:.0f} KB/s (~{kbs*8/1000:.1f} Mbps) "
              f"mesuré {quand}")
    elif d["tunnel_up"]:
        print("  Circuit    : non mesuré")
    if d["lan_sharing"]:  print("  Partage LAN: actif")
    if d["ipv6_blocked"]: print("  IPv6       : bloqué")
    if d.get("kill_switch"): print("  Hors tunnel: bloqué")
    if d.get("incoming_return"): print("  Entrantes  : réponses hors tunnel (SSH joignable)")
except Exception:
    pass
PYEOF
)
        if [ -n "$DSTATUS" ]; then
            echo "$DSTATUS"
        else
            # Processus de ce programme uniquement (pas Tor Browser, pas un
            # autre VPN), reconnus à leur ligne de commande.
            TOR_PID=$(pgrep -f "^tor .*katakomba/tor(rc|_data)" | head -1)
            if [ -n "$TOR_PID" ]; then
                echo "  Tor        : actif  (PID $TOR_PID)"
            else
                echo "  Tor        : inactif"
            fi
            if pgrep -f -- "^openvpn .*katakomba(-vpn)?/auth" &>/dev/null \
                    || pgrep -f -- "pont_wg\.py .*--ecoute 127\.0\.0\.1:51871" &>/dev/null; then
                if ip link show tun-katakomba up 2>/dev/null | grep -q .; then
                    echo "  VPN        : actif  (tun-katakomba UP)"
                else
                    echo "  VPN        : connexion en cours"
                fi
            else
                echo "  VPN        : inactif"
            fi
        fi
        if [ -f /etc/systemd/resolved.conf.d/katakomba-split.conf ]; then
            DNS_SERVER=$(grep '^DNS=' /etc/systemd/resolved.conf.d/katakomba-split.conf | cut -d= -f2)
            echo "  DNS split  : actif  (→ $DNS_SERVER)"
        else
            echo "  DNS split  : inactif"
        fi
        echo ""
        IP=$(curl -s --max-time 6 https://api.ipify.org 2>/dev/null)
        echo "  IP publique: ${IP:-(inaccessible)}"
        echo ""
        echo "── Derniers logs ────────────────────────────────────────"
        journalctl -u "$SERVICE" -n 15 --no-pager --output=short-precise 2>/dev/null \
            || echo "  (journalctl non disponible)"
        echo "────────────────────────────────────────────────────────"
        ;;

    doctor)
        # Diagnostic complet, en LECTURE SEULE et sans root : vérifie les
        # invariants qui doivent tenir quand la connexion est saine.
        # Code de sortie : 0 si aucun KO, 1 sinon, 2 si une reconnexion est en
        # cours (contrôles du tunnel reportés, rien de bloquant par ailleurs),
        # 3 si l'état du daemon n'est pas lisible par ce compte (ni membre de
        # katakomba ou katakomba-statut, ni root) : rien de cassé, mais rien
        # de vérifié non plus côté daemon.
        # --json : mêmes résultats pour l'interface graphique.  Textes dans la
        # langue de l'utilisateur (KATAKOMBA_LANGUE, sinon celle du système).
        python3 - "$DAEMON_DIR" "${@:2}" << 'PYEOF'
import json, os, socket, subprocess, sys, time

DAEMON_DIR = sys.argv[1] if len(sys.argv) > 1 else ""
JSON = "--json" in sys.argv[2:]
# Textes dans la langue de l'utilisateur (KATAKOMBA_LANGUE, sinon celle du
# système) ; en français si les traductions sont introuvables.
try:
    sys.path.insert(0, DAEMON_DIR)
    import i18n
    i18n.activer(os.environ.get("KATAKOMBA_LANGUE", ""))
    from i18n import _, ngettext, nombre
except Exception:
    _ = lambda s: s
    ngettext = lambda s, p, n: s if n == 1 else p
    nombre = lambda v, d=1: f"{v:.{d}f}"

OK, WARN, KO = "OK  ", "WARN", "KO  "
ATTENTE, REPORTE = "....", "--  "
NIVEAUX_JSON = {OK: "ok", WARN: "attention", KO: "erreur", ATTENTE: "attente",
                REPORTE: "reporte"}
# Une reconnexion voulue (nouveau circuit, relance du VPN) dure quelques
# secondes.  Au-delà de ce délai, un tunnel toujours absent est une panne,
# même si le daemon est encore en train d'essayer.
RECONNEXION_MAX = 120
NON_VERIFIE = _("reporté — le tunnel se reconnecte")
en_cours = ""        # raison d'une reconnexion en cours ; vide sinon
non_verifie = False  # état du daemon illisible pour ce compte (droits)
resultats = []

def note(niveau, titre, detail=""):
    resultats.append((niveau, titre, detail))

def sh(*cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception:
        return 1, ""

def duree(s):
    return _("{h} h {m:02d}").format(h=s // 3600, m=(s % 3600) // 60)

def publier(conclusion, code):
    """Résultats puis verdict : tableau lisible, ou JSON pour l'interface."""
    if JSON:
        print(json.dumps({"resultats": [{"niveau": NIVEAUX_JSON[n], "titre": t, "detail": d}
                                        for n, t, d in resultats],
                          "conclusion": conclusion, "code": code}, ensure_ascii=False))
        sys.exit(code)
    largeur = max(len(t) for _n, t, _d in resultats) + 2
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║  " + _("Diagnostic Katakomba").ljust(52) + "║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    for niveau, titre, detail in resultats:
        print(f"  [{niveau}] {titre:{largeur}} {detail}")
    print()
    for ligne in conclusion:
        print(f"  {ligne}")
    print()
    sys.exit(code)

# ── 1. Service ────────────────────────────────────────────────────────────────
rc, _sortie = sh("systemctl", "is-active", "katakomba")
if rc != 0:
    note(KO, _("Service"), _("katakomba n'est pas actif — sudo katakomba start"))
    publier([_("Le service est arrêté : aucun autre contrôle n'a de sens.")], 1)
note(OK, _("Service"), _("actif"))

# ── 2. État du daemon ─────────────────────────────────────────────────────────
# Socket complet (groupe katakomba), sinon celui en lecture seule (groupe
# katakomba-statut, v3.12.0) : le même JSON.  Un refus de permission n'est
# pas une panne — le compte n'a simplement pas le droit de lire l'état.
st, refus, erreur = {}, False, None
for chemin in ("/run/katakomba.sock", "/run/katakomba-statut.sock"):
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(3)
        s.connect(chemin)
        st = json.loads(s.makefile().readline())
        break
    except PermissionError:
        refus = True
    except FileNotFoundError as e:
        erreur = erreur or e
    except Exception as e:
        erreur = e
if not st and refus:
    non_verifie = True
    note(REPORTE, _("Socket de statut"),
         _("non vérifiable — réservé aux groupes katakomba et katakomba-statut "
           "(ou sudo)"))
elif not st:
    note(KO, _("Socket de statut"), _("injoignable ({erreur})").format(erreur=erreur))

if st:
    # Reconnexion voulue en cours ?  Décidé avant tout le reste : pendant
    # ces quelques secondes, Tor et le tunnel sont absents par construction.
    bas = st.get("tunnel_down_for", 0)
    raison = st.get("reconnect_reason", "")
    if not st.get("tunnel_up") and raison and bas < RECONNEXION_MAX:
        en_cours = _(raison)          # raisons du daemon : traduites (catalogue)
    note(OK, _("Version du daemon"), st["version"])
    if st.get("tor_ready"):
        note(OK, _("Tor"), _("bootstrap terminé"))
    elif en_cours:
        note(ATTENTE, _("Tor"), _("démarrage en cours"))
    else:
        note(KO, _("Tor"), _("pas prêt"))
    if st.get("tunnel_up") and st.get("transport") == "wireguard":
        note(OK, _("Tunnel"), _("{iface} depuis {duree} ({fournisseur}, WireGuard, "
                                "fichier {n})").format(
            iface=st["tunnel_iface"], duree=duree(st["tunnel_uptime"]),
            fournisseur=st["provider"], n=st["account_index"] + 1))
    elif st.get("tunnel_up"):
        note(OK, _("Tunnel"), _("{iface} depuis {duree} ({fournisseur}, compte {n})").format(
            iface=st["tunnel_iface"], duree=duree(st["tunnel_uptime"]),
            fournisseur=st["provider"], n=st["account_index"] + 1))
    elif en_cours:
        note(ATTENTE, _("Tunnel"), _("reconnexion en cours depuis {s} s ({raison})").format(
            s=bas, raison=en_cours))
    else:
        depuis = _(" depuis {m} min {s:02d} s").format(m=bas // 60, s=bas % 60) if bas else ""
        cause = _(" — dernière cause : {raison}").format(raison=_(raison)) if raison else ""
        note(KO, _("Tunnel"), _("fermé{depuis}{cause}").format(depuis=depuis, cause=cause))
    kbs, age = st.get("last_circuit_kbs", 0), st.get("last_circuit_age", 0)
    if kbs:
        vieux = age > 6 * 3600
        note(WARN if vieux else OK, _("Qualité du circuit"),
             _("{kbs} Ko/s (~{mbps} Mb/s), mesuré il y a {age}").format(
                 kbs=f"{kbs:.0f}", mbps=nombre(kbs * 8 / 1000), age=duree(age))
             + (_(" — mesure ancienne, le circuit a pu se dégrader") if vieux else ""))
    elif st.get("tunnel_up"):
        note(WARN, _("Qualité du circuit"), _("aucune mesure pour ce tunnel"))

    # Comptes écartés temporairement : ni une panne ni un état normal, une
    # information.  Un refus d'authentification ne distingue pas un mot de
    # passe invalide d'un quota de connexions simultanées atteint.
    quar = st.get("accounts_cooldown") or {}
    if quar:
        detail = ", ".join(_("compte {n} ({min} min)").format(n=n, min=s // 60)
                           for n, s in sorted(quar.items(), key=lambda kv: int(kv[0])))
        note(WARN, _("Comptes en quarantaine"), detail + _(" — essayés en dernier"))
    else:
        note(OK, _("Comptes"), _("aucun écarté"))

tun = st.get("tunnel_iface", "tun-katakomba")

# ── 3. Routage ────────────────────────────────────────────────────────────────
_rc, routes = sh("ip", "-4", "route", "show")
lignes = routes.splitlines()

defauts = [l for l in lignes if l.startswith("default")]
if not defauts:
    note(KO, _("Route par défaut"), _("absente"))
elif f"dev {tun}" in defauts[0]:
    note(KO, _("Route par défaut"),
         _("pointe sur {tun} — boucle de routage probable").format(tun=tun))
else:
    note(OK, _("Route par défaut"),
         _("{route} (hors tunnel)").format(route=defauts[0].split("proto")[0].strip()))

if "tor_guard_routes" in st:
    # Relais que le daemon a protégés, retrouvés dans la table de routage.
    # Compter toutes les routes /32 « via » prenait aussi les exclusions de
    # l'utilisateur (192.168.50.10/32…) pour des guards : faux OK possible.
    attendus = st["tor_guard_routes"]
    hors_tunnel = {l.split()[0] for l in lignes if " via " in l}
    guards = [ip for ip in attendus if ip in hors_tunnel]
    if guards:
        note(OK, _("Protection des guards Tor"),
             ngettext("{n}/{total} relais routé hors tunnel",
                      "{n}/{total} relais routés hors tunnel", len(guards)).format(
                 n=len(guards), total=len(attendus)))
    elif en_cours:
        # Posées à la montée du tunnel ; un redémarrage complet les retire.
        note(REPORTE, _("Protection des guards Tor"), NON_VERIFIE)
    else:
        note(KO, _("Protection des guards Tor"),
             _("aucun relais protégé dans la table de routage — Tor risque de "
               "joindre ses relais par le tunnel"))
else:
    # Daemon antérieur à la v3.7.0 : heuristique d'origine.
    guards = [l for l in lignes
              if l[:1].isdigit() and "/" not in l.split()[0] and " via " in l]
    if guards:
        note(OK, _("Protection des guards Tor"),
             ngettext("{n} route /32 hors tunnel", "{n} routes /32 hors tunnel",
                      len(guards)).format(n=len(guards)))
    else:
        note(KO, _("Protection des guards Tor"),
             _("aucune route /32 — Tor risque de joindre ses relais par le tunnel"))

redirect = [l for l in lignes if l.startswith(("0.0.0.0/1", "128.0.0.0/1"))]
if en_cours:
    note(REPORTE, _("Redirection du trafic"), NON_VERIFIE)
else:
    note(OK if len(redirect) == 2 else WARN, _("Redirection du trafic"),
         _("{n}/2 routes def1 présentes").format(n=len(redirect)))

# Piège scope-link : un réseau directement connecté ne doit jamais être
# supplanté par une route « via » de métrique 0.
_rc, liens = sh("ip", "-4", "route", "show", "scope", "link")
connectes = {l.split()[0] for l in liens.splitlines() if "/" in l.split()[0]}
detournes = [c for c in connectes
             if any(l.startswith(c + " ") and " via " in l for l in lignes)]
if detournes:
    note(KO, _("Réseaux locaux"),
         _("détourné(s) par une route via : {reseaux} — casse l'accès aux machines "
           "du segment").format(reseaux=", ".join(detournes)))
else:
    note(OK, _("Réseaux locaux"),
         ngettext("{n} réseau en accès direct", "{n} réseaux en accès direct",
                  len(connectes)).format(n=len(connectes)))

# systemd-networkd retire à son redémarrage (une mise à jour suffit) les routes
# et règles qu'il n'a pas posées.  Le daemon les repose (v3.12.1), mais le
# tunnel reste coupé jusqu'à 30 s.  Dernière valeur lue = celle qui s'applique.
if sh("systemctl", "is-active", "systemd-networkd")[0] == 0:
    _rc, conf = sh("systemd-analyze", "cat-config", "systemd/networkd.conf")
    valeurs = {}
    for l in conf.splitlines():
        l = l.strip()
        if "=" in l and not l.startswith(("#", ";", "[")):
            cle, _sep, val = l.partition("=")
            valeurs[cle.strip()] = val.strip().lower()
    actifs = [cle for cle in ("ManageForeignRoutes", "ManageForeignRoutingPolicyRules")
              if valeurs.get(cle, "yes") not in ("no", "false", "0", "off")]
    if actifs:
        note(WARN, _("systemd-networkd"),
             _("{reglages} actif : à chaque redémarrage de networkd, le tunnel est "
               "coupé jusqu'à 30 s — « =no » dans networkd.conf l'évite (README)").format(
                 reglages=", ".join(actifs)))
    else:
        note(OK, _("systemd-networkd"), _("ne retire pas les routes du tunnel"))

# ── 4. DNS ────────────────────────────────────────────────────────────────────
rc, sortie = sh("resolvectl", "status", tun)
attrs = {}
for ligne in sortie.splitlines():
    label, sep, val = ligne.partition(":")
    if sep:
        attrs[label.strip()] = val.strip()
# default-route : le format varie selon la version de systemd.  Le drapeau de
# « Protocols » est présent partout ; l'étiquette « Default Route » n'existe
# pas sur systemd 255.  None = format non reconnu, on ne conclut pas.
def etat_default_route(attrs):
    proto = attrs.get("Protocols", "")
    if "+DefaultRoute" in proto:
        return True
    if "-DefaultRoute" in proto:
        return False
    for label in ("Default Route", "DefaultRoute setting"):
        if label in attrs:
            return attrs[label].strip().lower() in ("yes", "true")
    return None

route_dns = etat_default_route(attrs)
manquants = []
if not attrs.get("DNS Servers"):
    manquants.append(_("serveur"))
if "~." not in attrs.get("DNS Domain", "").split():
    manquants.append(_("domaine ~."))
if route_dns is False:
    manquants.append("default-route")
if en_cours:
    note(REPORTE, _("DNS du tunnel"), NON_VERIFIE)
elif manquants:
    note(KO, _("DNS du tunnel"),
         _("incomplet ({manquants}) — risque de requêtes hors tunnel").format(
             manquants=", ".join(manquants)))
elif route_dns is None:
    note(WARN, _("DNS du tunnel"),
         _("{serveurs} · ~. — default-route non vérifiable (format resolvectl "
           "inconnu)").format(serveurs=attrs.get("DNS Servers", "?")))
else:
    note(OK, _("DNS du tunnel"), f"{attrs['DNS Servers']} · ~. · default-route")

if os.path.exists("/etc/systemd/resolved.conf.d/katakomba-split.conf"):
    note(OK, _("DNS split"), _("drop-in en place"))

# Où part réellement une requête publique ? Le résolveur local répond en
# ~0 ms, celui du tunnel en dizaines/centaines de ms.
uplink = ""
if defauts:
    champs = defauts[0].split()
    if "dev" in champs:
        uplink = champs[champs.index("dev") + 1]

if not en_cours:
    t0 = time.monotonic()
    sh("resolvectl", "query", "--cache=no", "wikipedia.org", timeout=20)
    lat_defaut = time.monotonic() - t0
    lat_locale = None
    if uplink:
        t0 = time.monotonic()
        sh("resolvectl", "query", "--cache=no", "-i", uplink, "wikipedia.org", timeout=20)
        lat_locale = time.monotonic() - t0

if en_cours:
    note(REPORTE, _("Chemin des requêtes DNS"), NON_VERIFIE)
elif lat_defaut < 0.02 and (lat_locale is None or lat_locale < 0.02):
    note(WARN, _("Chemin des requêtes DNS"),
         _("trop rapide pour passer par Tor — vérifiez une éventuelle fuite"))
else:
    ref = _(" (résolveur local via {uplink} : {ms} ms)").format(
        uplink=uplink, ms=f"{lat_locale * 1000:.0f}") if lat_locale is not None else ""
    note(OK, _("Chemin des requêtes DNS"), f"{lat_defaut * 1000:.0f} ms{ref}")

# ── 5. IPv6 et blocage hors tunnel ────────────────────────────────────────────
# Connus du daemon seul : sans son état, rien à conclure (pas de faux WARN).
if not st:
    pass
elif st.get("ipv6_blocked"):
    note(OK, _("IPv6"), _("bloqué"))
elif st.get("kill_switch"):
    note(OK, _("IPv6"), _("bloqué hors tunnel"))
else:
    note(WARN, _("IPv6"), _("non bloqué (option désactivée dans les paramètres)"))
# Absent d'un daemon plus ancien : rien à vérifier.
if st.get("kill_switch"):
    note(OK, _("Blocage hors tunnel"),
         _("actif — seuls le tunnel, Tor et le réseau local sortent"))
elif st.get("kill_switch_config"):
    note(KO, _("Blocage hors tunnel"),
         _("activé dans les réglages mais inactif — cause dans le journal "
           "(katakomba logs)"))
elif "kill_switch_config" in st:
    note(WARN, _("Blocage hors tunnel"),
         _("désactivé — pendant une reconnexion, le trafic peut sortir à découvert"))
# Réponses aux connexions entrantes (SSH, services) : par la carte réseau.
# Absent d'un daemon plus ancien : rien à vérifier.
if st.get("tunnel_up") and "incoming_return" in st:
    _rc, regles = sh("ip", "-4", "rule", "show")
    if st["incoming_return"] and "lookup 19265" in regles:
        note(OK, _("Connexions entrantes"),
             _("réponses par la carte réseau — SSH et services restent joignables"))
    else:
        note(KO, _("Connexions entrantes"),
             _("réponses envoyées dans le tunnel — une session SSH distante serait "
               "coupée (cause dans le journal)"))
# Une exclusion vers Internet est légitime (un service qui refuse Tor), mais
# elle doit rester visible : elle a pu être ajoutée hors de l'interface.
if st.get("public_exclusions"):
    note(WARN, _("Exclusions vers Internet"),
         _("{reseaux} — ce trafic sort hors du tunnel, avec votre adresse "
           "réelle").format(reseaux=", ".join(st["public_exclusions"])))

# ── 6. Connectivité réelle à travers le tunnel ────────────────────────────────
if en_cours:
    rc, ip = 1, ""
else:
    rc, ip = sh("curl", "-s", "--max-time", "20", "--interface", tun,
                "https://api.ipify.org", timeout=25)
ip = ip.strip()
if en_cours:
    note(REPORTE, _("Sortie Internet"), NON_VERIFIE)
elif rc == 0 and ip:
    import ipaddress
    try:
        # is_private couvre tout 172.16.0.0/12, pas seulement 172.16.x.
        prive = not ipaddress.ip_address(ip).is_global
    except ValueError:
        prive = True
    note(KO if prive else OK, _("Sortie Internet"),
         _("IP publique {ip}").format(ip=ip)
         + (_(" — adresse privée, sortie anormale") if prive else ""))
else:
    note(KO, _("Sortie Internet"), _("aucune réponse via {tun}").format(tun=tun))

# ── Verdict ───────────────────────────────────────────────────────────────────
n_ko = sum(1 for n, _t, _d in resultats if n == KO)
n_warn = sum(1 for n, _t, _d in resultats if n == WARN)
conclusion = []
if en_cours:
    # Surtout pas « restart » ici : il interromprait la reconnexion en cours
    # et repartirait de zéro.
    conclusion.append(_("Reconnexion en cours ({raison}) : les contrôles du tunnel "
                        "sont reportés.").format(raison=en_cours))
    conclusion.append(_("C'est normal et passager : relancez le diagnostic dans 30 s."))
    if n_ko:
        conclusion.append(ngettext("{n} autre problème bloquant ci-dessus, à revoir ensuite.",
                                   "{n} autres problèmes bloquants ci-dessus, à revoir ensuite.",
                                   n_ko).format(n=n_ko))
elif n_ko:
    conclusion.append(ngettext("{n} problème bloquant", "{n} problèmes bloquants",
                               n_ko).format(n=n_ko) + ", "
                      + ngettext("{n} avertissement.", "{n} avertissements.",
                                 n_warn).format(n=n_warn))
    conclusion.append(_("Piste : sudo katakomba restart (3 s de coupure), puis "
                        "relancez ce diagnostic."))
elif n_warn:
    conclusion.append(ngettext("Aucun problème bloquant, {n} avertissement à surveiller.",
                               "Aucun problème bloquant, {n} avertissements à surveiller.",
                               n_warn).format(n=n_warn))
elif non_verifie:
    conclusion.append(_("Aucun problème vu, mais l'état du daemon (Tor, tunnel, blocage "
                        "hors tunnel) n'est pas lisible par ce compte."))
    conclusion.append(_("Supervision : sudo katakomba autoriser <compte> --statut "
                        "(lecture seule), ou lancez avec sudo."))
else:
    conclusion.append(_("Tout est conforme."))
publier(conclusion, 1 if n_ko else (2 if en_cours else (3 if non_verifie else 0)))
PYEOF
        ;;

    logs)
        N="${2:-60}"
        journalctl -u "$SERVICE" -n "$N" --no-pager
        ;;

    follow)
        echo "Suivi des logs en temps réel (Ctrl+C pour quitter) …"
        journalctl -u "$SERVICE" -f
        ;;

    ip)
        IP=$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null)
        if [ -n "$IP" ]; then echo "$IP"; else echo "Impossible de récupérer l'IP."; fi
        ;;

    provider|fournisseur|account|compte|exclude|exclusion|set|reglage|backup|sauvegarde)
        # Configuration sans interface graphique (serveur) : console.py,
        # mêmes contrôles que l'interface.  Root ou groupe katakomba.
        exec python3 -B "$DAEMON_DIR/console.py" "$@"
        ;;

    help|--help|-h|aide|*)
        # Aide traduite (langue du système), tenue à jour dans console.py.
        python3 -B "$DAEMON_DIR/console.py" help
        # Commande inconnue : code 2, comme toute erreur d'usage.
        case "${1:-help}" in help|--help|-h|aide) ;; *) exit 2 ;; esac
        ;;
esac
