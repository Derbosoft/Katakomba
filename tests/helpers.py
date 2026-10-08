"""
Utilitaires communs aux tests : daemon factice et interception des commandes.

Principe de sûreté : AUCUN test ne doit exécuter de commande réelle.  Toutes
les fonctions qui touchent au système (iptables, ip, resolvectl, systemctl,
curl, openvpn, tor) passent par `_run` ou `subprocess`, tous deux remplacés
par les enregistreurs ci-dessous.  Un test qui oublierait de les remplacer
serait détecté par `tests/test_safety.py`.
"""

import atexit
import contextlib
import io
import shutil
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from constants import DEFAULT_CONFIG          # noqa: E402
from daemon import Daemon                     # noqa: E402

# Modules daemon qui importent `_run` depuis .core : chacun garde SA propre
# référence, il faut donc les remplacer un par un (patcher core ne suffit pas).
import daemon.core      as m_core             # noqa: E402
import daemon.dns       as m_dns              # noqa: E402
import daemon.firewall  as m_firewall         # noqa: E402
import daemon.network   as m_network          # noqa: E402
import daemon.openvpn   as m_openvpn          # noqa: E402
import daemon.tor       as m_tor              # noqa: E402
import daemon.watchdog  as m_watchdog         # noqa: E402

RUN_MODULES = (m_core, m_dns, m_firewall, m_network, m_openvpn, m_tor, m_watchdog)

# ── Bac à sable des fichiers du daemon ───────────────────────────────────────
# Sur une machine déployée, /run/katakomba et /var/lib/katakomba
# existent et appartiennent à root.  Un test qui y accéderait échouerait sans
# root (constaté : PermissionError sur dnsmasq.pid) — et, lancé en root,
# modifierait les fichiers de production.  Tous ces chemins sont donc
# redirigés, pour toute la suite, vers un répertoire temporaire.  Un test qui
# patche lui-même un chemin reste libre de le faire.
_BAC_A_SABLE = Path(tempfile.mkdtemp(prefix="katakomba-tests-"))
atexit.register(shutil.rmtree, _BAC_A_SABLE, True)
_RUN, _STATE = _BAC_A_SABLE / "run", _BAC_A_SABLE / "state"
_REDIRECTIONS = {
    "RUN_DIR":            _RUN,
    "STATE_DIR":          _STATE,
    "AUTH_TMP":           _RUN / "auth.tmp",
    "OVPN_RUN":           _RUN / "openvpn.conf",
    "TORRC_RUN":          _RUN / "torrc",
    "LAN_DNSMASQ_PID":    _RUN / "dnsmasq.pid",
    "TOR_ROUTES_FILE":    _STATE / "tor-routes.txt",
    "TOR_DATA_DIR":       _STATE / "tor_data",
    "TOR_COOKIE":         _STATE / "tor_data" / "control_auth_cookie",
    "LEGACY_TOR_DATA":    _BAC_A_SABLE / "etc" / "tor_data",
    "LEGACY_DNSMASQ_PID": _BAC_A_SABLE / "etc" / "tor-vpn-dnsmasq.pid",
}
for _m in RUN_MODULES:
    for _nom, _chemin in _REDIRECTIONS.items():
        if hasattr(_m, _nom):
            setattr(_m, _nom, _chemin)


class Result:
    """Imite subprocess.CompletedProcess pour les deux conventions d'accès :
    `.stdout` en bytes (via _run) comme en str (via subprocess.run(text=True))."""

    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._out = stdout.encode() if isinstance(stdout, str) else stdout
        self._err = stderr.encode() if isinstance(stderr, str) else stderr
        self.text = False

    @property
    def stdout(self):
        return self._out.decode() if self.text else self._out

    @property
    def stderr(self):
        return self._err.decode() if self.text else self._err


class Recorder:
    """Remplaçant de `_run` : enregistre chaque commande, répond selon un script.

    `responses` associe une sous-chaîne de la commande à `(returncode, stdout)`.
    La première correspondance gagne ; sinon `default` s'applique.
    """

    def __init__(self, responses=None, default=(0, b"")):
        self.calls = []
        self.responses = list((responses or {}).items())
        self.default = default

    def __call__(self, *cmd, **kwargs):
        argv = list(cmd[0]) if len(cmd) == 1 and isinstance(cmd[0], (list, tuple)) else list(cmd)
        line = " ".join(str(c) for c in argv)
        self.calls.append(line)
        for pattern, (rc, out) in self.responses:
            if pattern in line:
                r = Result(rc, out)
                r.text = bool(kwargs.get("text"))
                return r
        r = Result(*self.default)
        r.text = bool(kwargs.get("text"))
        return r

    # ── Assertions de lecture ────────────────────────────────────────────────

    def matching(self, *needles):
        """Commandes contenant TOUTES les sous-chaînes données."""
        return [c for c in self.calls if all(n in c for n in needles)]

    def count(self, *needles):
        return len(self.matching(*needles))

    def ran(self, *needles):
        return self.count(*needles) > 0

    def dump(self):
        return "\n".join(f"  {c}" for c in self.calls)


@contextlib.contextmanager
def patched_run(recorder, modules=RUN_MODULES):
    """Remplace `_run` dans tous les modules daemon le temps du bloc."""
    saved = [(m, getattr(m, "_run", None)) for m in modules]
    for m in modules:
        if hasattr(m, "_run"):
            m._run = recorder
    try:
        yield recorder
    finally:
        for m, old in saved:
            if old is not None:
                m._run = old


@contextlib.contextmanager
def patched_subprocess(module, recorder, popen=None):
    """Remplace `subprocess` dans un module par un faux minimal."""
    saved = module.subprocess
    module.subprocess = types.SimpleNamespace(
        run=recorder,
        Popen=popen or (lambda *a, **k: FakeProc("")),
        PIPE=-1, STDOUT=-2, DEVNULL=-3,
        TimeoutExpired=saved.TimeoutExpired,
        CalledProcessError=saved.CalledProcessError,
    )
    try:
        yield recorder
    finally:
        module.subprocess = saved


@contextlib.contextmanager
def no_sleep(*modules):
    """Neutralise time.sleep sans toucher à time.time."""
    saved = []
    for m in modules:
        saved.append((m, m.time))
        m.time = types.SimpleNamespace(sleep=lambda s: None,
                                       time=saved[-1][1].time)
    try:
        yield
    finally:
        for m, old in saved:
            m.time = old


class FakeProc:
    """Faux processus : sortie scriptée, terminaison observable."""

    def __init__(self, output="", returncode=0):
        self.stdout = io.StringIO(output)
        self._rc = returncode
        self.terminated = False
        self.killed = False
        self.pid = 4242

    def poll(self):
        return self._rc

    def wait(self, timeout=None):
        return self._rc

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakeDaemon(Daemon):
    """Daemon réel (tous les mixins), mais sans accès disque ni journal stdout.

    On instancie la vraie classe pour tester le vrai code — seuls la lecture
    de configuration et la journalisation sont détournées.
    """

    def __init__(self, config=None, **state):
        self.logs = []                       # avant super() : _load_config loggue
        self._cfg_override = {**DEFAULT_CONFIG, **(config or {})}
        super().__init__()
        for k, v in state.items():
            setattr(self, k, v)

    def _load_config(self):
        return dict(self._cfg_override)

    def _log(self, msg, level="INFO"):
        self.logs.append((level.strip(), str(msg)))

    # ── Assertions de lecture ────────────────────────────────────────────────

    def logged(self, needle, level=None):
        return [(l, m) for l, m in self.logs
                if needle in m and (level is None or l == level)]

    def has_log(self, needle, level=None):
        return bool(self.logged(needle, level))

    def log_dump(self):
        return "\n".join(f"  [{l}] {m}" for l, m in self.logs)


def provider(name, n_accounts=1, ovpn="/dev/null", obfuscate=True):
    """Fabrique une entrée `providers` valide."""
    import base64
    enc = (lambda s: base64.b64encode(s.encode()).decode()) if obfuscate else (lambda s: s)
    return {
        "name": name,
        "ovpn_file": ovpn,
        "accounts": [{"u": enc(f"user{i}"), "p": enc(f"pass{i}")}
                     for i in range(n_accounts)],
    }
