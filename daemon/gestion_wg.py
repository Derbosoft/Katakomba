"""
WireGuard géré (v4.2.0) : Katakomba enregistre lui-même sa clé WireGuard
sur un compte du fournisseur, sans fichier .conf.  IVPN pour l'instant.

Un fournisseur est géré quand sa configuration porte « wg_auto » :

  "wg_auto": {"service": "ivpn", "countries": ["NL", "CH"],
              "reserved_accounts": false}

Ses comptes OpenVPN sont les numéros de compte IVPN : les mêmes servent aux
deux transports.  Ses éventuels fichiers .conf sont alors ignorés.

Principe, pour un parc de PC qui partagent des comptes :

- une session (place d'appareil) par PC, sur un compte tiré au hasard, et
  gardée : ni redémarrage ni reconnexion n'appellent l'API ;
- elle ne change que sur une raison donnée par l'API (session fermée :
  compte remis à zéro par un autre PC, ou depuis le site ; compte inactif)
  ou par la configuration (compte retiré) ;
- un échec de connexion change de serveur, jamais de compte : la clé vaut
  pour tous les serveurs du fournisseur ;
- la clé est renouvelée toutes les semaines, sur la MÊME session ;
- compte plein : le suivant ; tous pleins : remise à zéro de l'un d'eux,
  seulement si les comptes sont réservés à Katakomba (ses autres appareils
  sont déconnectés ; les PC Katakomba s'en aperçoivent et se réenregistrent).

L'état (jeton de session, clé privée) vit dans STATE_DIR, en root seul, lié
à la machine par /etc/machine-id : une image disque clonée ne réutilise pas
la session de l'original.

Les échanges avec l'API passent par ivpn.py, lancé SANS AUCUN DROIT (il lit
ce que le réseau renvoie), à travers Tor.  Il ne voit jamais la clé privée.
Le .conf produit passe par validation.analyser_wg, comme un fichier importé.
"""

import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path

import ivpn
from validation import analyser_wg

from .core import SCRIPT_DIR, STATE_DIR, _deobf, _read_regular, _write_private

SESSION_FILE = STATE_DIR / "ivpn-session.json"
SERVEURS_FILE = STATE_DIR / "ivpn-serveurs.json"
MACHINE_ID = Path("/etc/machine-id")

SERVEURS_GERES = 3               # serveurs essayés à tour de rôle, villes différentes
SERVEURS_FRAICHEUR = 24 * 3600   # âge de la liste avant un nouveau téléchargement
ROTATION = 7 * 24 * 3600         # renouvellement de la clé
ROTATION_ALEA = 24 * 3600        # étalement, pour qu'un parc ne renouvelle pas d'un coup
ROTATION_REPORT = 6 * 3600       # renouvellement refusé : nouvel essai
PAUSE_API = 15 * 60              # API sans réponse utile : pas de nouvel appel avant
PAUSE_CAPTCHA = 60 * 60
API_DELAI = 150                  # secondes, assistant compris (Tor peut être lent)
LISTE_MAX = 2_000_000            # octets de la liste des serveurs en cache


def service_gere(fournisseur: dict) -> str:
    """« ivpn » si le fournisseur est géré (et a des comptes), sinon ""."""
    g = fournisseur.get("wg_auto")
    if (isinstance(g, dict) and g.get("service") == "ivpn"
            and fournisseur.get("accounts")):
        return "ivpn"
    return ""


def empreinte(texte: str) -> str:
    """Identifie un compte ou une machine sans les écrire en clair."""
    return hashlib.sha256(texte.encode()).hexdigest()[:16]


def _prochaine_rotation(depuis: float) -> float:
    return depuis + ROTATION + random.uniform(0, ROTATION_ALEA)


class GestionWgMixin:

    # ── Échanges avec l'API ──────────────────────────────────────────────────

    def _api_ivpn(self, requete: dict) -> dict:
        """Une requête à l'API d'IVPN, par ivpn.py sans aucun droit.  Le
        numéro de compte passe par l'entrée standard, jamais en argument
        (visible de tous dans /proc)."""
        ids = self._utilisateur_vpn()
        if ids is None:
            return {"ok": False, "code": ivpn.RESEAU, "message": "utilisateur absent"}
        cmd = [sys.executable, "-I", str(SCRIPT_DIR / "ivpn.py"), "api",
               "--socks", "127.0.0.1:9050"]
        try:
            r = subprocess.run(
                cmd, input=json.dumps(requete), capture_output=True, text=True,
                timeout=API_DELAI, user=ids[0], group=ids[1], extra_groups=[],
                cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                              "LANG": "C.UTF-8"})
        except subprocess.TimeoutExpired:
            return {"ok": False, "code": ivpn.RESEAU,
                    "message": f"API sans réponse en {API_DELAI} s"}
        except OSError as e:
            return {"ok": False, "code": ivpn.RESEAU,
                    "message": f"assistant IVPN impossible à lancer ({e})"}
        try:
            reponse = json.loads(r.stdout[:2 * ivpn.REPONSE_MAX])
        except ValueError:
            reponse = None
        if not isinstance(reponse, dict) or not isinstance(reponse.get("ok"), bool):
            # Jamais sa sortie d'erreur : elle pourrait citer la requête.
            return {"ok": False, "code": ivpn.RESEAU,
                    "message": "réponse illisible de l'assistant IVPN"}
        return reponse

    # ── État de la session, sur disque ───────────────────────────────────────

    def _machine(self) -> str:
        try:
            return hashlib.sha256(MACHINE_ID.read_bytes().strip()).hexdigest()[:16]
        except OSError:
            return ""

    def _ivpn_lire(self):
        """L'état de la session gérée, ou None (absent ou illisible)."""
        try:
            etat = json.loads(_read_regular(SESSION_FILE, 65536))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            self._log("IVPN : état de la session illisible — nouvel "
                      "enregistrement.", "WARN")
            return None
        texte = ("machine", "compte", "jeton", "cle", "publique", "adresse")
        if (not isinstance(etat, dict)
                or not all(isinstance(etat.get(c), str) and etat[c] for c in texte)
                or not all(isinstance(etat.get(c), (int, float))
                           for c in ("cle_du", "rotation"))):
            self._log("IVPN : état de la session incomplet — nouvel "
                      "enregistrement.", "WARN")
            return None
        return etat

    def _ivpn_ecrire(self, etat: dict) -> bool:
        try:
            _write_private(SESSION_FILE, json.dumps(etat) + "\n", dir_mode=0o755)
        except OSError as e:
            self._log(f"IVPN : état de la session impossible à enregistrer ({e}).",
                      "ERROR")
            return False
        self._ivpn_etat = etat
        return True

    def _ivpn_effacer(self):
        SESSION_FILE.unlink(missing_ok=True)
        self._ivpn_etat = None

    # ── Session : ouverture, renouvellement, vérification ────────────────────

    def _comptes_ivpn(self, p: dict) -> list:
        """[(index, numéro de compte)] : les identifiants OpenVPN du
        fournisseur, qui sont ses numéros de compte IVPN."""
        return [(i, _deobf(a.get("u", "")).strip())
                for i, a in enumerate(p.get("accounts", [])) if isinstance(a, dict)]

    def _ivpn_ouvrir(self, i: int, compte: str, force: bool):
        """Ouvre une session sur le compte i ; l'état enregistré, ou None
        (le code de l'API reste dans self._ivpn_code)."""
        try:
            privee, publique = ivpn.generer_cles()
        except ImportError:
            self._log("IVPN : python3-cryptography manque pour créer une clé "
                      "WireGuard (sudo apt install python3-cryptography).", "ERROR")
            self._ivpn_code = ivpn.RESEAU
            return None
        r = self._api_ivpn({"action": "nouvelle", "compte": compte,
                            "publique": publique, "force": force})
        if not r["ok"] or not isinstance(r.get("jeton"), str) \
                or not isinstance(r.get("adresse"), str):
            self._ivpn_code = r.get("code", ivpn.RESEAU)
            self._log(f"IVPN, compte {i+1} : {r.get('message', 'réponse inattendue')}.",
                      "WARN")
            return None
        maintenant = time.time()
        etat = {"machine": self._machine(), "compte": empreinte(compte),
                "jeton": r["jeton"], "cle": privee, "publique": publique,
                "adresse": r["adresse"], "cle_du": maintenant,
                "rotation": _prochaine_rotation(maintenant)}
        if not self._ivpn_ecrire(etat):
            # Une session qu'on ne retrouverait pas au prochain démarrage
            # occuperait une place pour rien : on la rend tout de suite.
            self._api_ivpn({"action": "fermer", "jeton": r["jeton"]})
            self._ivpn_code = ivpn.RESEAU
            return None
        self._log(f"IVPN : session ouverte sur le compte {i+1} — une place "
                  "d'appareil, gardée par ce PC jusqu'à sa désinstallation.", "OK")
        return etat

    def _ivpn_enregistrer(self, p: dict):
        """Une session sur l'un des comptes, tirés au hasard (un parc se
        répartit ainsi de lui-même).  None si aucun ne l'accepte."""
        comptes = [(i, c) for i, c in self._comptes_ivpn(p) if c]
        random.shuffle(comptes)
        pleins = []
        for i, compte in comptes:
            etat = self._ivpn_ouvrir(i, compte, force=False)
            if etat:
                return etat
            if self._ivpn_code == ivpn.COMPTE_PLEIN:
                pleins.append((i, compte))
            elif self._ivpn_code in ivpn.CAPTCHA:
                self._wg_gere_pause = time.time() + PAUSE_CAPTCHA
                return None
            elif self._ivpn_code == ivpn.RESEAU:
                # API injoignable : les autres comptes ne feraient pas mieux.
                self._wg_gere_pause = time.time() + PAUSE_API
                return None
        if pleins and p["wg_auto"].get("reserved_accounts"):
            i, compte = random.choice(pleins)
            self._log(f"IVPN : tous les comptes sont pleins — remise à zéro du "
                      f"compte {i+1} (comptes réservés à Katakomba) : ses autres "
                      "appareils sont déconnectés et se réenregistreront.", "WARN")
            etat = self._ivpn_ouvrir(i, compte, force=True)
            if etat:
                return etat
        elif pleins:
            self._log("IVPN : tous les comptes utilisables sont pleins. Ajoutez un "
                      "compte, libérez une place sur le site d'IVPN, ou, si ces "
                      "comptes ne servent qu'à Katakomba, cochez « Comptes réservés "
                      "à Katakomba ».", "ERROR")
        self._wg_gere_pause = time.time() + PAUSE_API
        return None

    def _ivpn_renouveler(self, etat: dict):
        """Nouvelle clé sur la même session.  L'état (nouveau, ou l'ancien si
        le renouvellement est reporté), ou None si la session n'existe plus."""
        try:
            privee, publique = ivpn.generer_cles()
        except ImportError:
            return etat
        r = self._api_ivpn({"action": "cle", "jeton": etat["jeton"],
                            "publique": publique, "active": etat["publique"]})
        maintenant = time.time()
        if r["ok"] and isinstance(r.get("adresse"), str):
            neuf = {**etat, "cle": privee, "publique": publique,
                    "adresse": r["adresse"], "cle_du": maintenant,
                    "rotation": _prochaine_rotation(maintenant)}
            # Clé changée chez IVPN mais pas sur le disque (disque plein) :
            # la vérification qui suit un échec la resynchronise.
            self._ivpn_ecrire(neuf)
            self._log("IVPN : clé WireGuard renouvelée (même session, même "
                      "place d'appareil).", "OK")
            return neuf
        if r.get("code") == ivpn.SESSION_INCONNUE:
            self._log("IVPN : session fermée côté IVPN (compte remis à zéro, ou "
                      "depuis le site) — nouvel enregistrement.", "WARN")
            self._ivpn_effacer()
            return None
        self._log(f"IVPN : renouvellement de la clé reporté "
                  f"({r.get('message', '?')}).", "WARN")
        etat = {**etat, "rotation": maintenant + ROTATION_REPORT}
        self._ivpn_ecrire(etat)
        return etat

    def _ivpn_session(self, p: dict):
        """La session de ce PC, ouverte ou renouvelée au besoin ; None si
        aucune n'est possible pour l'instant."""
        comptes = {empreinte(c): i for i, c in self._comptes_ivpn(p) if c}
        etat = self._ivpn_lire()
        if etat and etat["machine"] != self._machine():
            self._log("IVPN : session enregistrée par une autre machine (image "
                      "disque clonée ?) — ignorée sans la fermer, nouvel "
                      "enregistrement pour ce PC.", "WARN")
            self._ivpn_effacer()
            etat = None
        if etat and etat["compte"] not in comptes:
            self._log("IVPN : le compte de la session n'est plus dans la "
                      "configuration — session fermée, nouvel enregistrement.", "WARN")
            self._api_ivpn({"action": "fermer", "jeton": etat["jeton"]})
            self._ivpn_effacer()
            etat = None
        if etat and time.time() >= etat["rotation"]:
            etat = self._ivpn_renouveler(etat)
        if etat is None:
            etat = self._ivpn_enregistrer(p)
        self._ivpn_etat = etat
        return etat

    def _ivpn_serveurs(self):
        """La liste des serveurs : celle du cache tant qu'elle a moins d'un
        jour, sinon téléchargée ; l'ancienne si le téléchargement échoue."""
        cache = None
        try:
            brut = json.loads(_read_regular(SERVEURS_FILE, LISTE_MAX))
            if isinstance(brut, dict) and isinstance(brut.get("liste"), dict):
                cache = brut
        except (OSError, ValueError):
            pass
        if cache and 0 <= time.time() - cache.get("le", 0) < SERVEURS_FRAICHEUR:
            return cache["liste"]
        r = self._api_ivpn({"action": "serveurs"})
        if r["ok"] and isinstance(r.get("liste"), dict):
            try:
                _write_private(SERVEURS_FILE, json.dumps(
                    {"le": time.time(), "liste": r["liste"]}), dir_mode=0o755)
            except OSError:
                pass
            return r["liste"]
        if cache:
            self._log(f"IVPN : liste des serveurs non mise à jour "
                      f"({r.get('message', '?')}) — ancienne liste.", "WARN")
            return cache["liste"]
        self._log(f"IVPN : liste des serveurs indisponible ({r.get('message', '?')}).",
                  "WARN")
        self._wg_gere_pause = time.time() + PAUSE_API
        return None

    # ── Pour la boucle VPN ───────────────────────────────────────────────────

    def _wg_gere_reglages(self, p: dict, idx: int) -> tuple:
        """(réglages, nom, issue) du serveur n° idx du fournisseur géré.
        issue : "" (prêt), « indisponible » (aucune session ou aucune liste
        de serveurs pour l'instant : l'étape suivante peut servir), « refus »
        (ce serveur-là est refusé par la validation)."""
        reste = self._wg_gere_pause - time.time()
        if reste > 0:
            self._log(f"IVPN : API en pause après un échec, nouvel essai dans "
                      f"{int(reste) // 60 + 1} min.", "INFO")
            return None, "", "indisponible"
        etat = self._ivpn_session(p)
        if etat is None:
            return None, "", "indisponible"
        liste = self._ivpn_serveurs()
        if liste is None:
            return None, "", "indisponible"
        if not self._ivpn_hotes:
            pays = p["wg_auto"].get("countries") or []
            self._ivpn_hotes = ivpn.choisir_hotes(
                liste, [c for c in pays if isinstance(c, str)], SERVEURS_GERES)
        if not 0 <= idx < len(self._ivpn_hotes):
            if self._ivpn_hotes:
                # Moins de serveurs que d'essais prévus (un seul pays, petit) :
                # tous ont été essayés, l'étape suivante peut servir.
                self._log(f"IVPN : les {len(self._ivpn_hotes)} serveur(s) des pays "
                          "choisis ont été essayés.", "WARN")
            else:
                self._log("IVPN : aucun serveur WireGuard + V2Ray dans la liste.", "WARN")
            return None, "", "indisponible"
        passerelle, hote = self._ivpn_hotes[idx]
        nom = f"IVPN {hote.get('hostname', '?')}"
        try:
            texte = ivpn.config_wg(etat["cle"], etat["adresse"], liste, passerelle, hote)
        except (ivpn.ErreurIvpn, KeyError, TypeError, AttributeError) as e:
            self._log(f"IVPN : liste des serveurs inattendue ({e}).", "WARN")
            return None, nom, "refus"
        reglages, refus, _avert = analyser_wg(texte)
        for m in refus:
            self._log(f"[provider] {nom} : {m}", "ERROR")
        if refus:
            return None, nom, "refus"
        return reglages, nom, ""

    def _wg_gere_echec(self) -> bool:
        """Connexion sans poignée de main sur un fournisseur géré : la
        session existe-t-elle encore ?  Vrai si elle a disparu (un nouvel
        enregistrement suit aussitôt) ; faux si le serveur reste en cause."""
        etat = self._ivpn_lire()
        if etat is None:
            return False
        r = self._api_ivpn({"action": "statut", "jeton": etat["jeton"]})
        if not r["ok"]:
            if r.get("code") == ivpn.SESSION_INCONNUE:
                self._log("IVPN : session fermée (compte remis à zéro par un autre "
                          "PC, ou depuis le site) — nouvel enregistrement.", "WARN")
                self._ivpn_effacer()
                self._wg_gere_pause = 0.0
                return True
            return False
        if not r.get("actif"):
            self._log("IVPN : abonnement du compte inactif — session fermée, "
                      "un autre compte va être essayé.", "WARN")
            self._api_ivpn({"action": "fermer", "jeton": etat["jeton"]})
            self._ivpn_effacer()
            return True
        if not self._ivpn_resynchro:
            # Session active : la clé connue d'IVPN peut différer de la nôtre
            # (renouvellement interrompu par une coupure).  On la repose, une
            # fois par série d'échecs.
            self._ivpn_resynchro = True
            r = self._api_ivpn({"action": "cle", "jeton": etat["jeton"],
                                "publique": etat["publique"], "active": etat["publique"]})
            if r["ok"] and isinstance(r.get("adresse"), str) \
                    and r["adresse"] != etat["adresse"]:
                self._ivpn_ecrire({**etat, "adresse": r["adresse"]})
                return True
        return False

    def _wg_gere_menage(self):
        """Une fois par démarrage, Tor prêt : une session gérée dont plus
        aucun fournisseur ne veut (gestion désactivée, fournisseur retiré)
        est fermée, pour rendre sa place au compte."""
        if self._ivpn_menage_fait:
            return
        self._ivpn_menage_fait = True
        if any(service_gere(p) for p in self.config.get("providers", [])):
            return
        etat = self._ivpn_lire()
        if etat is None:
            return
        if etat["machine"] == self._machine():
            r = self._api_ivpn({"action": "fermer", "jeton": etat["jeton"]})
            if not r["ok"]:
                self._log(f"IVPN : session gérée non fermée ({r.get('message', '?')}) "
                          "— nouvel essai au prochain démarrage.", "WARN")
                return
            self._log("IVPN : WireGuard géré désactivé — session fermée, place "
                      "rendue au compte.", "OK")
        self._ivpn_effacer()

    def _wg_gere_statut(self) -> dict:
        """Pour le statut : compte (numéro affiché) et date de la clé, rien
        de secret."""
        etat = self._ivpn_etat
        for p in self.config.get("providers", []):
            if etat and service_gere(p):
                for i, compte in self._comptes_ivpn(p):
                    if compte and empreinte(compte) == etat.get("compte"):
                        return {"service": "ivpn", "provider": p.get("name", ""),
                                "account": i + 1, "key_since": int(etat["cle_du"])}
        return {}
