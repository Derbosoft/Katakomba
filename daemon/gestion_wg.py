"""
WireGuard géré : Katakomba enregistre lui-même sa clé WireGuard sur un
compte du fournisseur, sans fichier .conf.  IVPN (v4.2.0) et Mullvad (v4.3.0).

Un fournisseur est géré quand sa configuration porte « wg_auto » :

  "wg_auto": {"service": "ivpn" | "mullvad", "countries": ["NL", "CH"],
              "reserved_accounts": false}

Ses comptes (« accounts », champ « u ») sont les numéros de compte : chez
IVPN, ce sont aussi les identifiants OpenVPN ; Mullvad n'a plus d'OpenVPN.
Ses éventuels fichiers .conf sont alors ignorés.

Principe, pour un parc de PC qui partagent des comptes :

- une place d'appareil par PC (une « session » IVPN, un « appareil »
  Mullvad), sur un compte tiré au hasard, et gardée : ni redémarrage ni
  reconnexion n'appellent l'API ;
- elle ne change que sur une raison donnée par l'API (place supprimée :
  compte remis à zéro, appareil supprimé par un autre PC ou depuis le site ;
  compte inactif) ou par la configuration (compte retiré) ;
- un échec de connexion change de serveur, jamais de compte : la clé vaut
  pour tous les serveurs du fournisseur ;
- chaque connexion tire un serveur au hasard dans les pays choisis, autre
  que le précédent : au démarrage, et à chaque reconnexion après une
  coupure (comme « remote-random » d'OpenVPN).  Aucun appel à l'API : la
  liste des serveurs est en cache (7 jours ; 24 h après un serveur muet) ;
- la clé est renouvelée toutes les semaines.  IVPN : sur la même session.
  Mullvad : par un appareil neuf, l'ancien supprimé ensuite ; l'API ne
  donnant que la date de création d'un appareil, elle devient sa preuve de
  vie ;
- compte plein : le suivant.  Si les comptes sont réservés à Katakomba, une
  place se récupère : Mullvad, appareils de plus de 3 semaines supprimés
  (PC disparus) ; IVPN, qui ne montre pas les autres sessions, remise à
  zéro d'un compte en dernier recours (ses autres appareils sont
  déconnectés ; les PC Katakomba s'en aperçoivent et se réenregistrent).

L'état (identifiant de la place, clé privée) vit dans STATE_DIR, en root
seul, lié à la machine par /etc/machine-id : une image disque clonée ne
réutilise pas la place de l'original.  Le numéro de compte n'y figure qu'en
empreinte.

Les échanges avec l'API passent par ivpn.py ou mullvad.py, lancés SANS AUCUN
DROIT (ils lisent ce que le réseau renvoie), à travers Tor.  Ils ne voient
jamais la clé privée.  Le .conf produit passe par validation.analyser_wg,
comme un fichier importé.
"""

import hashlib
import json
import random
import subprocess
import sys
import time
from pathlib import Path

import ivpn
import mullvad
from validation import analyser_wg

from .core import SCRIPT_DIR, STATE_DIR, _deobf, _read_regular, _write_private

SERVICES = {"ivpn": ivpn, "mullvad": mullvad}
NOMS = {"ivpn": "IVPN", "mullvad": "Mullvad"}
MACHINE_ID = Path("/etc/machine-id")

SERVEURS_GERES = 3               # serveurs essayés à tour de rôle, villes différentes
SERVEURS_FRAICHEUR = 7 * 24 * 3600   # âge de la liste avant un nouveau téléchargement
SERVEURS_DOUTE     = 24 * 3600       # après un serveur muet : la liste a pu changer
ROTATION = 7 * 24 * 3600         # renouvellement de la clé
ROTATION_ALEA = 24 * 3600        # étalement, pour qu'un parc ne renouvelle pas d'un coup
ROTATION_REPORT = 6 * 3600       # renouvellement refusé : nouvel essai
# Mullvad : un appareil plus vieux a manqué trois renouvellements ; son PC a
# disparu (réinstallé, jeté, éteint depuis des semaines).
APPAREIL_MORT = 3 * ROTATION + ROTATION_ALEA
PAUSE_API = 15 * 60              # API sans réponse utile : pas de nouvel appel avant
PAUSE_CAPTCHA = 60 * 60
API_DELAI = 150                  # secondes, assistant compris (Tor peut être lent)
LISTE_MAX = 2_000_000            # octets de la liste des serveurs en cache


def service_gere(fournisseur: dict) -> str:
    """Le service (« ivpn », « mullvad ») si le fournisseur est géré et a des
    comptes, sinon ""."""
    g = fournisseur.get("wg_auto")
    if (isinstance(g, dict) and g.get("service") in SERVICES
            and fournisseur.get("accounts")):
        return g["service"]
    return ""


def fichier_session(service: str) -> Path:
    return STATE_DIR / f"{service}-session.json"


def fichier_serveurs(service: str) -> Path:
    return STATE_DIR / f"{service}-serveurs.json"


def empreinte(texte: str) -> str:
    """Identifie un compte ou une machine sans les écrire en clair."""
    return hashlib.sha256(texte.encode()).hexdigest()[:16]


def _prochaine_rotation(depuis: float) -> float:
    return depuis + ROTATION + random.uniform(0, ROTATION_ALEA)


class GestionWgMixin:

    # ── Échanges avec l'API ──────────────────────────────────────────────────

    def _api_wg(self, service: str, requete: dict) -> dict:
        """Une requête à l'API du service, par son assistant sans aucun
        droit.  Le numéro de compte passe par l'entrée standard, jamais en
        argument (visible de tous dans /proc)."""
        ids = self._utilisateur_vpn()
        if ids is None:
            return {"ok": False, "code": ivpn.RESEAU, "message": "utilisateur absent"}
        cmd = [sys.executable, "-I", str(SCRIPT_DIR / f"{service}.py"), "api",
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
                    "message": f"assistant {NOMS[service]} impossible à lancer ({e})"}
        try:
            reponse = json.loads(r.stdout[:2 * ivpn.REPONSE_MAX])
        except ValueError:
            reponse = None
        if not isinstance(reponse, dict) or not isinstance(reponse.get("ok"), bool):
            # Jamais sa sortie d'erreur : elle pourrait citer la requête.
            return {"ok": False, "code": ivpn.RESEAU,
                    "message": f"réponse illisible de l'assistant {NOMS[service]}"}
        return reponse

    # ── État de la place, sur disque ─────────────────────────────────────────

    def _machine(self) -> str:
        try:
            return hashlib.sha256(MACHINE_ID.read_bytes().strip()).hexdigest()[:16]
        except OSError:
            return ""

    def _wg_lire(self, service: str):
        """L'état de la place gérée du service, ou None (absent ou illisible)."""
        nom = NOMS[service]
        try:
            etat = json.loads(_read_regular(fichier_session(service), 65536))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            self._log(f"{nom} : état de la place gérée illisible — nouvel "
                      "enregistrement.", "WARN")
            return None
        texte = ("machine", "compte", "jeton", "cle", "publique", "adresse")
        if (not isinstance(etat, dict)
                or not all(isinstance(etat.get(c), str) and etat[c] for c in texte)
                or not all(isinstance(etat.get(c), (int, float))
                           for c in ("cle_du", "rotation"))):
            self._log(f"{nom} : état de la place gérée incomplet — nouvel "
                      "enregistrement.", "WARN")
            return None
        return etat

    def _wg_ecrire(self, service: str, etat: dict) -> bool:
        try:
            _write_private(fichier_session(service), json.dumps(etat) + "\n",
                           dir_mode=0o755)
        except OSError as e:
            self._log(f"{NOMS[service]} : état de la place gérée impossible à "
                      f"enregistrer ({e}).", "ERROR")
            return False
        self._wg_etats[service] = etat
        return True

    def _wg_effacer(self, service: str):
        fichier_session(service).unlink(missing_ok=True)
        self._wg_etats.pop(service, None)

    # ── Comptes ──────────────────────────────────────────────────────────────

    def _comptes_wg(self, p: dict) -> list:
        """[(index, numéro de compte)] du fournisseur (champ « u »)."""
        return [(i, _deobf(a.get("u", "")).strip())
                for i, a in enumerate(p.get("accounts", [])) if isinstance(a, dict)]

    def _compte_par_empreinte(self, emp: str) -> str:
        """Le numéro de compte d'empreinte `emp`, chez n'importe quel
        fournisseur : Mullvad le demande même pour supprimer un appareil."""
        for p in self.config.get("providers", []):
            for _i, compte in self._comptes_wg(p) if isinstance(p, dict) else []:
                if compte and empreinte(compte) == emp:
                    return compte
        return ""

    # ── Place : ouverture, renouvellement, vérification ──────────────────────

    def _wg_ouvrir(self, service: str, i: int, compte: str, force=False,
                   renouvellement=False):
        """Ouvre une place sur le compte i ; l'état enregistré, ou None
        (le code de l'API reste dans self._wg_code)."""
        nom = NOMS[service]
        try:
            privee, publique = ivpn.generer_cles()
        except ImportError:
            self._log(f"{nom} : python3-cryptography manque pour créer une clé "
                      "WireGuard (sudo apt install python3-cryptography).", "ERROR")
            self._wg_code = ivpn.RESEAU
            return None
        r = self._api_wg(service, {"action": "nouvelle", "compte": compte,
                                   "publique": publique, "force": force})
        if not r["ok"] or not isinstance(r.get("jeton"), str) \
                or not isinstance(r.get("adresse"), str):
            self._wg_code = r.get("code", ivpn.RESEAU)
            self._log(f"{nom}, compte {i+1} : {r.get('message', 'réponse inattendue')}.",
                      "WARN")
            return None
        maintenant = time.time()
        etat = {"machine": self._machine(), "compte": empreinte(compte),
                "jeton": r["jeton"], "cle": privee, "publique": publique,
                "adresse": r["adresse"], "cle_du": maintenant,
                "rotation": _prochaine_rotation(maintenant)}
        if not self._wg_ecrire(service, etat):
            # Une place qu'on ne retrouverait pas au prochain démarrage
            # resterait prise pour rien : on la rend tout de suite.
            self._api_wg(service, {"action": "fermer", "jeton": r["jeton"],
                                   "compte": compte})
            self._wg_code = ivpn.RESEAU
            return None
        if not renouvellement:
            self._log(f"{nom} : session ouverte sur le compte {i+1} — une place "
                      "d'appareil, gardée par ce PC jusqu'à sa désinstallation.", "OK")
        return etat

    def _wg_nettoyer(self, i: int, compte: str) -> int:
        """Mullvad, comptes réservés : supprime les appareils du compte qui
        ont manqué trois renouvellements (PC disparus).  Leur âge se compte à
        l'heure de Mullvad.  Renvoie le nombre supprimé."""
        r = self._api_wg("mullvad", {"action": "appareils", "compte": compte})
        if not r["ok"] or not isinstance(r.get("appareils"), list):
            return 0
        maintenant = r.get("maintenant") or time.time()
        morts = [a["jeton"] for a in r["appareils"]
                 if isinstance(a, dict) and isinstance(a.get("cree"), int)
                 and isinstance(a.get("jeton"), str)
                 and maintenant - a["cree"] > APPAREIL_MORT]
        n = sum(self._api_wg("mullvad", {"action": "fermer", "jeton": j,
                                         "compte": compte})["ok"] for j in morts)
        if n:
            self._log(f"Mullvad, compte {i+1} : {n} appareil(s) de plus de 3 "
                      "semaines supprimé(s) — PC disparus (comptes réservés à "
                      "Katakomba).", "WARN")
        return n

    def _wg_enregistrer(self, p: dict, service: str):
        """Une place sur l'un des comptes, tirés au hasard (un parc se
        répartit ainsi de lui-même).  None si aucun ne l'accepte."""
        nom = NOMS[service]
        reserves = bool(p["wg_auto"].get("reserved_accounts"))
        comptes = [(i, c) for i, c in self._comptes_wg(p) if c]
        random.shuffle(comptes)
        pleins = []
        for i, compte in comptes:
            etat = self._wg_ouvrir(service, i, compte)
            if etat:
                return etat
            if self._wg_code == ivpn.COMPTE_PLEIN:
                if service == "mullvad" and reserves and self._wg_nettoyer(i, compte):
                    etat = self._wg_ouvrir(service, i, compte)
                    if etat:
                        return etat
                pleins.append((i, compte))
            elif self._wg_code in ivpn.CAPTCHA:
                self._wg_pauses[service] = time.time() + PAUSE_CAPTCHA
                return None
            elif self._wg_code == ivpn.RESEAU:
                # API injoignable : les autres comptes ne feraient pas mieux.
                self._wg_pauses[service] = time.time() + PAUSE_API
                return None
        if pleins and reserves and service == "ivpn":
            i, compte = random.choice(pleins)
            self._log(f"IVPN : tous les comptes sont pleins — remise à zéro du "
                      f"compte {i+1} (comptes réservés à Katakomba) : ses autres "
                      "appareils sont déconnectés et se réenregistreront.", "WARN")
            etat = self._wg_ouvrir(service, i, compte, force=True)
            if etat:
                return etat
        elif pleins and reserves:
            self._log(f"{nom} : tous les comptes utilisables sont pleins, sans "
                      "appareil de PC disparu à supprimer. Ajoutez un compte.", "ERROR")
        elif pleins:
            self._log(f"{nom} : tous les comptes utilisables sont pleins. Ajoutez un "
                      f"compte, libérez une place sur le site de {nom}, ou, si ces "
                      "comptes ne servent qu'à Katakomba, cochez « Comptes réservés "
                      "à Katakomba ».", "ERROR")
        self._wg_pauses[service] = time.time() + PAUSE_API
        return None

    def _wg_renouveler(self, service: str, etat: dict, i: int, compte: str):
        """Nouvelle clé : l'état (nouveau, ou l'ancien si le renouvellement
        est reporté), ou None si la place n'existe plus.

        IVPN : clé changée sur la même session.  Mullvad : appareil neuf,
        puis l'ancien supprimé — sa date de création prouve que ce PC vit."""
        nom = NOMS[service]
        maintenant = time.time()
        if service == "mullvad":
            neuf = self._wg_ouvrir(service, i, compte, renouvellement=True)
            if neuf is None and self._wg_code == ivpn.COMPTE_PLEIN:
                # Pas de place pour les deux : l'ancien d'abord.
                self._api_wg(service, {"action": "fermer", "jeton": etat["jeton"],
                                       "compte": compte})
                self._wg_effacer(service)
                return None
            if neuf is not None:
                self._api_wg(service, {"action": "fermer", "jeton": etat["jeton"],
                                       "compte": compte})
                self._log("Mullvad : clé WireGuard renouvelée (appareil neuf, "
                          "l'ancien supprimé).", "OK")
                return neuf
            r = {"code": self._wg_code, "message": "appareil neuf refusé"}
        else:
            try:
                privee, publique = ivpn.generer_cles()
            except ImportError:
                return etat
            r = self._api_wg(service, {"action": "cle", "jeton": etat["jeton"],
                                       "publique": publique, "active": etat["publique"],
                                       "compte": compte})
            if r["ok"] and isinstance(r.get("adresse"), str):
                neuf = {**etat, "cle": privee, "publique": publique,
                        "adresse": r["adresse"], "cle_du": maintenant,
                        "rotation": _prochaine_rotation(maintenant)}
                # Clé changée chez IVPN mais pas sur le disque (disque plein) :
                # la vérification qui suit un échec la resynchronise.
                self._wg_ecrire(service, neuf)
                self._log("IVPN : clé WireGuard renouvelée (même session, même "
                          "place d'appareil).", "OK")
                return neuf
        if r.get("code") == ivpn.SESSION_INCONNUE:
            self._log(f"{nom} : session fermée côté {nom} (compte remis à zéro, ou "
                      "depuis le site) — nouvel enregistrement.", "WARN")
            self._wg_effacer(service)
            return None
        self._log(f"{nom} : renouvellement de la clé reporté "
                  f"({r.get('message', '?')}).", "WARN")
        etat = {**etat, "rotation": maintenant + ROTATION_REPORT}
        self._wg_ecrire(service, etat)
        return etat

    def _wg_session(self, p: dict, service: str):
        """La place de ce PC, ouverte ou renouvelée au besoin ; None si aucune
        n'est possible pour l'instant."""
        nom = NOMS[service]
        comptes = {empreinte(c): (i, c) for i, c in self._comptes_wg(p) if c}
        etat = self._wg_lire(service)
        if etat and etat["machine"] != self._machine():
            self._log(f"{nom} : session enregistrée par une autre machine (image "
                      "disque clonée ?) — ignorée sans la fermer, nouvel "
                      "enregistrement pour ce PC.", "WARN")
            self._wg_effacer(service)
            etat = None
        if etat and etat["compte"] not in comptes:
            self._log(f"{nom} : le compte de la session n'est plus dans la "
                      "configuration — session fermée, nouvel enregistrement.", "WARN")
            self._api_wg(service, {"action": "fermer", "jeton": etat["jeton"],
                                   "compte": self._compte_par_empreinte(etat["compte"])})
            self._wg_effacer(service)
            etat = None
        if etat and time.time() >= etat["rotation"]:
            etat = self._wg_renouveler(service, etat, *comptes[etat["compte"]])
        if etat is None:
            etat = self._wg_enregistrer(p, service)
        if etat is not None:
            self._wg_etats[service] = etat
        return etat

    def _wg_serveurs(self, service: str):
        """La liste des serveurs : celle du cache tant qu'elle a moins de 7
        jours (24 h après un serveur muet : il a pu être retiré), sinon
        téléchargée ; l'ancienne si le téléchargement échoue.  Elle n'est
        demandée qu'à une connexion, jamais par une minuterie."""
        nom = NOMS[service]
        cache = None
        try:
            brut = json.loads(_read_regular(fichier_serveurs(service), LISTE_MAX))
            if isinstance(brut, dict) and isinstance(brut.get("liste"), dict):
                cache = brut
        except (OSError, ValueError):
            pass
        fraicheur = SERVEURS_DOUTE if self._wg_liste_douteuse else SERVEURS_FRAICHEUR
        if cache and 0 <= time.time() - cache.get("le", 0) < fraicheur:
            return cache["liste"]
        r = self._api_wg(service, {"action": "serveurs"})
        if r["ok"] and isinstance(r.get("liste"), dict):
            self._wg_liste_douteuse = False
            try:
                _write_private(fichier_serveurs(service), json.dumps(
                    {"le": time.time(), "liste": r["liste"]}), dir_mode=0o755)
            except OSError:
                pass
            return r["liste"]
        if cache:
            self._log(f"{nom} : liste des serveurs non mise à jour "
                      f"({r.get('message', '?')}) — ancienne liste.", "WARN")
            return cache["liste"]
        self._log(f"{nom} : liste des serveurs indisponible ({r.get('message', '?')}).",
                  "WARN")
        self._wg_pauses[service] = time.time() + PAUSE_API
        return None

    # ── Pour la boucle VPN ───────────────────────────────────────────────────

    def _wg_gere_reglages(self, p: dict, idx: int) -> tuple:
        """(réglages, nom, issue) du serveur n° idx du fournisseur géré.
        issue : "" (prêt), « indisponible » (aucune place ou aucune liste de
        serveurs pour l'instant : l'étape suivante peut servir), « refus »
        (ce serveur-là est refusé par la validation)."""
        service = service_gere(p)
        nom_service, module = NOMS[service], SERVICES[service]
        reste = self._wg_pauses.get(service, 0.0) - time.time()
        if reste > 0:
            self._log(f"{nom_service} : API en pause après un échec, nouvel essai "
                      f"dans {int(reste) // 60 + 1} min.", "INFO")
            return None, "", "indisponible"
        etat = self._wg_session(p, service)
        if etat is None:
            return None, "", "indisponible"
        liste = self._wg_serveurs(service)
        if liste is None:
            return None, "", "indisponible"
        if not self._wg_hotes:
            pays = p["wg_auto"].get("countries") or []
            # Un de plus que nécessaire : le serveur de la connexion
            # précédente est écarté, sauf s'il est le seul.
            hotes = module.choisir_hotes(
                liste, [c for c in pays if isinstance(c, str)], SERVEURS_GERES + 1)
            autres = [h for h in hotes if module.nom_hote(*h) != self._wg_dernier]
            self._wg_hotes = (autres or hotes)[:SERVEURS_GERES]
        if not 0 <= idx < len(self._wg_hotes):
            if self._wg_hotes:
                # Moins de serveurs que d'essais prévus (un seul pays, petit) :
                # tous ont été essayés, l'étape suivante peut servir.
                self._log(f"{nom_service} : les {len(self._wg_hotes)} serveur(s) des "
                          "pays choisis ont été essayés.", "WARN")
            else:
                self._log(f"{nom_service} : aucun serveur utilisable dans la liste.",
                          "WARN")
            return None, "", "indisponible"
        hote = self._wg_hotes[idx]
        try:
            self._wg_dernier = module.nom_hote(*hote)
            nom = f"{nom_service} {self._wg_dernier}"
            texte = module.config_wg(etat["cle"], etat["adresse"], liste, *hote)
        except (ivpn.ErreurIvpn, KeyError, TypeError, AttributeError) as e:
            self._log(f"{nom_service} : liste des serveurs inattendue ({e}).", "WARN")
            return None, nom_service, "refus"
        reglages, refus, _avert = analyser_wg(texte)
        for m in refus:
            self._log(f"[provider] {nom} : {m}", "ERROR")
        if refus:
            return None, nom, "refus"
        return reglages, nom, ""

    def _wg_gere_echec(self, p: dict) -> bool:
        """Connexion sans poignée de main sur un fournisseur géré : la place
        existe-t-elle encore ?  Vrai si elle a disparu ou changé (un nouvel
        essai suit aussitôt) ; faux si le serveur reste en cause."""
        service = service_gere(p)
        nom = NOMS[service]
        self._wg_liste_douteuse = True       # ce serveur a peut-être disparu
        etat = self._wg_lire(service)
        if etat is None:
            return False
        compte = self._compte_par_empreinte(etat["compte"])
        r = self._api_wg(service, {"action": "statut", "jeton": etat["jeton"],
                                   "compte": compte})
        if not r["ok"]:
            if r.get("code") == ivpn.SESSION_INCONNUE:
                self._log(f"{nom} : session fermée (compte remis à zéro par un autre "
                          "PC, ou depuis le site) — nouvel enregistrement.", "WARN")
                self._wg_effacer(service)
                self._wg_pauses[service] = 0.0
                return True
            return False
        if not r.get("actif"):
            self._log(f"{nom} : abonnement du compte inactif — session fermée, "
                      "un autre compte va être essayé.", "WARN")
            self._api_wg(service, {"action": "fermer", "jeton": etat["jeton"],
                                   "compte": compte})
            self._wg_effacer(service)
            return True
        if r.get("publique") == etat["publique"]:
            return False                         # Mullvad : la clé est la bonne
        if not self._wg_resynchro:
            # Session active : la clé connue du service peut différer de la
            # nôtre (renouvellement interrompu par une coupure).  On la
            # repose, une fois par série d'échecs.
            self._wg_resynchro = True
            r = self._api_wg(service, {"action": "cle", "jeton": etat["jeton"],
                                       "publique": etat["publique"],
                                       "active": etat["publique"], "compte": compte})
            if r["ok"] and isinstance(r.get("adresse"), str) \
                    and r["adresse"] != etat["adresse"]:
                self._wg_ecrire(service, {**etat, "adresse": r["adresse"]})
                return True
        return False

    def _wg_gere_menage(self):
        """Une fois par démarrage, Tor prêt : une place gérée dont plus aucun
        fournisseur ne veut (gestion désactivée, fournisseur retiré) est
        rendue au compte."""
        if self._wg_menage_fait:
            return
        self._wg_menage_fait = True
        geres = {service_gere(p) for p in self.config.get("providers", [])}
        for service in SERVICES:
            if service in geres:
                continue
            etat = self._wg_lire(service)
            if etat is None:
                continue
            nom = NOMS[service]
            if etat["machine"] == self._machine():
                r = self._api_wg(service, {
                    "action": "fermer", "jeton": etat["jeton"],
                    "compte": self._compte_par_empreinte(etat["compte"])})
                if not r["ok"]:
                    self._log(f"{nom} : place gérée non rendue ({r.get('message', '?')})"
                              " — nouvel essai au prochain démarrage.", "WARN")
                    continue
                self._log(f"{nom} : WireGuard géré désactivé — session fermée, place "
                          "rendue au compte.", "OK")
            self._wg_effacer(service)

    def _wg_gere_statut(self) -> dict:
        """Pour le statut : fournisseur géré en cours, numéro affiché du
        compte qui porte la place de ce PC, date de la clé ; rien de secret."""
        providers = self.config.get("providers", [])
        if not 0 <= self._current_provider_idx < len(providers):
            return {}
        p = providers[self._current_provider_idx]
        service = service_gere(p)
        etat = self._wg_etats.get(service) if service else None
        for i, compte in self._comptes_wg(p) if etat else []:
            if compte and empreinte(compte) == etat.get("compte"):
                return {"service": service, "provider": p.get("name", ""),
                        "account": i + 1, "key_since": int(etat["cle_du"])}
        return {}
