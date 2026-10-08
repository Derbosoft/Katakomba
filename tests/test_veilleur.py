"""Veilleur : quand l'interface en arrière-plan prévient-elle ?

Chaque test rejoue une suite de lectures d'état (une toutes les 3 s, comme
la fenêtre) et vérifie les notifications décidées."""

import unittest

from gui.veilleur import SEUIL_COUPURE, SEUIL_ETABLISSEMENT, Veilleur

CONNECTE = {"tunnel_up": True, "provider": "MonVPN"}


def coupe(depuis=None, raison=""):
    st = {"tunnel_up": False, "provider": "MonVPN", "reconnect_reason": raison}
    if depuis is not None:
        st["tunnel_down_for"] = depuis
    return st


class VeilleurTest(unittest.TestCase):

    def setUp(self):
        self.v = Veilleur()
        self.t = 1000.0

    def lire(self, service, st, avance=3, discret=False):
        self.t += avance
        return self.v.observer(service, st, self.t, discret=discret)

    def titres(self, avis):
        return [a.titre for a in avis]

    def connecte_depuis_longtemps(self):
        self.assertEqual(self.lire("active", CONNECTE), [], "rien à la première lecture")

    # ── Coupures ─────────────────────────────────────────────────────────────

    def test_reprise_rapide_silencieuse(self):
        self.connecte_depuis_longtemps()
        for _ in range(4):                                   # 12 s
            self.assertEqual(self.lire("active", coupe(raison="connexion VPN interrompue")), [])
        self.assertEqual(self.lire("active", CONNECTE), [])

    def test_coupure_longue_puis_retour(self):
        self.connecte_depuis_longtemps()
        avis = []
        for _ in range(SEUIL_COUPURE // 3 + 2):
            avis += self.lire("active", coupe(raison="perte de connectivité, relance d'OpenVPN"))
        self.assertEqual(self.titres(avis), ["Connexion perdue"])
        self.assertIn("Perte de connectivité", avis[0].corps)
        retour = self.lire("active", CONNECTE)
        self.assertEqual(self.titres(retour), ["Connexion rétablie"])
        self.assertEqual(retour[0].ident, avis[0].ident, "doit remplacer l'alerte")
        self.assertIn("de coupure", retour[0].corps)

    def test_duree_donnee_par_le_daemon(self):
        """Tunnel tombé pendant que l'interface ne regardait pas : la durée
        vient du daemon (tunnel_down_for), pas de la première lecture."""
        self.connecte_depuis_longtemps()
        avis = self.lire("active", coupe(depuis=SEUIL_COUPURE + 5))
        self.assertEqual(self.titres(avis), ["Connexion perdue"])

    def test_changement_de_raison_met_a_jour(self):
        self.connecte_depuis_longtemps()
        self.lire("active", coupe(depuis=SEUIL_COUPURE + 1, raison="circuit Tor trop lent, nouveau tirage"))
        self.assertEqual(self.lire("active", coupe(raison="circuit Tor trop lent, nouveau tirage")), [])
        maj = self.lire("active", coupe(raison="redémarrage complet de Tor et d'OpenVPN"))
        self.assertEqual(self.titres(maj), ["Connexion perdue"])
        self.assertIn("Redémarrage complet", maj[0].corps)

    def test_fenetre_regardee_pas_de_nouvelle_alerte(self):
        self.connecte_depuis_longtemps()
        self.assertEqual(self.lire("active", coupe(depuis=60), discret=True), [])
        self.assertEqual(self.lire("active", CONNECTE, discret=True), [])

    def test_alerte_deja_affichee_mise_a_jour_meme_fenetre_regardee(self):
        self.connecte_depuis_longtemps()
        self.lire("active", coupe(depuis=60))
        self.assertEqual(self.titres(self.lire("active", CONNECTE, discret=True)),
                         ["Connexion rétablie"])

    # ── Démarrage ────────────────────────────────────────────────────────────

    def test_connexion_etablie_signalee(self):
        """Ouverture de session : le service se connecte, l'interface cachée
        le confirme une fois."""
        self.assertEqual(self.lire("active", coupe(depuis=5, raison="démarrage du service")), [])
        avis = self.lire("active", CONNECTE)
        self.assertEqual(self.titres(avis), ["Katakomba est connecté"])
        self.assertIn("MonVPN", avis[0].corps)
        self.assertEqual(self.lire("active", CONNECTE), [])

    def test_etablissement_long_signale_plus_tard(self):
        self.lire("active", coupe(depuis=0, raison="démarrage du service"))
        self.assertEqual(self.lire("active", coupe(depuis=SEUIL_COUPURE + 5)), [],
                         "le premier établissement a droit à plus de temps")
        avis = self.lire("active", coupe(depuis=SEUIL_ETABLISSEMENT + 1, raison="identifiants refusés, compte suivant"))
        self.assertEqual(self.titres(avis), ["Connexion toujours en cours"])
        self.assertIn("Identifiants refusés", avis[0].corps)
        self.assertEqual(self.titres(self.lire("active", CONNECTE)), ["Katakomba est connecté"])

    # ── Arrêt du service ─────────────────────────────────────────────────────

    def test_arret_inattendu(self):
        self.connecte_depuis_longtemps()
        avis = self.lire("failed", {})
        self.assertEqual(self.titres(avis), ["Katakomba s'est arrêté sur une erreur"])
        self.assertEqual(avis[0].bouton, "reconnecter")
        self.assertTrue(avis[0].urgent)
        self.assertEqual(self.lire("failed", {}), [], "une seule fois")

    def test_arret_demande_silencieux(self):
        self.connecte_depuis_longtemps()
        self.v.action_utilisateur(self.t)
        self.assertEqual(self.lire("inactive", {}), [])

    def test_arret_demande_efface_l_alerte_perimee(self):
        self.connecte_depuis_longtemps()
        self.lire("active", coupe(depuis=60))
        self.v.action_utilisateur(self.t)
        avis = self.lire("inactive", {})
        self.assertEqual(len(avis), 1)
        self.assertTrue(avis[0].retirer)

    def test_redemarrage_demande_puis_connecte(self):
        self.connecte_depuis_longtemps()
        self.v.action_utilisateur(self.t)
        for _ in range(8):                                   # 24 s de redémarrage
            self.assertEqual(self.lire("active", coupe(raison="démarrage du service")), [])
        self.assertEqual(self.titres(self.lire("active", CONNECTE)), ["Katakomba est connecté"])

    def test_connexion_demandee_fenetre_ouverte(self):
        self.assertEqual(self.lire("inactive", {}), [])
        self.v.action_utilisateur(self.t)
        self.lire("active", coupe(depuis=2), discret=True)
        self.assertEqual(self.lire("active", CONNECTE, discret=True), [],
                         "l'utilisateur voit déjà l'écran Connexion")

    # ── Lectures incertaines ─────────────────────────────────────────────────

    def test_etats_transitoires_ignores(self):
        self.connecte_depuis_longtemps()
        for service in ("activating", "deactivating", "unknown"):
            self.assertEqual(self.lire(service, {}), [])
        self.assertEqual(self.lire("active", {}), [], "socket muet ≠ coupure")
        self.assertEqual(self.lire("active", CONNECTE), [])


if __name__ == "__main__":
    unittest.main()
