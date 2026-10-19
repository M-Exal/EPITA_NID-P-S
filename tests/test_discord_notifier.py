"""
Tests unitaires pour le module DiscordNotifier.
"""

import json
from unittest.mock import patch, MagicMock
from discord_notifier import DiscordNotifier, SEVERITE_PAR_TYPE, COULEURS_SEVERITE


class TestDiscordNotifierDesactive:
    """Tests quand le webhook n'est pas configuré."""

    def test_notifier_desactive_sans_url(self):
        """Le notifier doit être désactivé si aucune URL n'est fournie."""
        notifier = DiscordNotifier(webhook_url="")
        assert notifier.enabled is False

    def test_envoyer_alerte_ne_fait_rien_si_desactive(self):
        """Aucun appel réseau si le notifier est désactivé."""
        notifier = DiscordNotifier(webhook_url="")
        # Ne doit pas lever d'exception
        notifier.envoyer_alerte("DOS", "10.0.0.1", "flood détecté")


class TestDiscordNotifierActif:
    """Tests quand le webhook est configuré."""

    FAKE_URL = "https://discord.com/api/webhooks/123/abc"

    def test_notifier_active_avec_url(self):
        """Le notifier doit être actif si une URL est fournie."""
        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        assert notifier.enabled is True

    def test_construire_payload_structure(self):
        """Le payload doit contenir les champs embed Discord attendus."""
        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        payload = notifier._construire_payload("DOS", "192.168.1.100", "flood SYN")

        assert "embeds" in payload
        assert len(payload["embeds"]) == 1

        embed = payload["embeds"][0]
        assert "DOS" in embed["title"]
        assert embed["color"] == COULEURS_SEVERITE["CRITIQUE"]

        # Vérification des champs
        noms_champs = [f["name"] for f in embed["fields"]]
        assert "🎯 Type d'attaque" in noms_champs
        assert "🌐 IP Source" in noms_champs
        assert "⚡ Sévérité" in noms_champs
        assert "📋 Détails" in noms_champs  # car details est non vide

    def test_construire_payload_sans_details(self):
        """Le champ Détails ne doit pas apparaître si aucun détail n'est fourni."""
        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        payload = notifier._construire_payload("SCAN_PORTS", "10.0.0.5", "")

        embed = payload["embeds"][0]
        noms_champs = [f["name"] for f in embed["fields"]]
        assert "📋 Détails" not in noms_champs

    def test_mention_critique(self):
        """Les alertes critiques doivent contenir @here."""
        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        payload = notifier._construire_payload("BRUTE_FORCE", "10.0.0.1", "")
        assert "@here" in payload["content"]

    def test_pas_de_mention_non_critique(self):
        """Les alertes non-critiques ne doivent pas contenir @here."""
        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        payload = notifier._construire_payload("SCAN_PORTS", "10.0.0.1", "")
        assert "@here" not in payload["content"]

    def test_severite_par_type_tous_types(self):
        """Chaque type d'attaque connu doit avoir une sévérité définie."""
        types_attendus = [
            "SCAN_PORTS", "NULL_SCAN", "XMAS_SCAN", "BRUTE_FORCE",
            "DOS", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL",
        ]
        for t in types_attendus:
            assert t in SEVERITE_PAR_TYPE

    @patch("discord_notifier.urllib_request.urlopen")
    def test_envoyer_appelle_webhook(self, mock_urlopen):
        """L'envoi doit poster le payload JSON au webhook."""
        mock_response = MagicMock()
        mock_response.status = 204
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        notifier._envoyer("DOS", "10.0.0.1", "test")

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == self.FAKE_URL
        assert req.get_header("Content-type") == "application/json"

        # Vérifie que le body est du JSON valide
        body = json.loads(req.data.decode("utf-8"))
        assert "embeds" in body

    @patch("discord_notifier.urllib_request.urlopen")
    def test_envoyer_gere_erreur_reseau(self, mock_urlopen):
        """L'envoi ne doit pas lever d'exception en cas d'erreur réseau."""
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("Connection refused")

        notifier = DiscordNotifier(webhook_url=self.FAKE_URL)
        # Ne doit pas lever d'exception
        notifier._envoyer("DOS", "10.0.0.1", "test")


class TestDiscordNotifierEnvVar:
    """Test de la configuration via variable d'environnement."""

    @patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/456/def"})
    def test_url_depuis_env(self):
        """Le notifier doit lire l'URL depuis DISCORD_WEBHOOK_URL."""
        notifier = DiscordNotifier()
        assert notifier.enabled is True
        assert notifier.webhook_url == "https://discord.com/api/webhooks/456/def"
