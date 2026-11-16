"""
Tests unitaires pour l'envoi de rapport chiffré et d'alertes critiques par courriel.
"""

from unittest.mock import MagicMock, patch
from send_report import envoyer_rapport_chiffre, envoyer_alerte_critique_email


def test_envoi_rapport_chiffre_mock_smtp(mock_config, tmp_path):
    # Créer le fichier chiffré factice
    fichier_enc = tmp_path / "nids_alerts.enc"
    fichier_enc.write_bytes(b"CONTENU_CHIFFRE_MOCK")
    mock_config.ENCRYPTED_REPORT = str(fichier_enc)
    mock_config.REPORT_RECEIVER = "admin@example.com"
    mock_config.SMTP_USER = "nids@example.com"
    mock_config.SMTP_PASSWORD = "secretpassword"
    mock_config.RESEND_API_KEY = ""

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        succes = envoyer_rapport_chiffre(mock_config)

        assert succes is True
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("nids@example.com", "secretpassword")
        mock_instance.sendmail.assert_called_once()


def test_envoi_rapport_chiffre_resend(mock_config, tmp_path):
    fichier_enc = tmp_path / "nids_alerts.enc"
    fichier_enc.write_bytes(b"CONTENU_CHIFFRE_MOCK")
    mock_config.ENCRYPTED_REPORT = str(fichier_enc)
    mock_config.RESEND_API_KEY = "re_test_dummy_key"
    mock_config.ALERT_EMAIL_TO = "soc@epita.fr"

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "msg_123"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        succes = envoyer_rapport_chiffre(mock_config)
        assert succes is True
        mock_urlopen.assert_called_once()


def test_envoi_alerte_critique_resend(mock_config):
    mock_config.RESEND_API_KEY = "re_test_dummy_key"
    mock_config.ALERT_EMAIL_TO = "soc@epita.fr"

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "msg_alert_456"}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        succes = envoyer_alerte_critique_email(
            mock_config, "DOS_FLOOD", "10.0.0.99", "Inondation SYN massive"
        )
        assert succes is True
        mock_urlopen.assert_called_once()


def test_envoi_rapport_inexistant(mock_config):
    mock_config.ENCRYPTED_REPORT = "/chemin/inexistant.enc"
    succes = envoyer_rapport_chiffre(mock_config)
    assert succes is False
