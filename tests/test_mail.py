"""
Tests unitaires pour l'envoi de rapport chiffré par email (avec mock SMTP).
"""

from unittest.mock import MagicMock, patch
from send_report import envoyer_rapport_chiffre


def test_envoi_rapport_chiffre_mock(mock_config, tmp_path):
    # Créer le fichier chiffré factice
    fichier_enc = tmp_path / "nids_alerts.enc"
    fichier_enc.write_bytes(b"CONTENU_CHIFFRE_MOCK")
    mock_config.ENCRYPTED_REPORT = str(fichier_enc)
    mock_config.REPORT_RECEIVER = "admin@example.com"
    mock_config.SMTP_USER = "nids@example.com"
    mock_config.SMTP_PASSWORD = "secretpassword"

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_instance

        succes = envoyer_rapport_chiffre(mock_config)

        assert succes is True
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("nids@example.com", "secretpassword")
        mock_instance.sendmail.assert_called_once()


def test_envoi_rapport_inexistant(mock_config):
    mock_config.ENCRYPTED_REPORT = "/chemin/inexistant.enc"
    succes = envoyer_rapport_chiffre(mock_config)
    assert succes is False
