"""
Tests unitaires spécifiques au mécanisme de prévention NIPS (blocage actif).
"""

import pytest
from detectors import MoteurDetection


@pytest.mark.skip(reason="À implémenter par le membre en charge du NIPS")
def test_nips_actif_bloque_attaquant(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.50", "DOS")

    assert "192.168.1.50" in moteur.ips_bloquees
    assert "192.168.1.50" in mock_blocker.bloques


@pytest.mark.skip(reason="À implémenter par le membre en charge du NIPS")
def test_nips_inactif_ne_bloque_pas(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = False
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.51", "DOS")

    assert "192.168.1.51" not in moteur.ips_bloquees
    assert "192.168.1.51" not in mock_blocker.bloques


@pytest.mark.skip(reason="À implémenter par le membre en charge du NIPS")
def test_nips_bloquage_unique(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.52", "SCAN_PORTS")
    moteur.bloquer_ip("192.168.1.52", "SCAN_PORTS")

    assert mock_blocker.bloques.count("192.168.1.52") == 1
