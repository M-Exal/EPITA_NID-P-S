"""
Tests unitaires spécifiques au mécanisme de prévention NIPS (blocage actif).
"""

import pytest
from detectors import MoteurDetection


def test_nips_actif_bloque_attaquant(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.50", "DOS")

    assert "192.168.1.50" in moteur.ips_bloquees
    assert "192.168.1.50" in mock_blocker.bloques


def test_nips_inactif_ne_bloque_pas(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = False
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.51", "DOS")

    assert "192.168.1.51" not in moteur.ips_bloquees
    assert "192.168.1.51" not in mock_blocker.bloques


def test_nips_bloquage_unique(mock_config, mock_alertes, mock_blocker):
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur.bloquer_ip("192.168.1.52", "SCAN_PORTS")
    moteur.bloquer_ip("192.168.1.52", "SCAN_PORTS")

    assert mock_blocker.bloques.count("192.168.1.52") == 1


def test_nips_synchroniser_deblocage_ip(mock_config, mock_alertes, mock_blocker, monkeypatch):
    """Vérifie que la synchronisation NIPS retire l'IP de self.ips_bloquees et appelle le déblocage."""
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)
    moteur.ips_bloquees.add("172.19.0.3")

    debloquees = []
    monkeypatch.setattr(moteur, "_executer_deblocage_systeme", lambda ip: debloquees.append(ip))

    # Écrire un état NIPS sans 172.19.0.3 dans blocked_ips
    moteur._ecrire_etat_nips({
        "enabled": True,
        "blocked_ips": [],
        "pending_unblock": ["172.19.0.3"],
        "quarantined_accounts": [],
        "reset_requested": False,
    })

    moteur.synchroniser_etat_nips()

    assert "172.19.0.3" not in moteur.ips_bloquees
    assert "172.19.0.3" in debloquees

