"""
Tests unitaires spécifiques au mécanisme de prévention NIPS (blocage actif).
"""

import os
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


def test_nips_quarantaine_basee_sur_whoami(mock_config, mock_alertes, mock_blocker):
    """La quarantaine ne bloque que les comptes ayant un whoami réussi (preuve d'intrusion)."""
    import json
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    results_file = os.path.join(mock_config.DATA_DIR, "pentest_results.json")
    with open(results_file, "w") as f:
        json.dump({"attaques": {"brute_force_ssh": {"acces_valides": [
            {"utilisateur": "msfadmin", "mot_de_passe": "msfadmin", "whoami": "msfadmin", "code_retour": 0},
            {"utilisateur": "root", "mot_de_passe": "toor", "whoami": "", "code_retour": 1},
            {"utilisateur": "user", "mot_de_passe": "user", "whoami": "user", "code_retour": 0},
        ]}}}, f)

    moteur._enregistrer_ip_bloquee_etat("10.0.0.1", "BRUTE_FORCE")

    etat = moteur._lire_etat_nips()
    q = etat["quarantined_accounts"]
    assert "msfadmin" in q
    assert "user" in q
    assert "root" not in q


def test_nips_quarantaine_vide_sans_resultats(mock_config, mock_alertes, mock_blocker):
    """Sans résultats de pentest, aucun compte n'est mis en quarantaine."""
    mock_config.NIPS_ENABLED = True
    moteur = MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)

    moteur._enregistrer_ip_bloquee_etat("10.0.0.2", "BRUTE_FORCE")

    etat = moteur._lire_etat_nips()
    assert etat["quarantined_accounts"] == []


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

