"""
Tests unitaires pour AlertManager (logs texte et logs JSON).
"""

import json
import os
from alerting import AlertManager


def test_alert_manager_ecriture(mock_config):
    manager = AlertManager(mock_config)

    manager.log_alert("TEST_ATTACK", "10.0.0.1", "details=foo")

    # 1. Vérification du fichier texte
    assert os.path.exists(mock_config.ALERT_LOG)
    with open(mock_config.ALERT_LOG, "r", encoding="utf-8") as f:
        contenu = f.read()
    assert "TEST_ATTACK" in contenu
    assert "10.0.0.1" in contenu

    # 2. Vérification du fichier JSON
    assert os.path.exists(mock_config.ALERT_JSON)
    with open(mock_config.ALERT_JSON, "r", encoding="utf-8") as f:
        alertes_json = json.load(f)

    assert len(alertes_json) == 1
    assert alertes_json[0]["type"] == "TEST_ATTACK"
    assert alertes_json[0]["src_ip"] == "10.0.0.1"
