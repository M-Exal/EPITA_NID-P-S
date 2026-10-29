"""
Fixtures pytest pour l'environnement de test du NIDS / NIPS.
"""

import os
import sys
from pathlib import Path
import pytest

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "nids"))
sys.path.insert(0, str(RACINE / "mail"))
sys.path.insert(0, str(RACINE / "analysis"))

from config import Config
from detectors import MoteurDetection


class AlertesFactices:
    """Mock de AlertManager pour enregistrer les alertes en mémoire sans écriture disque."""
    def __init__(self):
        self.alertes = []

    def log_alert(self, type_attaque, ip_src, details=""):
        self.alertes.append({
            "type": type_attaque,
            "src_ip": ip_src,
            "details": details,
        })

    @property
    def types(self):
        return [a["type"] for a in self.alertes]


@pytest.fixture
def mock_config(tmp_path):
    """Configuration de test avec seuils réduits et fichiers dans tmp_path."""
    cfg = Config()
    cfg.DATA_DIR = str(tmp_path / "data")
    os.makedirs(cfg.DATA_DIR, exist_ok=True)
    cfg.ALERT_LOG = os.path.join(cfg.DATA_DIR, "nids_alerts.log")
    cfg.ALERT_JSON = os.path.join(cfg.DATA_DIR, "nids_alerts.json")
    cfg.KEY_FILE = os.path.join(cfg.DATA_DIR, "secret.key")
    cfg.ENCRYPTED_REPORT = os.path.join(cfg.DATA_DIR, "nids_alerts.enc")
    cfg.NIPS_STATE_FILE = os.path.join(cfg.DATA_DIR, "nips_state.json")

    # Seuils bas pour tester facilement
    cfg.SCAN_THRESHOLD = 3
    cfg.SCAN_WINDOW = 5
    cfg.DOS_THRESHOLD = 5
    cfg.DOS_WINDOW = 5
    cfg.BRUTE_THRESHOLD = 3
    cfg.BRUTE_WINDOW = 5
    cfg.ALERT_COOLDOWN = 10
    cfg.NIPS_ENABLED = True
    return cfg


@pytest.fixture
def mock_alertes():
    return AlertesFactices()


@pytest.fixture
def mock_blocker():
    """Mock pour capturer les appels de blocage NIPS."""
    bloques = []

    def blocker_fn(ip):
        bloques.append(ip)
        return True

    blocker_fn.bloques = bloques
    return blocker_fn


@pytest.fixture
def moteur(mock_config, mock_alertes, mock_blocker):
    """Moteur de détection injecté avec mock alertes et mock blocker."""
    return MoteurDetection(mock_config, mock_alertes, blocker=mock_blocker)
