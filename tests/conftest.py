"""
conftest.py — Fixtures partagées des tests du projet.

Le projet contient plusieurs modules portant le même nom dans des dossiers
différents (`nids/config.py` vs `pentest/config.py`, `nids/crypto_utils.py` vs
`mail/crypto_utils.py`). Pour éviter toute collision dans `sys.modules`, le
helper `charger()` importe chaque fichier sous un alias unique
(ex. `nids_config`) tout en laissant les imports internes du module
(`from config import Config`) se résoudre dans son propre dossier.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]

# Noms internes potentiellement ambigus : purgés avant chaque chargement.
INTERNES = ("config", "crypto_utils", "alerting", "detectors",
            "pentest", "nids", "analyze")


def charger(dossier, module):
    """
    Charge `<dossier>/<module>.py` et renvoie l'objet module.

    Le module est mis en cache sous l'alias `<dossier>_<module>` ; son nom
    « nu » (ex. `config`) est retiré de `sys.modules` après l'exécution pour
    ne pas polluer le chargement d'un autre dossier.
    """
    alias = f"{dossier}_{module}"
    if alias in sys.modules:
        return sys.modules[alias]

    chemin = RACINE / dossier / f"{module}.py"
    if not chemin.exists():
        raise FileNotFoundError(chemin)

    for nom in INTERNES:
        sys.modules.pop(nom, None)

    sys.path.insert(0, str(chemin.parent))
    try:
        spec = importlib.util.spec_from_file_location(alias, chemin)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[alias] = mod
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(chemin.parent))
        sys.modules.pop(module, None)

    return mod


@pytest.fixture
def nids_config(tmp_path):
    """Config du NIDS redirigée vers un répertoire temporaire."""
    cfg = charger("nids", "config").Config
    data = tmp_path / "nids"
    data.mkdir(parents=True, exist_ok=True)
    cfg.DATA_DIR = str(data)
    cfg.ALERT_LOG = str(data / "nids_alerts.log")
    cfg.ALERT_JSON = str(data / "nids_alerts.json")
    cfg.KEY_FILE = str(data / "secret.key")
    # Seuils par défaut (certains tests les surchargent via monkeypatch).
    cfg.SCAN_THRESHOLD, cfg.SCAN_WINDOW = 15, 10
    cfg.DOS_THRESHOLD, cfg.DOS_WINDOW = 200, 5
    cfg.BRUTE_THRESHOLD, cfg.BRUTE_WINDOW = 10, 30
    cfg.ALERT_COOLDOWN = 30
    return cfg


@pytest.fixture
def pentest_config(tmp_path):
    """Config du pentest redirigée vers un répertoire temporaire et une
    cible locale (aucun hôte externe contacté par les tests)."""
    cfg = charger("pentest", "config").Config
    cfg.TARGET_HOST = "127.0.0.1"
    cfg.DATA_DIR = str(tmp_path / "pentest")
    # Dictionnaires réduits pour garder les tests rapides.
    cfg.USERNAMES = ["root"]
    cfg.PASSWORDS = ["wrong"]
    cfg.DOS_COUNT = 3
    cfg.TIMEOUT = 0.5
    return cfg


class AlertesFactices:
    """Remplace `AlertManager` : mémorise les alertes au lieu d'écrire sur
    disque (test isolé et rapide du moteur de détection)."""

    def __init__(self):
        self.alertes = []

    def log_alert(self, type_attaque, ip_src, details=""):
        self.alertes.append((type_attaque, ip_src, details))

    @property
    def types(self):
        return [t for t, _, _ in self.alertes]


@pytest.fixture
def alertes(nids_config):
    return AlertesFactices()


@pytest.fixture
def moteur(nids_config, alertes):
    """Moteur de détection branché sur des alertes factices."""
    detections = charger("nids", "detectors")
    return detections.MoteurDetection(nids_config, alertes)
