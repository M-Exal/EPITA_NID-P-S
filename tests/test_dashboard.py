"""
Tests unitaires pour le backend du Dashboard SIEM CyBear.
"""

import json
import sys
from pathlib import Path
import pytest

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "dashboard"))

pytest.importorskip("flask")

from app import app, calculer_statistiques


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Client de test Flask configuré avec un fichier temporaire d'alertes."""
    test_alerts_file = tmp_path / "nids_alerts.json"
    sample_alerts = [
        {
            "timestamp": "2026-10-19T09:43:27",
            "type": "SCAN_PORTS",
            "src_ip": "172.19.0.3",
            "details": "(16 ports en 10s)",
        },
        {
            "timestamp": "2026-10-19T09:43:30",
            "type": "DOS",
            "src_ip": "172.19.0.3",
            "details": "(250 paquets en 5s)",
        },
        {
            "timestamp": "2026-10-19T09:44:00",
            "type": "SQL_INJECTION",
            "src_ip": "172.19.0.5",
            "details": "Payload: ' OR 1=1",
        },
    ]
    with open(test_alerts_file, "w", encoding="utf-8") as f:
        json.dump(sample_alerts, f)

    monkeypatch.setattr("app.ALERT_JSON_PATH", str(test_alerts_file))
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_route(client):
    """Vérifie que la page d'accueil du dashboard retourne le HTML."""
    res = client.get("/")
    assert res.status_code == 200
    assert b"CyBear SIEM" in res.data
    assert b"NIDS / NIPS SOC" in res.data


def test_api_alerts(client):
    """Vérifie que /api/alerts renvoie la liste complète des alertes."""
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]["type"] == "SCAN_PORTS"
    assert data[1]["type"] == "DOS"


def test_api_stats(client):
    """Vérifie que /api/stats agrège correctement les métriques SIEM."""
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.get_json()

    assert stats["total_alerts"] == 3
    assert stats["unique_ips"] == 2
    assert stats["severity_counts"]["CRITIQUE"] == 2  # DOS et SQL_INJECTION
    assert stats["severity_counts"]["MOYENNE"] == 1  # SCAN_PORTS
    assert "172.19.0.3" in stats["attack_matrix"]
    assert stats["attack_matrix"]["172.19.0.3"]["DOS"] == 1
    assert stats["attack_matrix"]["172.19.0.3"]["SCAN_PORTS"] == 1


def test_calculer_statistiques_vide():
    """Vérifie le comportement avec une liste vide d'alertes."""
    stats = calculer_statistiques([])
    assert stats["total_alerts"] == 0
    assert stats["unique_ips"] == 0
    assert stats["latest_alerts"] == []
    assert stats["derniere_alerte"] is None


def test_panneau_attaques_route(client):
    """Vérifie que la page /attaques se charge correctement."""
    res = client.get("/attaques")
    assert res.status_code == 200
    assert b"Panneau d'Attaque" in res.data or b"CyBear" in res.data


def test_api_attaques_status_vide(client):
    """Vérifie que /api/attaques/status renvoie la structure attendue."""
    res = client.get("/api/attaques/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "en_cours" in data
    assert "terminees" in data
    assert isinstance(data["en_cours"], list)
    assert isinstance(data["terminees"], list)


def test_api_attaques_lancer_validation(client):
    """Vérifie la validation des paramètres de /api/attaques/lancer."""
    # Requête sans body ou sans clé 'attaque'
    res = client.post("/api/attaques/lancer", json={})
    assert res.status_code == 400
    assert "error" in res.get_json()

    # Attaque inconnue
    res = client.post("/api/attaques/lancer", json={"attaque": "attaque_inconnue"})
    assert res.status_code == 400
    assert "error" in res.get_json()
