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
    assert b"NIDS / NIPS" in res.data


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
    assert "acces_valides" in data
    assert isinstance(data["en_cours"], list)
    assert isinstance(data["terminees"], list)
    assert isinstance(data["acces_valides"], list)


def test_api_ssh_connect(client):
    """Vérifie que /api/attaques/ssh_connect répond favorablement à une demande de connexion."""
    res = client.post("/api/attaques/ssh_connect", json={"utilisateur": "msfadmin"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ready"
    assert data["utilisateur"] == "msfadmin"
    assert "token" in data
    assert "cible" in data


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


def test_panneau_attaques_tous_modules_actifs(client):
    """Vérifie que tous les modules d'attaque (notamment web et DoS) sont activés sur l'interface."""
    res = client.get("/attaques")
    assert res.status_code == 200
    # Aucun badge 'Non implémenté' restant
    assert b"Non impl\xc3\xa9ment\xc3\xa9" not in res.data
    # Les cartes pour lancer les attaques web et DoS sont présentes
    assert b"data-attack=\"SQL_INJECTION\"" in res.data
    assert b"data-attack=\"XSS\"" in res.data
    assert b"data-attack=\"PATH_TRAVERSAL\"" in res.data
    assert b"data-attack=\"DOS\"" in res.data


def test_api_attaques_lancer_nouvelles_attaques(client, monkeypatch):
    """Vérifie que le backend accepte le lancement de sql_injection, xss, path_traversal et dos."""
    from unittest.mock import MagicMock
    mock_proc = MagicMock()
    mock_proc.pid = 9999
    mock_proc.poll.return_value = None

    monkeypatch.setattr("subprocess.Popen", MagicMock(return_value=mock_proc))

    for atk in ["sql_injection", "xss", "path_traversal", "dos"]:
        res = client.post("/api/attaques/lancer", json={"attaque": atk})
        assert res.status_code == 200, f"Erreur lors du lancement de {atk}: {res.get_json()}"
        data = res.get_json()
        assert data["status"] == "started"
        assert data["success"] is True

    # Test avec la syntaxe frontend /api/attack/launch et majuscules
    for atk_type in ["SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "DOS"]:
        res = client.post("/api/attack/launch", json={"attack_type": atk_type})
        assert res.status_code == 200, f"Erreur lors du lancement de {atk_type}: {res.get_json()}"
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "started"


def test_api_alerts_reset(client):
    """Vérifie que /api/alerts/reset réinitialise la base d'alertes."""
    # Avant le reset : 3 alertes présentes
    res = client.get("/api/alerts")
    assert len(res.get_json()) == 3

    # Appel du endpoint de réinitialisation
    res_reset = client.post("/api/alerts/reset")
    assert res_reset.status_code == 200
    assert res_reset.get_json()["status"] == "success"

    # Après le reset : 0 alerte
    res_after = client.get("/api/alerts")
    assert len(res_after.get_json()) == 0

