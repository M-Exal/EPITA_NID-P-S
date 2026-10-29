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

    test_nips_file = tmp_path / "nips_state.json"
    with open(test_nips_file, "w", encoding="utf-8") as f:
        json.dump({"enabled": False, "blocked_ips": [], "quarantined_accounts": [], "reset_requested": False}, f)

    monkeypatch.setattr("app.ALERT_JSON_PATH", str(test_alerts_file))
    monkeypatch.setattr("app.NIPS_STATE_PATH", str(test_nips_file))
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


def test_api_ssh_connect_quarantined(client):
    """Vérifie que /api/attaques/ssh_connect bloque un compte en quarantaine si le NIPS est actif."""
    client.post("/api/nips/toggle", json={"enabled": True})
    # Simuler quarantaine
    import app
    st = app._lire_nips_state()
    st["quarantined_accounts"] = ["msfadmin"]
    app._ecrire_nips_state(st)

    res = client.post("/api/attaques/ssh_connect", json={"utilisateur": "msfadmin"})
    assert res.status_code == 403
    data = res.get_json()
    assert data["status"] == "quarantined"
    assert data["nips_bloque"] is True


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


def test_nips_status_and_toggle(client, tmp_path, monkeypatch):
    """Vérifie la consultation et le basculement dynamique du mode NIPS."""
    state_file = tmp_path / "nips_state.json"
    monkeypatch.setattr("app.NIPS_STATE_PATH", str(state_file))

    # Statut initial
    res = client.get("/api/nips/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["enabled"] is False

    # Activation NIPS
    res_toggle = client.post("/api/nips/toggle", json={"enabled": True})
    assert res_toggle.status_code == 200
    assert res_toggle.get_json()["enabled"] is True

    # Désactivation NIPS
    res_off = client.post("/api/nips/toggle", json={"enabled": False})
    assert res_off.status_code == 200
    assert res_off.get_json()["enabled"] is False


def test_nips_quarantine_blocks_ssh_connect(client, tmp_path, monkeypatch):
    """Vérifie que le NIPS actif révoque l'accès SSH aux comptes sous quarantaine."""
    state_file = tmp_path / "nips_state.json"
    monkeypatch.setattr("app.NIPS_STATE_PATH", str(state_file))

    # Écrire un état avec NIPS actif et msfadmin en quarantaine
    import json
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump({
            "enabled": True,
            "blocked_ips": ["172.19.0.3"],
            "quarantined_accounts": ["msfadmin"],
            "reset_requested": False,
        }, f)

    # Tentative de connexion avec le compte sous quarantaine
    res = client.post("/api/attaques/ssh_connect", json={
        "utilisateur": "msfadmin",
        "mot_de_passe": "msfadmin",
    })
    assert res.status_code == 403
    assert res.get_json()["status"] == "quarantined"

    # Réinitialisation de la protection NIPS
    res_reset = client.post("/api/nips/reset")
    assert res_reset.status_code == 200

    # L'accès est de nouveau autorisé une fois la quarantaine levée
    res_apres = client.post("/api/attaques/ssh_connect", json={
        "utilisateur": "msfadmin",
        "mot_de_passe": "msfadmin",
    })
    assert res_apres.status_code == 200
    assert res_apres.get_json()["status"] == "ready"

