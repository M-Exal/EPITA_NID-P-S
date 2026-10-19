"""
Tests unitaires pour LogAnalyzer (analyse des alertes NIDS et des logs Cowrie).
"""

import json
from analyze import LogAnalyzer


def test_analyse_alertes_nids(tmp_path):
    fichier_json = tmp_path / "nids_alerts.json"
    donnees = [
        {"type": "SCAN_PORTS", "src_ip": "10.0.0.1"},
        {"type": "SCAN_PORTS", "src_ip": "10.0.0.1"},
        {"type": "SQL_INJECTION", "src_ip": "10.0.0.2"},
    ]
    fichier_json.write_text(json.dumps(donnees), encoding="utf-8")

    analyzer = LogAnalyzer(nids_alerts=str(fichier_json))
    stats = analyzer.analyser_alertes_nids()

    assert stats["total"] == 3
    assert stats["types"]["SCAN_PORTS"] == 2
    assert stats["types"]["SQL_INJECTION"] == 1
    assert stats["top_sources"]["10.0.0.1"] == 2


def test_analyse_logs_cowrie(tmp_path):
    dossier_cowrie = tmp_path / "cowrie"
    dossier_cowrie.mkdir()
    fichier_log = dossier_cowrie / "cowrie.json"

    lignes = [
        {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"},
        {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "username": "root", "password": "wrong"},
        {"eventid": "cowrie.login.success", "src_ip": "1.2.3.4", "username": "root", "password": "root"},
        {"eventid": "cowrie.command.input", "src_ip": "1.2.3.4", "input": "uname -a"},
    ]
    fichier_log.write_text("\n".join(json.dumps(l) for l in lignes), encoding="utf-8")

    analyzer = LogAnalyzer(cowrie_dir=str(dossier_cowrie))
    stats = analyzer.analyser_logs_cowrie()

    assert stats["sessions"] == 1
    assert stats["logins_echoues"] == 1
    assert stats["logins_reussis"] == 1
    assert "uname -a" in stats["commandes_executees"]
