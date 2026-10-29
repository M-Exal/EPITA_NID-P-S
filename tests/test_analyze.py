"""
Tests unitaires pour LogAnalyzer (analyse des alertes NIDS et des logs Metasploitable 2).
"""

import json
from pathlib import Path
from analyze import LogAnalyzer, CORRELATION_MAP


def test_analyse_alertes_nids_vide(tmp_path):
    empty_alerts = tmp_path / "empty_alerts.json"
    empty_alerts.write_text("[]", encoding="utf-8")

    analyzer = LogAnalyzer(nids_alerts=empty_alerts)
    stats = analyzer.analyser_alertes_nids()
    assert "total" in stats
    assert stats["total"] == 0
    assert "types" in stats
    assert "top_sources" in stats


def test_analyse_alertes_nids_avec_donnees(tmp_path):
    alerts_file = tmp_path / "nids_alerts.json"
    alerts = [
        {"type": "SCAN_PORTS", "src_ip": "192.168.1.10", "severite": "MOYENNE", "timestamp": "2026-10-29T10:15:00"},
        {"type": "SCAN_PORTS", "src_ip": "192.168.1.10", "severite": "MOYENNE", "timestamp": "2026-10-29T10:15:10"},
        {"type": "BRUTE_FORCE", "src_ip": "192.168.1.50", "severite": "ELEVEE", "timestamp": "2026-10-29T10:16:00"},
        {"type": "SQL_INJECTION", "src_ip": "192.168.1.50", "severite": "CRITIQUE", "timestamp": "2026-10-29T10:17:00"},
    ]
    alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

    analyzer = LogAnalyzer(nids_alerts=alerts_file)
    stats = analyzer.analyser_alertes_nids()

    assert stats["total"] == 4
    assert stats["types"]["SCAN_PORTS"] == 2
    assert stats["types"]["BRUTE_FORCE"] == 1
    assert stats["types"]["SQL_INJECTION"] == 1
    assert stats["top_sources"]["192.168.1.50"] == 2
    assert stats["top_sources"]["192.168.1.10"] == 2
    assert stats["severites"]["CRITIQUE"] == 1
    assert stats["severites"]["ELEVEE"] == 1
    assert stats["severites"]["MOYENNE"] == 2


def test_analyse_logs_metasploitable_vide(tmp_path):
    empty_dir = tmp_path / "logs"
    empty_dir.mkdir()

    analyzer = LogAnalyzer(target_dir=empty_dir)
    stats = analyzer.analyser_logs_metasploitable()
    assert "total_evenements" in stats
    assert stats["total_evenements"] == 0
    assert "sessions" in stats
    assert "logins_echoues" in stats
    assert "logins_reussis" in stats


def test_analyse_logs_metasploitable_auth_et_access(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    auth_log = log_dir / "auth.log"
    auth_log.write_text(
        "Oct 29 10:00:01 meta sshd[100]: Failed password for invalid user admin from 10.0.0.1 port 50000 ssh2\n"
        "Oct 29 10:00:02 meta sshd[101]: Failed password for root from 10.0.0.1 port 50001 ssh2\n"
        "Oct 29 10:00:03 meta sshd[102]: Accepted password for msfadmin from 10.0.0.2 port 50002 ssh2\n"
        "Oct 29 10:00:04 meta sshd[103]: pam_unix(sshd:session): session opened for user msfadmin by (uid=0)\n",
        encoding="utf-8",
    )

    access_log = log_dir / "access.log"
    access_log.write_text(
        '10.0.0.1 - - [29/Oct/2026:10:00:10 +0200] "GET /vulnerabilities/sqli/?id=%27+OR+%271%27=%271 HTTP/1.1" 200 1234\n'
        '10.0.0.1 - - [29/Oct/2026:10:00:11 +0200] "GET /vulnerabilities/xss_r/?name=<script>alert(1)</script> HTTP/1.1" 200 567\n'
        '10.0.0.1 - - [29/Oct/2026:10:00:12 +0200] "GET /vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1" 200 890\n',
        encoding="utf-8",
    )

    analyzer = LogAnalyzer(target_dir=log_dir)
    stats = analyzer.analyser_logs_metasploitable()

    assert stats["logins_echoues"] == 2
    assert stats["logins_reussis"] == 1
    assert stats["sessions"] == 1
    assert stats["requetes_http"] == 3
    assert stats["total_evenements"] == 7
    assert stats["ssh"]["comptes_cibles"]["admin"] == 1
    assert stats["ssh"]["comptes_cibles"]["root"] == 1
    assert stats["http"]["signatures_web"]["sqli"] == 1
    assert stats["http"]["signatures_web"]["xss"] == 1
    assert stats["http"]["signatures_web"]["path_traversal"] == 1


def test_analyse_correlation_et_taux_detection(tmp_path):
    alerts_file = tmp_path / "alerts.json"
    pentest_file = tmp_path / "pentest.json"

    # Simulation d'un pentest ayant exécuté 3 attaques
    pentest_file.write_text(
        json.dumps({
            "cible": "metasploitable",
            "attaques": {
                "scan_ports": {"statut": "termine"},
                "brute_force_ssh": {"statut": "termine"},
                "sql_injection": {"statut": "termine"},
            },
        }),
        encoding="utf-8",
    )

    # Simulation du NIDS ayant détecté les 3 attaques
    alerts_file.write_text(
        json.dumps([
            {"type": "SCAN_PORTS", "src_ip": "10.0.0.5"},
            {"type": "BRUTE_FORCE", "src_ip": "10.0.0.5"},
            {"type": "SQL_INJECTION", "src_ip": "10.0.0.5"},
        ]),
        encoding="utf-8",
    )

    analyzer = LogAnalyzer(nids_alerts=alerts_file, pentest_results=pentest_file)
    rapport = analyzer.generer_rapport()

    assert "correlation" in rapport
    corr = rapport["correlation"]
    assert corr["total_attaques_pentest"] == 3
    assert corr["attaques_detectees_nids"] == 3
    assert corr["taux_detection_pct"] == 100.0
    assert "OPTIMALE" in corr["evaluation_globale"]

    # Restitution textuelle
    texte = analyzer.generer_synthese_texte(rapport)
    assert "RAPPORT DE SYNTHÈSE FORENSIQUE" in texte
    assert "100.0%" in texte
