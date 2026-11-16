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
    assert "RAPPORT DE SYNTHESE FORENSIQUE" in texte
    assert "100.0%" in texte


def test_synthese_texte_avec_comptes_et_bannieres(tmp_path):
    alerts_file = tmp_path / "alerts.json"
    pentest_file = tmp_path / "pentest.json"

    pentest_data = {
        "cible": "metasploitable",
        "attaques": {
            "null_scan": {
                "ports_ouverts": [21, 22, 80],
                "os_detecte": "Linux 2.6.X (Ubuntu / Metasploitable) [TTL=64]",
            },
            "scan_ports": {
                "ports_ouverts": [21, 22, 80],
                "bannieres": {
                    "21": "vsFTPd 2.3.4",
                    "22": "OpenSSH 4.7p1",
                    "80": "Apache 2.2.8",
                },
            },
            "brute_force_ssh": {
                "acces_valides": [
                    {"utilisateur": "msfadmin", "mot_de_passe": "msfadmin", "whoami": "msfadmin"},
                    {"utilisateur": "user", "mot_de_passe": "user", "whoami": "user"},
                ],
            },
            "sql_injection": {
                "reponses": [
                    {"extraits_bdd": ["admin  →  5f4dcc3b5aa765d61d8327deb882cf99"]},
                ],
            },
            "path_traversal": {
                "reponses": [
                    {"code_http": 200, "payload": "../../../../etc/passwd"},
                ],
            },
        },
    }
    pentest_file.write_text(json.dumps(pentest_data), encoding="utf-8")
    alerts_file.write_text("[]", encoding="utf-8")

    analyzer = LogAnalyzer(nids_alerts=alerts_file, pentest_results=pentest_file)
    texte = analyzer.generer_synthese_texte()

    assert "msfadmin:msfadmin" in texte
    assert "user:user" in texte
    assert "admin  →  5f4dcc3b5aa765d61d8327deb882cf99" in texte
    assert "vsFTPd 2.3.4" in texte
    assert "OpenSSH 4.7p1" in texte
    assert "Apache 2.2.8" in texte
    assert "/etc/passwd" in texte
    assert "Linux 2.6.X" in texte


def test_generer_graphiques_avec_donnees(tmp_path):
    """Vérifie que generer_graphiques exporte bien les 5 visuels PNG haute résolution."""
    alerts_file = tmp_path / "nids_alerts.json"
    alerts = [
        {"type": "SCAN_PORTS", "src_ip": "192.168.1.10", "severite": "MOYENNE", "timestamp": "2026-10-29T10:15:00"},
        {"type": "BRUTE_FORCE", "src_ip": "192.168.1.50", "severite": "ELEVEE", "timestamp": "2026-10-29T10:16:00"},
        {"type": "SQL_INJECTION", "src_ip": "192.168.1.50", "severite": "CRITIQUE", "timestamp": "2026-10-29T10:17:00"},
    ]
    alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

    dossier_sortie = tmp_path / "analysis_graphs"
    analyzer = LogAnalyzer(nids_alerts=alerts_file)
    fichiers = analyzer.generer_graphiques(dossier_sortie=dossier_sortie)

    assert len(fichiers) == 5
    noms = {f.name for f in fichiers}
    assert "alertes_par_type.png" in noms
    assert "timeline_alertes.png" in noms
    assert "top_sources_ips.png" in noms
    assert "activite_cible_metasploitable.png" in noms
    assert "matrice_detection_pentest.png" in noms

    for f in fichiers:
        assert f.exists()
        assert f.stat().st_size > 1000  # Fichier image non vide


def test_generer_graphiques_vide(tmp_path):
    """Vérifie la robustesse de la génération graphique en cas de données vides."""
    empty_alerts = tmp_path / "empty_alerts.json"
    empty_alerts.write_text("[]", encoding="utf-8")

    dossier_sortie = tmp_path / "empty_graphs"
    analyzer = LogAnalyzer(nids_alerts=empty_alerts)
    fichiers = analyzer.generer_graphiques(dossier_sortie=dossier_sortie)

    assert len(fichiers) == 5
    for f in fichiers:
        assert f.exists()
        assert f.stat().st_size > 1000


