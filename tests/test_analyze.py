"""
Tests unitaires pour LogAnalyzer (analyse des alertes NIDS et des logs Metasploitable 2).
"""

from analyze import LogAnalyzer


def test_analyse_alertes_nids():
    analyzer = LogAnalyzer()
    stats = analyzer.analyser_alertes_nids()
    assert "total" in stats
    assert "types" in stats
    assert "top_sources" in stats


def test_analyse_logs_metasploitable():
    analyzer = LogAnalyzer()
    stats = analyzer.analyser_logs_metasploitable()
    assert "total_evenements" in stats
    assert "sessions" in stats
    assert "logins_echoues" in stats
    assert "logins_reussis" in stats
