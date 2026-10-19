"""
test_analysis.py — Tests de la récupération et de l'analyse des données
du honeypot Cowrie (journal cowrie.json au format JSON Lines).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import RACINE, charger


# Jeu d'évènements représentatif d'une session de brute-force suivie d'une
# connexion réussie puis de commandes exécutées dans le faux shell.
EVENEMENTS = [
    {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "dst_port": 2222,
     "timestamp": "2025-11-20T10:00:00.000000Z"},
    {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4",
     "username": "root", "password": "123456"},
    {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4",
     "username": "root", "password": "admin"},
    {"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4",
     "username": "admin", "password": "root"},
    {"eventid": "cowrie.login.failed", "src_ip": "9.9.9.9",
     "username": "admin", "password": "admin"},
    {"eventid": "cowrie.login.success", "src_ip": "5.6.7.8",
     "username": "admin", "password": "admin"},
    {"eventid": "cowrie.command.input", "src_ip": "5.6.7.8", "input": "ls -la"},
    {"eventid": "cowrie.command.input", "src_ip": "5.6.7.8", "input": "cat /etc/passwd"},
    # Évènement hors périmètre : ne doit pas apparaître dans "attacks".
    {"eventid": "metrique.interne", "src_ip": "5.6.7.8"},
]


@pytest.fixture
def journal(tmp_path):
    """Écrit un cowrie.json valide + une ligne corrompue (fichier tronqué)."""
    chemin = tmp_path / "cowrie.json"
    with open(chemin, "w", encoding="utf-8") as f:
        for evenement in EVENEMENTS:
            f.write(json.dumps(evenement) + "\n")
        f.write('{"eventid": "cowrie.login.failed", "src_ip"')  # ligne coupée
    return str(chemin)


@pytest.fixture
def analyse():
    return charger("analysis", "analyze")


def test_recuperation_journal(analyse, journal):
    donnees = analyse.fetch_honeypot_data(journal)

    # La ligne corrompue est ignorée, les autres sont toutes lues.
    assert len(donnees["evenements"]) == len(EVENEMENTS)
    # "attacks" filtre les évènements de connexion / commande / session.
    assert len(donnees["attacks"]) == len(EVENEMENTS) - 1
    assert all(str(e["eventid"]).startswith(
        ("cowrie.login", "cowrie.command", "cowrie.session"))
        for e in donnees["attacks"])


def test_recuperation_journal_inexistant(analyse, tmp_path):
    donnees = analyse.fetch_honeypot_data(str(tmp_path / "absent.json"))
    assert donnees == {"attacks": [], "evenements": []}


def test_analyse_statistiques(analyse, journal):
    donnees = analyse.fetch_honeypot_data(journal)
    df = analyse.charger_dataframe(donnees["evenements"])
    resultats = analyse.analyser(df)

    assert resultats["ip_actives"].index[0] == "1.2.3.4"   # 4 évènements
    assert resultats["usernames"].index[0] == "admin"
    assert resultats["usernames"]["root"] == 2
    assert resultats["passwords"].index[0] == "admin"
    assert resultats["commandes"].index[0] in ("ls -la", "cat /etc/passwd")
    assert resultats["login_resultats"]["cowrie.login.failed"] == 4
    assert resultats["login_resultats"]["cowrie.login.success"] == 1


def test_analyse_dataframe_vide(analyse):
    df = analyse.charger_dataframe([])
    assert df.empty
    assert analyse.analyser(df) == {}


def test_rapport_et_graphiques(analyse, journal, tmp_path):
    donnees = analyse.fetch_honeypot_data(journal)
    df = analyse.charger_dataframe(donnees["evenements"])
    resultats = analyse.analyser(df)

    sortie = tmp_path / "analyse"
    fichiers = analyse.generer_graphiques(resultats, str(sortie))
    assert len(fichiers) >= 3
    for chemin in fichiers:
        assert os.path.exists(chemin)
        assert chemin.endswith(".png")

    rapport = analyse.generer_rapport(
        resultats, str(sortie / "rapport_analyse.txt"))
    assert "IP les plus actives" in rapport
    assert "1.2.3.4" in rapport
    assert Path(sortie / "rapport_analyse.txt").exists()


def test_rapport_sans_donnees(analyse, tmp_path):
    rapport = analyse.generer_rapport({}, str(tmp_path / "vide.txt"))
    assert "Aucune donnée à analyser" in rapport


def test_cli_analyse_complet(analyse, journal, tmp_path):
    """Exécution de bout en bout en sous-processus (usage documenté)."""
    sortie = tmp_path / "out"
    resultat = subprocess.run(
        [sys.executable, str(RACINE / "analysis" / "analyze.py"),
         "--log", journal, "--out", str(sortie)],
        capture_output=True, text=True, cwd=RACINE / "analysis",
        timeout=180,
    )
    assert resultat.returncode == 0, resultat.stderr
    assert (sortie / "rapport_analyse.txt").exists()
    assert list(sortie.glob("*.png"))
