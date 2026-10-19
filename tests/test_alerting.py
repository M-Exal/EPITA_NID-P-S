"""
test_alerting.py — Tests du système d'alertes et du rapport chiffré.

Vérifie :
  * la journalisation console + .log + .json de `AlertManager` ;
  * le résumé final ;
  * le chiffrement Fernet du rapport et son envoi mail (chemins sans
    identifiants SMTP -> échec propre, sans tentative réseau) ;
  * le déchiffrement (round-trip) et la détection d'une altération.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken

from conftest import RACINE, charger


@pytest.fixture
def alert_manager(nids_config):
    alerting = charger("nids", "alerting")
    return alerting.AlertManager(nids_config)


def test_alerte_ecrite_dans_les_trois_supports(alert_manager, nids_config):
    alert_manager.log_alert("SCAN_PORTS", "10.0.0.1", "(20 ports en 10 s)")
    alert_manager.log_alert("DOS", "10.0.0.2", "(250 paquets en 5 s)")

    # 1. Journal texte (format du cours : "%(asctime)s - %(message)s").
    log = Path(nids_config.ALERT_LOG).read_text(encoding="utf-8")
    assert "[SCAN_PORTS] depuis 10.0.0.1" in log
    assert "[DOS] depuis 10.0.0.2" in log

    # 2. Journal JSON structuré (une ligne = une alerte).
    lignes = Path(nids_config.ALERT_JSON).read_text(encoding="utf-8").splitlines()
    evenements = [json.loads(l) for l in lignes]
    assert [e["type"] for e in evenements] == ["SCAN_PORTS", "DOS"]
    assert evenements[0]["source_ip"] == "10.0.0.1"
    assert "timestamp" in evenements[0]

    # 3. Compteurs et résumé.
    resume = alert_manager.resume()
    assert "Total d'alertes : 2" in resume
    assert "SCAN_PORTS : 1" in resume


def test_resume_sans_alerte(alert_manager):
    assert "Aucune alerte relevée" in alert_manager.resume()


def test_alertes_multiples_sur_des_fichiers_distincts(alert_manager, nids_config):
    """Deux AlertManager successifs écrivent chacun dans LEUR fichier
    (le logger n'hérite pas du premier chemin installé)."""
    alert_manager.log_alert("DOS", "10.0.0.9")

    autre_cfg = nids_config
    autre_cfg.ALERT_LOG = nids_config.DATA_DIR + "/second.log"
    autre_cfg.ALERT_JSON = nids_config.DATA_DIR + "/second.json"
    alerting = charger("nids", "alerting")
    second = alerting.AlertManager(autre_cfg)
    second.log_alert("XSS", "10.0.0.10")

    assert "10.0.0.9" not in Path(autre_cfg.ALERT_LOG).read_text(encoding="utf-8")
    assert "10.0.0.10" in Path(autre_cfg.ALERT_LOG).read_text(encoding="utf-8")


# ======================================================================
# Chiffrement du rapport (exigence « rapport chiffré »)
# ======================================================================
def test_generer_et_dechiffrer_rapport(alert_manager, nids_config, tmp_path):
    alert_manager.log_alert("BRUTE_FORCE", "10.0.0.3")
    crypto = charger("nids", "crypto_utils")

    cle = crypto.charger_ou_creer_cle("", nids_config.KEY_FILE)
    assert os.path.exists(nids_config.KEY_FILE)

    chiffre = crypto.chiffrer_fichier(nids_config.ALERT_LOG, str(tmp_path / "rapport.enc"), cle)
    brut = Path(chiffre).read_bytes()
    assert b"BRUTE_FORCE" not in brut  # rien de lisible en clair

    sortie = crypto.dechiffrer_fichier(chiffre, str(tmp_path / "rapport.txt"), cle)
    assert "BRUTE_FORCE" in Path(sortie).read_text(encoding="utf-8")


def test_cle_depuis_environnement(tmp_path, monkeypatch):
    crypto = charger("nids", "crypto_utils")
    cle = crypto.charger_ou_creer_cle("", str(tmp_path / "k.key"))
    monkeypatch.setenv("NIDS_FERNET_KEY", cle.decode())
    assert crypto.charger_ou_creer_cle(os.environ["NIDS_FERNET_KEY"], "") == cle


def test_dechiffrement_avec_mauvaise_cle_echoue(nids_config, tmp_path):
    crypto = charger("nids", "crypto_utils")
    cle_a = crypto.charger_ou_creer_cle("", str(tmp_path / "a.key"))
    cle_b = crypto.charger_ou_creer_cle("", str(tmp_path / "b.key"))

    source = tmp_path / "src.txt"
    source.write_text("rapport secret", encoding="utf-8")
    chiffre = crypto.chiffrer_fichier(str(source), str(tmp_path / "src.enc"), cle_a)

    with pytest.raises(InvalidToken):
        crypto.dechiffrer_fichier(chiffre, str(tmp_path / "out.txt"), cle_b)


def test_rapport_altere_rejete(nids_config, tmp_path):
    """Fernet : toute modification du fichier chiffré invalide le HMAC."""
    crypto = charger("nids", "crypto_utils")
    cle = crypto.charger_ou_creer_cle("", str(tmp_path / "k.key"))
    source = tmp_path / "src.txt"
    source.write_text("contenu du rapport", encoding="utf-8")
    chiffre = crypto.chiffrer_fichier(str(source), str(tmp_path / "src.enc"), cle)

    donnees = bytearray(Path(chiffre).read_bytes())
    donnees[10] ^= 0xFF
    Path(chiffre).write_bytes(bytes(donnees))

    with pytest.raises(InvalidToken):
        crypto.dechiffrer_fichier(chiffre, str(tmp_path / "out.txt"), cle)


# ======================================================================
# Envoi mail : échecs propres quand la configuration manque
# ======================================================================
def test_envoi_sans_identifiants_echoue_proprement(alert_manager, nids_config, monkeypatch):
    alert_manager.log_alert("DOS", "10.0.0.2")
    for var in ("SMTP_USER", "SMTP_PASSWORD", "REPORT_RECEIVER", "NIDS_FERNET_KEY"):
        monkeypatch.delenv(var, raising=False)
    nids_config.SMTP_USER = ""
    nids_config.SMTP_PASSWORD = ""
    nids_config.REPORT_RECEIVER = ""

    alerting = charger("nids", "alerting")
    assert alerting.envoyer_mail(nids_config) is False


def test_envoi_fichier_inexistent_echoue_proprement(alert_manager, nids_config, monkeypatch):
    monkeypatch.setattr(nids_config, "SMTP_USER", "u@example.com")
    monkeypatch.setattr(nids_config, "SMTP_PASSWORD", "mdp")
    monkeypatch.setattr(nids_config, "REPORT_RECEIVER", "dest@example.com")
    alerting = charger("nids", "alerting")
    assert alerting.envoyer_mail(nids_config, fichier_a_envoyer="/introuvable.log") is False


def test_send_report_manuel_sans_config(nids_config, monkeypatch, tmp_path):
    """mail/send_report.py : refus propre si identifiants absents."""
    for var in ("REPORT_SENDER", "REPORT_RECEIVER", "SMTP_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    mail = charger("mail", "send_report")
    cible = tmp_path / "rapport.txt"
    cible.write_text("analyse", encoding="utf-8")
    assert mail.envoyer_email_gmail(str(cible)) is False


def test_decrypt_cli(tmp_path):
    """La CLI de déchiffrement fonctionne de bout en bout (sous-processus)."""
    crypto = charger("nids", "crypto_utils")
    cle = crypto.charger_ou_creer_cle("", str(tmp_path / "secret.key"))
    source = tmp_path / "rapport.txt"
    source.write_text("Rapport NIDS : 3 alertes", encoding="utf-8")
    chiffre = crypto.chiffrer_fichier(str(source), str(tmp_path / "rapport.enc"), cle)

    resultat = subprocess.run(
        [sys.executable, str(RACINE / "mail" / "decrypt_report.py"), chiffre],
        capture_output=True, text=True,
        env={**os.environ, "NIDS_FERNET_KEY": cle.decode()},
        cwd=tmp_path, timeout=60,
    )
    assert resultat.returncode == 0, resultat.stderr
    assert "Rapport NIDS : 3 alertes" in resultat.stdout
    assert (tmp_path / "rapport.dechiffre.txt").exists()
