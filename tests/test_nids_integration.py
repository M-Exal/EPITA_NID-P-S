"""
test_nids_integration.py — Test d'intégration du NIDS de bout en bout.

On rejoue un fichier .pcap dans le vrai `nids.py` (sous-processus) :
capture -> analyse -> alertes -> résumé, sans interface réseau ni envoi
de courriel. Deux scénarios :

  * un flux d'attaques (scan, DoS, brute-force, injection SQL) ;
  * un flux de trafic normal qui ne doit lever AUCUNE alerte
    (validation « pas de fausses alertes » du cahier des charges).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

from conftest import RACINE

NIDS = RACINE / "nids" / "nids.py"


def _rejouer(pcap, tmp_path):
    """Exécute nids.py --pcap puis relit le journal d'alertes produit."""
    data = tmp_path / "data"
    env = {**os.environ, "NIDS_DATA_DIR": str(data)}
    resultat = subprocess.run(
        [sys.executable, str(NIDS), "--pcap", str(pcap), "--no-mail"],
        capture_output=True, text=True, env=env,
        cwd=str(RACINE / "nids"), timeout=120,
    )
    assert resultat.returncode == 0, resultat.stdout + resultat.stderr

    journal = data / "nids_alerts.json"
    alertes = []
    if journal.exists():
        alertes = [json.loads(l) for l in journal.read_text(encoding="utf-8").splitlines()]
    return resultat, alertes


def test_flux_attaques_detecte(tmp_path):
    """Chaque type d'attaque du pentest doit être détecté par le NIDS."""
    paquets = []

    # 1. Scan de ports : 20 ports distincts (> seuil de 15) depuis une IP.
    for port in range(1000, 1021):
        paquets.append(IP(src="10.10.0.1") / TCP(dport=port, flags="S"))

    # 2. DoS : 250 paquets depuis une même IP (> seuil de 200).
    for _ in range(250):
        paquets.append(IP(src="10.10.0.2") / TCP(dport=80, flags="S"))

    # 3. Brute-force : SYN répétés vers le port SSH du honeypot (> seuil 10).
    for _ in range(12):
        paquets.append(IP(src="10.10.0.3") / TCP(dport=2222, flags="S"))

    # 4. Injection SQL : motif reconnu dans la charge utile.
    paquets.append(IP(src="10.10.0.4") / TCP(dport=80)
                   / Raw(load=b"1 UNION SELECT password FROM users"))

    pcap = tmp_path / "attaques.pcap"
    wrpcap(str(pcap), paquets)

    resultat, alertes = _rejouer(pcap, tmp_path)

    types = {a["type"] for a in alertes}
    assert {"SCAN_PORTS", "DOS", "BRUTE_FORCE", "SQL_INJECTION"} <= types
    assert {a["source_ip"] for a in alertes} >= {"10.10.0.1", "10.10.0.2",
                                                 "10.10.0.3", "10.10.0.4"}
    assert f"{len(paquets)} paquets analysés" in resultat.stdout
    assert "Total d'alertes" in resultat.stdout


def test_trafic_normal_aucune_alerte(tmp_path):
    """Validation : en condition normale, le NIDS reste silencieux."""
    paquets = []
    ip = "192.168.10.20"

    # Échanges TCP classiques (peu de ports, peu de paquets).
    for port in (80, 443):
        paquets.append(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="S"))
        paquets.append(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="SA"))
        paquets.append(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="A"))

    # Requêtes HTTP bénignes.
    for ressource in ("/", "/index.html", "/style.css", "/logo.png"):
        charge = f"GET {ressource} HTTP/1.1\r\nHost: example.com\r\n\r\n"
        paquets.append(IP(src=ip) / TCP(dport=80) / Raw(load=charge.encode()))

    # Réponse DNS et ping.
    paquets.append(IP(src=ip) / TCP(dport=53, sport=40100, flags="S"))
    paquets.append(IP(src=ip) / Raw(load=b"\xf1\x82\x01\x00example"))

    pcap = tmp_path / "normal.pcap"
    wrpcap(str(pcap), paquets)

    resultat, alertes = _rejouer(pcap, tmp_path)

    assert alertes == []
    assert "Aucune alerte relevée" in resultat.stdout
