#!/usr/bin/env python3
"""
Simulateur d'attaques pour valider la supervision temps réel du SIEM.
Injecte les 7 attaques du pentest une par une avec un intervalle réglable.
"""

import json
import os
import sys
import time
from datetime import datetime

FICHIER_ALERTES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "nids", "nids_alerts.json")
)

SCENARIOS = [
    {
        "type": "SCAN_PORTS",
        "src_ip": "172.19.0.4",
        "details": "SYN scan furtif détecté sur 20 ports en 4s",
    },
    {
        "type": "XMAS_SCAN",
        "src_ip": "172.19.0.4",
        "details": "Drapeaux illégaux FIN+PSH+URG détectés",
    },
    {
        "type": "BRUTE_FORCE",
        "src_ip": "172.19.0.4",
        "details": "12 tentatives de connexion SSH avec comptes 'root', 'admin'",
    },
    {
        "type": "DOS",
        "src_ip": "172.19.0.4",
        "details": "SYN flood volumétrique détecté : 320 paquets/s sur port 22",
    },
    {
        "type": "SQL_INJECTION",
        "src_ip": "172.19.0.7",
        "details": "Payload détecté : ' UNION SELECT null, username, password FROM users --",
    },
    {
        "type": "XSS",
        "src_ip": "172.19.0.7",
        "details": "Payload script web détecté : <script>alert('XSS')</script>",
    },
    {
        "type": "PATH_TRAVERSAL",
        "src_ip": "172.19.0.7",
        "details": "Traversée d'arborescence : ../../../../etc/shadow",
    },
]


def injecter_alerte(scenario):
    os.makedirs(os.path.dirname(FICHIER_ALERTES), exist_ok=True)
    alertes = []
    if os.path.exists(FICHIER_ALERTES):
        try:
            with open(FICHIER_ALERTES, "r", encoding="utf-8") as f:
                alertes = json.load(f)
        except Exception:
            alertes = []

    nouvelle_entree = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type": scenario["type"],
        "src_ip": scenario["src_ip"],
        "details": scenario["details"],
    }
    alertes.append(nouvelle_entree)

    with open(FICHIER_ALERTES, "w", encoding="utf-8") as f:
        json.dump(alertes, f, indent=2, ensure_ascii=False)

    return nouvelle_entree


def main():
    delai = 2.5
    if len(sys.argv) > 1:
        try:
            delai = float(sys.argv[1])
        except ValueError:
            pass

    print("=" * 65)
    print("  SIMULATEUR D'ATTAQUES TEMPS RÉEL — SUPERVISION SIEM")
    print(f"  Fichier cible : {FICHIER_ALERTES}")
    print(f"  Intervalle    : {delai} secondes")
    print("=" * 65)
    print("Ouvrez http://localhost:5050 dans votre navigateur pour observer le direct !\n")

    for i, s in enumerate(SCENARIOS, 1):
        time.sleep(delai)
        entree = injecter_alerte(s)
        print(f"[{i}/{len(SCENARIOS)}] 🚨 [{entree['timestamp']}] {entree['type']} depuis {entree['src_ip']}")
        print(f"       -> {entree['details']}")

    print("\n✅ Simulation terminée ! Toutes les attaques ont été envoyées au SIEM.")


if __name__ == "__main__":
    main()
