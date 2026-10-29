#!/usr/bin/env python3
"""
Script standalone : Scan furtif NULL (aucun drapeau TCP) contre la cible.

Usage :
    python run_null_scan.py [TARGET_HOST]
"""

import os
import sys

# Forçage du line-buffering pour affichage temps réel dans le terminal web
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(REPO_ROOT, "pentest"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "pentest")),
    "/app/pentest",
]:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

if len(sys.argv) > 1:
    os.environ["TARGET_HOST"] = sys.argv[1]

try:
    from config import Config
    from pentest import Pentester
except ImportError:
    from pentest.config import Config
    from pentest.pentest import Pentester


def main():
    cible = os.getenv("TARGET_HOST", Config.TARGET_HOST)
    print(f"[*] Cible : {cible}", flush=True)
    print(f"[*] Démarrage du Scan Furtif NULL (flags=0) — {cible}", flush=True)
    print("-" * 60, flush=True)

    pentester = Pentester(cfg=Config)

    try:
        ouverts = pentester.null_scan()
        pentester.sauvegarder()
        stats = pentester.resultats["attaques"].get("null_scan", {})
        statut = stats.get('status', 'inconnu')
        nb_pkts = stats.get('paquets_envoyes', 0)
        fermes = stats.get('ports_fermes', [])
        os_det = stats.get('os_detecte', 'Non déterminé')

        print(f"[+] Ports OUVERTS (silence RFC 793) : {ouverts}", flush=True)
        print(f"[-] Ports FERMÉS (RST reçu) : {fermes}", flush=True)
        print(f"[+] Fingerprinting OS : {os_det}", flush=True)
        print(f"[+] Résultat NULL : {statut} ({nb_pkts} paquets)", flush=True)
        print(f"[*] {len(ouverts)} port(s) ouvert(s) configurés pour l'attaque DoS.", flush=True)
    except Exception as exc:
        print(f"[!] Erreur durant l'attaque : {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    print("-" * 60, flush=True)
    print("[*] Scan NULL terminé.", flush=True)


if __name__ == "__main__":
    main()
