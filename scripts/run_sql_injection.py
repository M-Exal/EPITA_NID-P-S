#!/usr/bin/env python3
"""
Script standalone : Injection SQL contre l'application DVWA.

Usage :
    python run_sql_injection.py [TARGET_HOST]
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
    port = Config.HTTP_PORT
    print(f"[*] Cible : http://{cible}:{port}/dvwa/vulnerabilities/sqli/", flush=True)
    print(f"[*] Démarrage de l'injection SQL — {cible}:{port}", flush=True)
    print("-" * 60, flush=True)

    pentester = Pentester(cfg=Config)

    try:
        pentester.sql_injection()
        pentester.sauvegarder()
        stats = pentester.resultats["attaques"].get("sql_injection", {})
        if stats:
            print(
                f"[+] Synthèse SQL Injection : {stats.get('payloads_testes', 0)} payload(s) testé(s), status={stats.get('status')}",
                flush=True,
            )
        else:
            print("[~] Aucun résultat retourné.", flush=True)
    except Exception as exc:
        print(f"[!] Erreur durant l'attaque : {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    print("-" * 60, flush=True)
    print("[*] Injection SQL terminée.", flush=True)


if __name__ == "__main__":
    main()
