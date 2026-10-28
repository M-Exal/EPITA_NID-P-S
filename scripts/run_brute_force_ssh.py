#!/usr/bin/env python3
"""
Script standalone : Brute Force SSH contre Metasploitable 2.

Usage :
    python run_brute_force_ssh.py [TARGET_HOST]
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
    print(f"[*] Cible : {cible}:{Config.SSH_PORT}", flush=True)
    print(f"[*] Démarrage du Brute Force SSH — {cible}:{Config.SSH_PORT}", flush=True)
    print("-" * 60, flush=True)

    pentester = Pentester(cfg=Config)

    try:
        pentester.brute_force_ssh()
        pentester.sauvegarder()
        stats = pentester.resultats["attaques"].get("brute_force_ssh", {})
        if stats:
            print("[+] Synthèse brute_force_ssh :", flush=True)
            for k, v in stats.items():
                if k != "paires_testees":
                    print(f"    {k}: {v}", flush=True)
            print(f"    paires_testees: {len(stats.get('paires_testees', []))} combinaisons", flush=True)
        else:
            print("[~] Aucun résultat retourné.", flush=True)
    except Exception as exc:
        print(f"[!] Erreur durant l'attaque : {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    print("-" * 60, flush=True)
    print("[*] Attaque terminée.", flush=True)


if __name__ == "__main__":
    main()
