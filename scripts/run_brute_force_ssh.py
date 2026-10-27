#!/usr/bin/env python3
"""
Script standalone : Brute Force SSH contre Metasploitable 2.

Usage :
    python run_brute_force_ssh.py [TARGET_HOST]

La cible peut aussi être définie via la variable d'environnement TARGET_HOST.
"""

import os
import sys

# Permet d'importer pentest.py depuis ce script lancé en subprocess
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PENTEST_DIR = os.path.join(REPO_ROOT, "pentest")
sys.path.insert(0, PENTEST_DIR)

# Surcharge TARGET_HOST si passé en argv
if len(sys.argv) > 1:
    os.environ["TARGET_HOST"] = sys.argv[1]

from config import Config  # noqa: E402 — importé après le sys.path
from pentest import Pentester  # noqa: E402


def main():
    cible = os.getenv("TARGET_HOST", Config.TARGET_HOST)
    print(f"[*] Cible : {cible}:22")
    print(f"[*] Démarrage du Brute Force SSH — {cible}:22")
    print("-" * 60)

    pentester = Pentester(cfg=Config)

    try:
        pentester.brute_force_ssh()
        stats = pentester.resultats["attaques"].get("brute_force_ssh", {})
        if stats:
            print("[+] Synthèse brute_force_ssh :")
            for k, v in stats.items():
                if k != "paires_testees":
                    print(f"    {k}: {v}")
            print(f"    paires_testees: {len(stats.get('paires_testees', []))} combinaisons")
        else:
            print("[~] Aucun résultat retourné.")
    except Exception as exc:
        print(f"[!] Erreur durant l'attaque : {exc}", file=sys.stderr)
        sys.exit(1)

    print("-" * 60)
    print("[*] Attaque terminée.")


if __name__ == "__main__":
    main()
