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
        resultats = pentester.brute_force_ssh()
        if resultats:
            print(f"[+] Résultats brute_force_ssh :")
            for k, v in resultats.items():
                print(f"    {k}: {v}")
        else:
            print("[~] Aucun résultat retourné par brute_force_ssh().")
    except Exception as exc:
        print(f"[!] Erreur durant l'attaque : {exc}", file=sys.stderr)
        sys.exit(1)

    print("-" * 60)
    print("[*] Attaque terminée.")


if __name__ == "__main__":
    main()
