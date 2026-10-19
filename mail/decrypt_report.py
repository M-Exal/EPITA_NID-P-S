#!/usr/bin/env python3
"""
decrypt_report.py — Déchiffre un rapport reçu par e-mail.

Le destinataire du rapport l'exécute avec la clé Fernet partagée :

    python3 decrypt_report.py rapport.enc
    NIDS_FERNET_KEY="xxxxx=" python3 decrypt_report.py rapport.enc rapport.txt

La clé est lue dans la variable d'environnement NIDS_FERNET_KEY, ou dans le
fichier secret.key du dossier courant.
"""

import os
import sys

from crypto_utils import charger_ou_creer_cle, dechiffrer_fichier


def main():
    if len(sys.argv) < 2:
        print("Usage : python3 decrypt_report.py <fichier.enc> [sortie.txt]")
        sys.exit(1)

    source = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) > 2 else source.replace(".enc", "") + ".dechiffre.txt"

    cle = charger_ou_creer_cle(os.environ.get("NIDS_FERNET_KEY", ""), "secret.key")
    try:
        dechiffrer_fichier(source, dest, cle)
        print(f"[OK] Rapport déchiffré dans : {dest}")
        with open(dest, "r", encoding="utf-8", errors="ignore") as f:
            print("\n----- CONTENU -----\n")
            print(f.read())
    except Exception as e:  # noqa: BLE001 — InvalidToken si clé fausse/altéré
        print(f"[ERREUR] Déchiffrement impossible : {e}")
        print("Vérifiez que la clé (NIDS_FERNET_KEY) correspond à l'émetteur.")
        sys.exit(1)


if __name__ == "__main__":
    main()
