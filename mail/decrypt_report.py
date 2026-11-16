"""
Outil CLI pour déchiffrer un rapport NIDS reçu.
"""

import argparse
import os
import sys
from crypto_utils import dechiffrer_fichier


def main():
    parser = argparse.ArgumentParser(description="Déchiffrer un rapport NIDS chiffré (.enc).")
    parser.add_argument("fichier_chiffre", help="Chemin du fichier chiffré (.enc)")
    parser.add_argument(
        "--key",
        "-k",
        required=False,
        help="Clé Fernet (chaîne base64). Si omise, tente de lire data/nids/secret.key ou la variable NIDS_FERNET_KEY.",
    )
    parser.add_argument("--output", "-o", help="Chemin de sortie pour le fichier en clair")
    args = parser.parse_args()

    chemin_chiffre = os.path.expanduser(args.fichier_chiffre)
    if not os.path.exists(chemin_chiffre):
        print(f"[!] Fichier introuvable : {chemin_chiffre}", file=sys.stderr)
        sys.exit(1)

    cle_str = args.key or os.getenv("NIDS_FERNET_KEY", "")
    if not cle_str:
        # Recherche locale automatique de secret.key
        candidats_cle = [
            os.path.join(os.path.dirname(__file__), "..", "data", "nids", "secret.key"),
            "data/nids/secret.key",
            "secret.key",
        ]
        for c in candidats_cle:
            if os.path.isfile(c):
                with open(c, "r", encoding="utf-8") as f:
                    cle_str = f.read().strip()
                print(f"[*] Clé chargée automatiquement depuis {c}")
                break

    if not cle_str:
        print("[!] Aucune clé fournie. Spécifiez --key <CLE> ou définissez NIDS_FERNET_KEY.", file=sys.stderr)
        sys.exit(1)

    try:
        donnees = dechiffrer_fichier(chemin_chiffre, args.output, cle_str.encode("utf-8"))
        if args.output:
            print(f"[+] Rapport déchiffré enregistré dans : {args.output}")
        else:
            print("\n--- RAPPORT DÉCHIFFRÉ ---")
            print(donnees.decode("utf-8", errors="ignore"))
    except Exception as e:
        print(f"[!] Erreur de déchiffrement : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
