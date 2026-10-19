"""
Outil CLI pour déchiffrer un rapport NIDS reçu.
"""

import argparse
import sys
from crypto_utils import dechiffrer_fichier


def main():
    parser = argparse.ArgumentParser(description="Déchiffrer un rapport NIDS chiffré.")
    parser.add_argument("fichier_chiffre", help="Chemin du fichier chiffré (.enc)")
    parser.add_argument("--key", required=True, help="Clé Fernet (chaîne base64)")
    parser.add_argument("--output", "-o", help="Chemin de sortie pour le fichier en clair")
    args = parser.parse_args()

    try:
        donnees = dechiffrer_fichier(args.fichier_chiffre, args.output, args.key.encode())
        if args.output:
            print(f"[+] Rapport déchiffré dans : {args.output}")
        else:
            print("\n--- RAPPORT DÉCHIFFRÉ ---")
            print(donnees.decode(errors="ignore"))
    except Exception as e:
        print(f"[!] Erreur de déchiffrement : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
