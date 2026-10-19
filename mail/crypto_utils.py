"""
crypto_utils.py — Chiffrement du rapport de détection.

Le cahier des charges impose que « le rapport de détection final devra vous
être envoyé par courriel, de manière chiffrée ». On utilise la bibliothèque
`cryptography` (Fernet = AES-128 en mode CBC + HMAC), vue en cours dans la
fiche « bibliothèques chiffrement ».

Fernet garantit à la fois la confidentialité (chiffrement) et l'intégrité
(authentification via HMAC) : un rapport modifié en transit est rejeté au
déchiffrement.
"""

import os

from cryptography.fernet import Fernet


def charger_ou_creer_cle(key_env="", key_file="secret.key"):
    """
    Récupère la clé Fernet.

    Priorité :
      1. La variable d'environnement (clé partagée entre l'émetteur et le
         destinataire) ;
      2. Sinon, un fichier `secret.key` (créé automatiquement s'il n'existe pas).

    :return: la clé au format bytes, utilisable par Fernet.
    """
    # 1. Clé fournie via l'environnement.
    if key_env:
        return key_env.encode() if isinstance(key_env, str) else key_env

    # 2. Clé stockée dans un fichier.
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read().strip()

    # 3. Génération d'une nouvelle clé et sauvegarde.
    cle = Fernet.generate_key()
    os.makedirs(os.path.dirname(key_file) or ".", exist_ok=True)
    with open(key_file, "wb") as f:
        f.write(cle)
    print(f"[CRYPTO] Nouvelle clé générée et sauvegardée dans {key_file}")
    print(f"[CRYPTO] Clé (à partager avec le destinataire) : {cle.decode()}")
    return cle


def chiffrer_fichier(chemin_source, chemin_dest, cle):
    """
    Chiffre le contenu d'un fichier et écrit le résultat dans `chemin_dest`.

    :param chemin_source: fichier en clair (ex. nids_alerts.log).
    :param chemin_dest:   fichier chiffré de sortie (ex. rapport.enc).
    :param cle:           clé Fernet (bytes).
    :return: le chemin du fichier chiffré.
    """
    fernet = Fernet(cle)
    with open(chemin_source, "rb") as f:
        donnees = f.read()
    donnees_chiffrees = fernet.encrypt(donnees)
    with open(chemin_dest, "wb") as f:
        f.write(donnees_chiffrees)
    return chemin_dest


def dechiffrer_fichier(chemin_source, chemin_dest, cle):
    """
    Déchiffre un fichier produit par `chiffrer_fichier`.

    :param chemin_source: fichier chiffré (.enc).
    :param chemin_dest:   fichier en clair de sortie.
    :param cle:           clé Fernet (bytes).
    :return: le chemin du fichier déchiffré.
    """
    fernet = Fernet(cle)
    with open(chemin_source, "rb") as f:
        donnees_chiffrees = f.read()
    donnees = fernet.decrypt(donnees_chiffrees)  # lève InvalidToken si altéré
    with open(chemin_dest, "wb") as f:
        f.write(donnees)
    return chemin_dest


def chiffrer_texte(texte, cle):
    """Chiffre une chaîne de caractères et renvoie le token (bytes)."""
    fernet = Fernet(cle)
    return fernet.encrypt(texte.encode())


if __name__ == "__main__":
    # Petit utilitaire en ligne de commande : génération de clé.
    #   python crypto_utils.py genkey
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "genkey":
        print(Fernet.generate_key().decode())
    else:
        print("Usage : python crypto_utils.py genkey")
