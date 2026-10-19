"""
Utilitaires de chiffrement symétrique pour le module de messagerie (Fernet).
"""

import os
from cryptography.fernet import Fernet


def generer_cle():
    """Génère une nouvelle clé symétrique Fernet."""
    return Fernet.generate_key()


def charger_ou_creer_cle(chemin_cle):
    """Charge ou crée une clé Fernet."""
    if os.path.exists(chemin_cle):
        with open(chemin_cle, "rb") as f:
            return f.read().strip()

    os.makedirs(os.path.dirname(os.path.abspath(chemin_cle)), exist_ok=True)
    cle = generer_cle()
    with open(chemin_cle, "wb") as f:
        f.write(cle)
    return cle


def chiffrer_fichier(chemin_source, chemin_destination, cle):
    """Chiffre un fichier source vers une destination."""
    fernet = Fernet(cle)
    with open(chemin_source, "rb") as f:
        donnees = f.read()

    chiffre = fernet.encrypt(donnees)
    os.makedirs(os.path.dirname(os.path.abspath(chemin_destination)), exist_ok=True)
    with open(chemin_destination, "wb") as f:
        f.write(chiffre)

    return len(chiffre)


def dechiffrer_fichier(chemin_chiffre, chemin_clair, cle):
    """Déchiffre un fichier chiffré."""
    fernet = Fernet(cle)
    with open(chemin_chiffre, "rb") as f:
        chiffre = f.read()

    clair = fernet.decrypt(chiffre)
    if chemin_clair:
        os.makedirs(os.path.dirname(os.path.abspath(chemin_clair)), exist_ok=True)
        with open(chemin_clair, "wb") as f:
            f.write(clair)

    return clair
