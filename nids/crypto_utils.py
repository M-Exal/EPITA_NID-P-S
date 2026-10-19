"""
Utilitaires de chiffrement symétrique (Fernet / AES-128-CBC + HMAC-SHA256).

Conforme aux exigences de la Séance 4 : transmission de rapports chiffrés.
"""

import os
from cryptography.fernet import Fernet


def generer_cle():
    """Génère une nouvelle clé symétrique Fernet (32 octets base64-encodés)."""
    return Fernet.generate_key()


def charger_ou_creer_cle(chemin_cle):
    """
    Charge la clé depuis `chemin_cle` si le fichier existe,
    sinon en génère une nouvelle et la sauvegarde.
    """
    if os.path.exists(chemin_cle):
        with open(chemin_cle, "rb") as f:
            return f.read().strip()

    os.makedirs(os.path.dirname(os.path.abspath(chemin_cle)), exist_ok=True)
    cle = generer_cle()
    with open(chemin_cle, "wb") as f:
        f.write(cle)
    return cle


def chiffrer_fichier(chemin_source, chemin_destination, cle):
    """
    Chiffre le contenu de `chemin_source` et l'écrit dans `chemin_destination`.
    Retourne la taille du contenu chiffré.
    """
    fernet = Fernet(cle)
    with open(chemin_source, "rb") as f:
        donnees = f.read()

    chiffre = fernet.encrypt(donnees)
    os.makedirs(os.path.dirname(os.path.abspath(chemin_destination)), exist_ok=True)
    with open(chemin_destination, "wb") as f:
        f.write(chiffre)

    return len(chiffre)


def dechiffrer_fichier(chemin_chiffre, chemin_clair, cle):
    """
    Déchiffre le contenu de `chemin_chiffre` et écrit le résultat dans `chemin_clair`.
    Retourne les octets déchiffrés.
    """
    fernet = Fernet(cle)
    with open(chemin_chiffre, "rb") as f:
        chiffre = f.read()

    clair = fernet.decrypt(chiffre)
    if chemin_clair:
        os.makedirs(os.path.dirname(os.path.abspath(chemin_clair)), exist_ok=True)
        with open(chemin_clair, "wb") as f:
            f.write(clair)

    return clair
