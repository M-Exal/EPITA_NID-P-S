"""
Tests unitaires pour les utilitaires de chiffrement (Fernet).
"""

import os
import pytest
from cryptography.fernet import InvalidToken
from crypto_utils import (
    charger_ou_creer_cle,
    chiffrer_fichier,
    dechiffrer_fichier,
    generer_cle,
)


def test_generation_et_chargement_cle(tmp_path):
    chemin_cle = str(tmp_path / "test.key")
    cle1 = charger_ou_creer_cle(chemin_cle)
    assert os.path.exists(chemin_cle)

    # Recharger doit renvoyer la même clé
    cle2 = charger_ou_creer_cle(chemin_cle)
    assert cle1 == cle2


def test_chiffrement_et_dechiffrement(tmp_path):
    cle = generer_cle()
    source = tmp_path / "original.txt"
    destination_enc = tmp_path / "fichier.enc"
    destination_dec = tmp_path / "restaure.txt"

    message = b"Alerte intrusion NIDS confidentielle - top secret"
    source.write_bytes(message)

    # Chiffrement
    taille = chiffrer_fichier(str(source), str(destination_enc), cle)
    assert taille > 0
    assert destination_enc.read_bytes() != message

    # Déchiffrement
    contenu_recupere = dechiffrer_fichier(str(destination_enc), str(destination_dec), cle)
    assert contenu_recupere == message
    assert destination_dec.read_bytes() == message


def test_dechiffrement_mauvaise_cle(tmp_path):
    cle1 = generer_cle()
    cle2 = generer_cle()

    source = tmp_path / "source.txt"
    destination_enc = tmp_path / "fichier.enc"
    source.write_bytes(b"Donnees de test")

    chiffrer_fichier(str(source), str(destination_enc), cle1)

    with pytest.raises(InvalidToken):
        dechiffrer_fichier(str(destination_enc), None, cle2)
