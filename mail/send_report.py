#!/usr/bin/env python3
"""
send_report.py — Envoi manuel d'un rapport chiffré par e-mail.

Utile pour envoyer à la demande le rapport d'analyse du honeypot ou le journal
d'alertes du NIDS, chiffré avec Fernet, sans attendre l'arrêt du NIDS.

Reprend la forme des snippets du cours (smtplib + MIME) en y ajoutant le
chiffrement obligatoire.

Usage :
    python3 send_report.py ../data/analysis/rapport_analyse.txt
Les identifiants SMTP sont lus dans les variables d'environnement
(voir le fichier .env) : SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
REPORT_SENDER, REPORT_RECEIVER, NIDS_FERNET_KEY.
"""

import os
import smtplib
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from crypto_utils import chiffrer_fichier, charger_ou_creer_cle


def envoyer_email_gmail(fichier, sujet="Rapport chiffré (NIDS/Honeypot)"):
    """
    Chiffre `fichier` puis l'envoie en pièce jointe via SMTP (Gmail/Outlook).

    :return: True si l'envoi réussit, False sinon.
    """
    expediteur = os.environ.get("REPORT_SENDER", os.environ.get("SMTP_USER", ""))
    destinataire = os.environ.get("REPORT_RECEIVER", "")
    mot_de_passe = os.environ.get("SMTP_PASSWORD", "")
    serveur_smtp = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))

    if not (expediteur and destinataire and mot_de_passe):
        print("[MAIL] Identifiants manquants (voir .env).")
        return False
    if not os.path.exists(fichier):
        print(f"[MAIL] Fichier introuvable : {fichier}")
        return False

    # Chiffrement du rapport.
    cle = charger_ou_creer_cle(os.environ.get("NIDS_FERNET_KEY", ""),
                               "secret.key")
    fichier_chiffre = fichier + ".enc"
    chiffrer_fichier(fichier, fichier_chiffre, cle)

    # Construction du message.
    email = MIMEMultipart()
    email["From"] = expediteur
    email["To"] = destinataire
    email["Subject"] = sujet
    email.attach(MIMEText(
        "Rapport chiffré ci-joint (Fernet). "
        "Déchiffrez-le avec decrypt_report.py et la clé partagée.", "plain"))

    with open(fichier_chiffre, "rb") as piece_jointe:
        part = MIMEApplication(piece_jointe.read(),
                               Name=os.path.basename(fichier_chiffre))
        part["Content-Disposition"] = (
            f'attachment; filename="{os.path.basename(fichier_chiffre)}"')
        email.attach(part)

    try:
        with smtplib.SMTP(serveur_smtp, port, timeout=30) as serveur:
            serveur.starttls()
            serveur.login(expediteur, mot_de_passe)
            serveur.send_message(email)
        print(f"[MAIL] Rapport chiffré envoyé à {destinataire} !")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[MAIL] Erreur : {e}")
        return False


if __name__ == "__main__":
    cible = sys.argv[1] if len(sys.argv) > 1 else "../data/analysis/rapport_analyse.txt"
    envoyer_email_gmail(cible)
