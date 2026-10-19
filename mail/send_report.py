"""
Envoi du rapport d'alertes chiffré par email (conformément aux exigences du cours).
"""

import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def envoyer_rapport_chiffre(cfg):
    """
    Construit et expédie un courriel avec le rapport chiffré en pièce jointe.
    """
    if not os.path.exists(cfg.ENCRYPTED_REPORT):
        print(f"[!] Rapport chiffré introuvable : {cfg.ENCRYPTED_REPORT}")
        return False

    msg = MIMEMultipart()
    msg["From"] = cfg.REPORT_SENDER or cfg.SMTP_USER
    msg["To"] = cfg.REPORT_RECEIVER
    msg["Subject"] = "[NIDS Alert] Rapport de détection d'intrusions (Chiffré)"

    corps = (
        "Bonjour,\n\n"
        "Veuillez trouver ci-joint le rapport des alertes d'intrusion détectées "
        "par le NIDS.\n"
        "Ce fichier est chiffré avec la clé symétrique convenue (Fernet/AES).\n\n"
        "Cordialement,\n"
        "Le service NIDS / NIPS Automatisé."
    )
    msg.attach(MIMEText(corps, "plain", "utf-8"))

    nom_fichier = os.path.basename(cfg.ENCRYPTED_REPORT)
    with open(cfg.ENCRYPTED_REPORT, "rb") as f:
        piece_jointe = MIMEApplication(f.read(), Name=nom_fichier)
    piece_jointe["Content-Disposition"] = f'attachment; filename="{nom_fichier}"'
    msg.attach(piece_jointe)

    try:
        with smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=15) as serveur:
            serveur.starttls()
            if cfg.SMTP_USER and cfg.SMTP_PASSWORD:
                serveur.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
            serveur.sendmail(msg["From"], [cfg.REPORT_RECEIVER], msg.as_string())
        print(f"[+] Rapport chiffré envoyé avec succès à {cfg.REPORT_RECEIVER}")
        return True
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi du courriel : {e}")
        return False
