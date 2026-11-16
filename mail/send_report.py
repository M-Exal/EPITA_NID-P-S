"""
Envoi du rapport d'alertes chiffré et des notifications critiques par courriel.
Supporte l'API HTTPS native Resend (recommandée) et le protocole SMTP standard.
"""

import base64
import json
import os
import smtplib
import urllib.error
import urllib.request
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def envoyer_via_resend(api_key, expéditeur, destinataire, sujet, corps, piece_jointe_path=None):
    """
    Expédie un courriel via l'API REST HTTPS Resend.
    Bypasse les limitations de ports SMTP (587/465) des réseaux d'entreprise/clouds.
    """
    url = "https://api.resend.com/emails"
    payload = {
        "from": expéditeur or "CyBear NIDS <onboarding@resend.dev>",
        "to": [destinataire],
        "subject": sujet,
        "text": corps,
    }

    if piece_jointe_path and os.path.exists(piece_jointe_path):
        nom = os.path.basename(piece_jointe_path)
        with open(piece_jointe_path, "rb") as f:
            contenu_b64 = base64.b64encode(f.read()).decode("utf-8")
        payload["attachments"] = [
            {
                "filename": nom,
                "content": contenu_b64,
            }
        ]

    donnees = json.dumps(payload).encode("utf-8")
    requete = urllib.request.Request(
        url,
        data=donnees,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CyBear-NIDS/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(requete, timeout=15) as reponse:
            corps_rep = reponse.read().decode("utf-8")
            data_rep = json.loads(corps_rep)
            email_id = data_rep.get("id", "inconnu")
            print(f"[+] Courriel envoyé avec succès via Resend API (ID: {email_id}) à {destinataire}")
            return True
    except Exception as e:
        print(f"[!] Erreur d'envoi via Resend API : {e}")
        return False


def envoyer_via_smtp(host, port, user, password, expediteur, destinataire, sujet, corps, piece_jointe_path=None):
    """
    Expédie un courriel via un serveur SMTP standard.
    """
    msg = MIMEMultipart()
    msg["From"] = expediteur or user
    msg["To"] = destinataire
    msg["Subject"] = sujet
    msg.attach(MIMEText(corps, "plain", "utf-8"))

    if piece_jointe_path and os.path.exists(piece_jointe_path):
        nom = os.path.basename(piece_jointe_path)
        with open(piece_jointe_path, "rb") as f:
            piece_jointe = MIMEApplication(f.read(), Name=nom)
        piece_jointe["Content-Disposition"] = f'attachment; filename="{nom}"'
        msg.attach(piece_jointe)

    try:
        with smtplib.SMTP(host, port, timeout=15) as serveur:
            serveur.starttls()
            if user and password:
                serveur.login(user, password)
            serveur.sendmail(msg["From"], [destinataire], msg.as_string())
        print(f"[+] Courriel envoyé avec succès via SMTP à {destinataire}")
        return True
    except Exception as e:
        print(f"[!] Erreur d'envoi via SMTP : {e}")
        return False


def envoyer_rapport_chiffre(cfg):
    """
    Construit et expédie un courriel avec le rapport chiffré en pièce jointe.
    Privilégie Resend API si disponible, avec fallback sur SMTP.
    """
    rapport_path = getattr(cfg, "ENCRYPTED_REPORT", "")
    if not rapport_path or not os.path.exists(rapport_path):
        print(f"[!] Rapport chiffré introuvable : {rapport_path}")
        return False

    destinataire = getattr(cfg, "ALERT_EMAIL_TO", None) or getattr(cfg, "REPORT_RECEIVER", "")
    expediteur = (
        getattr(cfg, "ALERT_EMAIL_FROM", None)
        or getattr(cfg, "REPORT_SENDER", None)
        or "CyBear NIDS <onboarding@resend.dev>"
    )
    sujet = "[NIDS Alert] Rapport de détection d'intrusions (Chiffré)"
    corps = (
        "Bonjour,\n\n"
        "Veuillez trouver ci-joint le rapport des alertes d'intrusion détectées "
        "par le NIDS.\n"
        "Ce fichier est chiffré avec la clé symétrique convenue (Fernet/AES-128-CBC + HMAC-SHA256).\n\n"
        "Pour déchiffrer ce fichier en console :\n"
        "  python3 mail/decrypt_report.py nids_alerts.enc --key <VOTRE_CLE_FERNET>\n\n"
        "Cordialement,\n"
        "Le service NIDS / NIPS Automatisé CyBear."
    )

    resend_key = getattr(cfg, "RESEND_API_KEY", "")
    if resend_key:
        ok = envoyer_via_resend(
            api_key=resend_key,
            expéditeur=expediteur,
            destinataire=destinataire,
            sujet=sujet,
            corps=corps,
            piece_jointe_path=rapport_path,
        )
        if ok:
            return True

    # Fallback SMTP
    host = getattr(cfg, "SMTP_HOST", "smtp.gmail.com")
    port = int(getattr(cfg, "SMTP_PORT", 587))
    user = getattr(cfg, "SMTP_USER", "")
    password = getattr(cfg, "SMTP_PASSWORD", "")

    return envoyer_via_smtp(
        host=host,
        port=port,
        user=user,
        password=password,
        expediteur=expediteur,
        destinataire=destinataire,
        sujet=sujet,
        corps=corps,
        piece_jointe_path=rapport_path,
    )


def envoyer_alerte_critique_email(cfg, type_attaque, ip_src, details=""):
    """
    Expédie immédiatement une notification par courriel pour une alerte très critique.
    (Issue #12 : Mode de notification mail pour les alertes les plus critiques).
    """
    destinataire = getattr(cfg, "ALERT_EMAIL_TO", None) or getattr(cfg, "REPORT_RECEIVER", "")
    if not destinataire:
        return False

    expediteur = (
        getattr(cfg, "ALERT_EMAIL_FROM", None)
        or getattr(cfg, "REPORT_SENDER", None)
        or "CyBear NIDS <onboarding@resend.dev>"
    )
    sujet = f"[CRITIQUE - CyBear NIDS] Intrusion détectée : {type_attaque} depuis {ip_src}"
    corps = (
        f"⚠️ ALERTE DE SÉCURITÉ TRÈS CRITIQUE — CyBear NIDS / NIPS\n\n"
        f"Une menace nécessitant une attention immédiate a été interceptée :\n\n"
        f"  • Menace     : {type_attaque}\n"
        f"  • IP Source  : {ip_src}\n"
        f"  • Détails    : {details}\n"
        f"  • Statut NIPS: Attaquant neutralisé / règles d'isolement appliquées.\n\n"
        f"Consultez le tableau de bord de supervision ou le rapport forensique chiffré pour plus de détails.\n\n"
        f"CyBear Autonomous Defense System."
    )

    resend_key = getattr(cfg, "RESEND_API_KEY", "")
    if resend_key:
        return envoyer_via_resend(
            api_key=resend_key,
            expéditeur=expediteur,
            destinataire=destinataire,
            sujet=sujet,
            corps=corps,
        )

    user = getattr(cfg, "SMTP_USER", "")
    if user:
        host = getattr(cfg, "SMTP_HOST", "smtp.gmail.com")
        port = int(getattr(cfg, "SMTP_PORT", 587))
        password = getattr(cfg, "SMTP_PASSWORD", "")
        return envoyer_via_smtp(
            host=host,
            port=port,
            user=user,
            password=password,
            expediteur=expediteur,
            destinataire=destinataire,
            sujet=sujet,
            corps=corps,
        )

    return False
