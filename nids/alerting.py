"""
alerting.py — Système d'alertes et d'envoi de rapport chiffré.

Reprend la forme des snippets du cours (logging + smtplib + MIMEApplication)
mais rend le tout fonctionnel :
  - `AlertManager` journalise chaque alerte (fichier .log lisible + .json
    exploitable par l'analyse) ;
  - `envoyer_mail` chiffre le rapport avec Fernet avant de l'envoyer en pièce
    jointe (exigence « rapport chiffré »).
"""

import json
import logging
import os
import smtplib
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from crypto_utils import chiffrer_fichier, charger_ou_creer_cle


class AlertManager:
    """Centralise la journalisation et la remontée des alertes du NIDS."""

    def __init__(self, config):
        self.cfg = config
        os.makedirs(config.DATA_DIR, exist_ok=True)

        # Journalisation texte (format repris du cours).
        # Logger dédié avec son propre gestionnaire de fichier :
        # logging.basicConfig est global et ignorerait un second chemin.
        self.logger = logging.getLogger("NIDS")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        for gestionnaire in list(self.logger.handlers):
            self.logger.removeHandler(gestionnaire)
            gestionnaire.close()
        gestionnaire_fichier = logging.FileHandler(config.ALERT_LOG,
                                                   encoding="utf-8")
        gestionnaire_fichier.setFormatter(
            logging.Formatter("%(asctime)s - %(message)s"))
        self.logger.addHandler(gestionnaire_fichier)

        # Compteur par type d'attaque (utile pour le résumé final).
        self.compteur = {}

    def log_alert(self, type_attaque, ip_src, details=""):
        """
        Enregistre une alerte : console + fichier .log + fichier .json.

        :param type_attaque: ex. "SCAN_PORTS", "DOS", "BRUTE_FORCE".
        :param ip_src:       adresse IP source suspecte.
        :param details:      complément d'information (port, payload, etc.).
        """
        horodatage = datetime.now().isoformat(timespec="seconds")
        message = f"[{type_attaque}] depuis {ip_src} {details}".strip()

        # 1. Console (affichage temps réel pour la démonstration).
        print(f"[ALERTE] {horodatage} {message}")

        # 2. Fichier .log (format du cours).
        self.logger.info(message)

        # 3. Fichier .json (structuré, lu par l'analyse / le rapport).
        enregistrement = {
            "timestamp": horodatage,
            "type": type_attaque,
            "source_ip": ip_src,
            "details": details,
        }
        with open(self.cfg.ALERT_JSON, "a", encoding="utf-8") as f:
            f.write(json.dumps(enregistrement) + "\n")

        # 4. Statistiques.
        self.compteur[type_attaque] = self.compteur.get(type_attaque, 0) + 1

    def resume(self):
        """Renvoie un résumé texte des alertes relevées (pour le rapport)."""
        lignes = ["===== RÉSUMÉ DES ALERTES NIDS =====",
                  f"Généré le : {datetime.now().isoformat(timespec='seconds')}", ""]
        if not self.compteur:
            lignes.append("Aucune alerte relevée durant la période de capture.")
        else:
            total = sum(self.compteur.values())
            lignes.append(f"Total d'alertes : {total}")
            for type_attaque, nombre in sorted(self.compteur.items()):
                lignes.append(f"  - {type_attaque} : {nombre}")
        return "\n".join(lignes)


def envoyer_mail(config, fichier_a_envoyer=None, sujet="Rapport NIDS (chiffré)"):
    """
    Chiffre le rapport puis l'envoie par e-mail en pièce jointe.

    Reprend la structure du snippet du cours (MIMEMultipart + smtplib +
    starttls) en ajoutant l'étape de chiffrement Fernet exigée par le sujet.

    :param config:             objet Config (identifiants SMTP, clé Fernet…).
    :param fichier_a_envoyer:  fichier en clair à chiffrer puis joindre
                               (par défaut : le journal d'alertes).
    :return: True si l'envoi a réussi, False sinon.
    """
    if fichier_a_envoyer is None:
        fichier_a_envoyer = config.ALERT_LOG

    # Vérifications de base pour éviter un plantage silencieux.
    if not os.path.exists(fichier_a_envoyer):
        print(f"[MAIL] Fichier introuvable : {fichier_a_envoyer}")
        return False
    if not (config.SMTP_USER and config.SMTP_PASSWORD and config.REPORT_RECEIVER):
        print("[MAIL] Identifiants SMTP ou destinataire manquants "
              "(voir le fichier .env). Envoi ignoré.")
        return False

    # 1. Chiffrement du rapport (confidentialité + intégrité).
    cle = charger_ou_creer_cle(config.FERNET_KEY, config.KEY_FILE)
    fichier_chiffre = fichier_a_envoyer + ".enc"
    chiffrer_fichier(fichier_a_envoyer, fichier_chiffre, cle)

    # 2. Construction du message.
    msg = MIMEMultipart()
    msg["From"] = config.REPORT_SENDER
    msg["To"] = config.REPORT_RECEIVER
    msg["Subject"] = sujet
    corps = ("Bonjour,\n\n"
             "Veuillez trouver ci-joint le rapport du NIDS, chiffré avec "
             "Fernet (AES-128-CBC + HMAC).\n"
             "Déchiffrement : python mail/decrypt_report.py <fichier.enc>\n\n"
             "Cordialement,\nLe NIDS automatisé.")
    msg.attach(MIMEText(corps, "plain"))

    with open(fichier_chiffre, "rb") as piece_jointe:
        part = MIMEApplication(piece_jointe.read(),
                               Name=os.path.basename(fichier_chiffre))
        part["Content-Disposition"] = (
            f'attachment; filename="{os.path.basename(fichier_chiffre)}"')
        msg.attach(part)

    # 3. Envoi via SMTP (gestion d'erreurs complète).
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as serveur:
            serveur.starttls()
            serveur.login(config.SMTP_USER, config.SMTP_PASSWORD)
            serveur.send_message(msg)
        print(f"[MAIL] Rapport chiffré envoyé à {config.REPORT_RECEIVER}.")
        return True
    except Exception as e:  # noqa: BLE001 — on veut capturer toute erreur SMTP
        print(f"[MAIL] Erreur lors de l'envoi : {e}")
        return False
