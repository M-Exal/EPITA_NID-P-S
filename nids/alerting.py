"""
Système d'alertes du NIDS.

Enregistre les alertes dans un fichier texte (format lisible)
et dans un fichier JSON (pour analyse automatique ou SIEM).
Notifie optionnellement un channel Discord via webhook.
"""

import json
import logging
import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from discord_notifier import DiscordNotifier

# Fuseau horaire de référence pour les horodatages (conteneur en UTC)
TZ_PARIS = ZoneInfo("Europe/Paris")

# Alertes considérées comme hautement critiques exigeant un courriel immédiat (Issue #12)
TYPES_TRES_CRITIQUES = {
    "DOS",
    "DOS_FLOOD",
    "DENI_DE_SERVICE",
    "BRUTE_FORCE",
    "BRUTEFORCE_SSH",
    "SQL_INJECTION",
    "PATH_TRAVERSAL",
}


class AlertManager:
    """Gestionnaire d'alertes horodatées et persistées."""

    def __init__(self, config):
        self.cfg = config
        os.makedirs(self.cfg.DATA_DIR, exist_ok=True)

        # Notifier Discord (optionnel — actif si DISCORD_WEBHOOK_URL est défini)
        self.discord = DiscordNotifier()

        # Logger texte standard
        self.logger = logging.getLogger("NIDS_Alerts")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        fichier_handler = logging.FileHandler(self.cfg.ALERT_LOG, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fichier_handler.setFormatter(formatter)
        self.logger.addHandler(fichier_handler)

        # Initialisation du fichier JSON si inexistant
        if not os.path.exists(self.cfg.ALERT_JSON):
            with open(self.cfg.ALERT_JSON, "w", encoding="utf-8") as f:
                json.dump([], f)

        # Anti-spam d'emails critiques : (ip, type) -> timestamp
        self._cooldown_email = {}
        self.email_cooldown_delai = getattr(self.cfg, "EMAIL_ALERT_COOLDOWN", 60)

    def log_alert(self, type_attaque, ip_src, details=""):
        """
        Enregistre une alerte et l'affiche dans la console.
        """
        horodatage = datetime.now(TZ_PARIS).isoformat(timespec="seconds")
        message = f"ALERTE [{type_attaque}] depuis {ip_src} {details}".strip()

        # 1. Log texte
        self.logger.info(message)
        print(f"[!] {message}")

        # 2. Log structuré JSON
        entree = {
            "timestamp": horodatage,
            "type": type_attaque,
            "src_ip": ip_src,
            "details": details,
        }
        self._append_json(entree)

        # 3. Notification Discord (pour tous les types d'alertes)
        self.discord.envoyer_alerte(type_attaque, ip_src, details)

        # 4. Notification Email (exclusivement pour les alertes les plus critiques — Issue #12)
        type_upper = type_attaque.upper()
        est_tres_critique = (
            type_upper in TYPES_TRES_CRITIQUES
            or any(k in type_upper for k in ("DOS", "SQL", "BRUTE", "TRAVERSAL"))
        )
        if est_tres_critique:
            maintenant = time.time()
            cle = (ip_src, type_attaque)
            derniere = self._cooldown_email.get(cle, 0)
            if maintenant - derniere >= self.email_cooldown_delai:
                self._cooldown_email[cle] = maintenant
                self._notifier_mail_critique(type_attaque, ip_src, details)

    def _notifier_mail_critique(self, type_attaque, ip_src, details):
        """Déclenche l'envoi d'un courriel d'alerte pour les intrusions critiques."""
        try:
            from send_report import envoyer_alerte_critique_email
            envoyer_alerte_critique_email(self.cfg, type_attaque, ip_src, details)
        except Exception as e:
            self.logger.debug(f"Alerte email critique ignorée : {e}")

    def _append_json(self, entree):
        """Ajoute atomiquement une entrée dans le fichier JSON d'alertes."""
        try:
            with open(self.cfg.ALERT_JSON, "r+", encoding="utf-8") as f:
                try:
                    alertes = json.load(f)
                except json.JSONDecodeError:
                    alertes = []
                alertes.append(entree)
                f.seek(0)
                json.dump(alertes, f, indent=2, ensure_ascii=False)
                f.truncate()
        except Exception as e:
            self.logger.error(f"Erreur d'écriture JSON : {e}")
