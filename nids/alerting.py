"""
Système d'alertes du NIDS.

Enregistre les alertes dans un fichier texte (format lisible)
et dans un fichier JSON (pour analyse automatique ou SIEM).
Notifie optionnellement un channel Discord via webhook.
"""

import json
import logging
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from discord_notifier import DiscordNotifier

# Fuseau horaire de référence pour les horodatages (conteneur en UTC)
TZ_PARIS = ZoneInfo("Europe/Paris")


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

        # 3. Notification Discord
        self.discord.envoyer_alerte(type_attaque, ip_src, details)

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
