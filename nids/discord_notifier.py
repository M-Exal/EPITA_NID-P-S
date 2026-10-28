"""
Module de notification Discord pour le NIDS.

Envoie des alertes d'intrusion formatées en embeds Discord
via un Webhook Discord (pas besoin d'un bot complet).
Fonctionne de manière asynchrone pour ne pas bloquer le moteur de détection.
"""

import json
import logging
import os
import threading
from datetime import datetime
from urllib import request as urllib_request
from urllib.error import URLError
from zoneinfo import ZoneInfo

logger = logging.getLogger("NIDS_Discord")

# Fuseau horaire de référence pour les horodatages (conteneur en UTC)
TZ_PARIS = ZoneInfo("Europe/Paris")


# Couleurs d'embed Discord par sévérité
COULEURS_SEVERITE = {
    "CRITIQUE": 0xFF0000,   # Rouge
    "HAUTE":    0xFF6600,   # Orange
    "MOYENNE":  0xFFCC00,   # Jaune
    "BASSE":    0x00CC00,   # Vert
}

# Mapping type d'attaque -> sévérité
SEVERITE_PAR_TYPE = {
    "SCAN_PORTS":       "MOYENNE",
    "NULL_SCAN":        "HAUTE",
    "XMAS_SCAN":        "HAUTE",
    "BRUTE_FORCE":      "CRITIQUE",
    "DOS":              "CRITIQUE",
    "SQL_INJECTION":    "CRITIQUE",
    "XSS":              "HAUTE",
    "PATH_TRAVERSAL":   "HAUTE",
}

# Emojis par type d'attaque
EMOJIS = {
    "SCAN_PORTS":       "🔍",
    "NULL_SCAN":        "👻",
    "XMAS_SCAN":        "🎄",
    "BRUTE_FORCE":      "🔐",
    "DOS":              "💥",
    "SQL_INJECTION":    "💉",
    "XSS":              "🕷️",
    "PATH_TRAVERSAL":   "📂",
}


class DiscordNotifier:
    """Envoie des alertes d'intrusion vers un channel Discord via Webhook."""

    def __init__(self, webhook_url=None):
        """
        Initialise le notifier Discord.

        Args:
            webhook_url: URL du webhook Discord.
                         Si None, lit la variable d'environnement DISCORD_WEBHOOK_URL.
                         Si une chaîne vide est fournie explicitement, le notifier
                         est désactivé (utile pour les tests unitaires).
        """
        if webhook_url is None:
            self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        else:
            self.webhook_url = webhook_url
        self.enabled = bool(self.webhook_url)

        if not self.enabled:
            logger.warning(
                "DISCORD_WEBHOOK_URL non configuré — notifications Discord désactivées."
            )

    def envoyer_alerte(self, type_attaque, ip_src, details=""):
        """
        Envoie une alerte d'intrusion vers Discord de manière asynchrone.

        Cette méthode est non-bloquante : elle lance l'envoi dans un thread
        séparé pour ne pas ralentir le moteur de détection.

        Args:
            type_attaque: Type d'attaque détectée (ex: "BRUTE_FORCE", "DOS").
            ip_src: Adresse IP source de l'attaque.
            details: Détails supplémentaires (optionnel).
        """
        if not self.enabled:
            return

        thread = threading.Thread(
            target=self._envoyer,
            args=(type_attaque, ip_src, details),
            daemon=True,
        )
        thread.start()

    def _envoyer(self, type_attaque, ip_src, details):
        """Envoie effectivement le message Discord (appelé dans un thread)."""
        try:
            payload = self._construire_payload(type_attaque, ip_src, details)
            data = json.dumps(payload).encode("utf-8")

            req = urllib_request.Request(
                self.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "NIDS-Bot/1.0",
                },
                method="POST",
            )

            with urllib_request.urlopen(req, timeout=10) as response:
                if response.status not in (200, 204):
                    logger.error(
                        f"Discord webhook a répondu avec le code {response.status}"
                    )

        except URLError as e:
            logger.error(f"Erreur d'envoi Discord : {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue Discord : {e}")

    def _construire_payload(self, type_attaque, ip_src, details):
        """
        Construit le payload JSON de l'embed Discord.

        Returns:
            dict: Payload prêt à être envoyé au webhook Discord.
        """
        severite = SEVERITE_PAR_TYPE.get(type_attaque, "MOYENNE")
        couleur = COULEURS_SEVERITE.get(severite, 0xFFCC00)
        emoji = EMOJIS.get(type_attaque, "⚠️")
        horodatage = datetime.now(TZ_PARIS).isoformat()

        embed = {
            "title": f"{emoji} Intrusion Détectée — {type_attaque}",
            "color": couleur,
            "fields": [
                {
                    "name": "🎯 Type d'attaque",
                    "value": f"`{type_attaque}`",
                    "inline": True,
                },
                {
                    "name": "🌐 IP Source",
                    "value": f"`{ip_src}`",
                    "inline": True,
                },
                {
                    "name": "⚡ Sévérité",
                    "value": f"**{severite}**",
                    "inline": True,
                },
            ],
            "footer": {
                "text": "NIDS/NIPS — Système de Détection d'Intrusions",
            },
            "timestamp": horodatage,
        }

        if details:
            embed["fields"].append({
                "name": "📋 Détails",
                "value": f"```\n{details[:1000]}\n```",
                "inline": False,
            })

        payload = {
            "username": "🛡️ NIDS CyBear Bot",
            "content": self._mention_si_critique(severite),
            "embeds": [embed],
        }

        return payload

    def _mention_si_critique(self, severite):
        """
        Retourne une mention @here pour les alertes critiques,
        afin de notifier tous les membres en ligne du channel.
        """
        if severite == "CRITIQUE":
            return "🚨 **ALERTE CRITIQUE** @here"
        return ""

    def envoyer_demarrage(self):
        """Envoie une notification de démarrage du NIDS."""
        if not self.enabled:
            return

        payload = {
            "username": "🛡️ NIDS CyBear Bot",
            "embeds": [{
                "title": "✅ NIDS/NIPS Démarré",
                "description": "Le système de détection d'intrusions est actif et surveille le réseau.",
                "color": 0x00CC00,
                "timestamp": datetime.now(TZ_PARIS).isoformat(),
                "footer": {
                    "text": "NIDS/NIPS — Système de Détection d'Intrusions",
                },
            }],
        }

        thread = threading.Thread(
            target=self._envoyer_payload_brut,
            args=(payload,),
            daemon=True,
        )
        thread.start()

    def envoyer_arret(self):
        """Envoie une notification d'arrêt du NIDS."""
        if not self.enabled:
            return

        payload = {
            "username": "🛡️ NIDS CyBear Bot",
            "embeds": [{
                "title": "🔴 NIDS/NIPS Arrêté",
                "description": "Le système de détection d'intrusions a été arrêté.",
                "color": 0xFF0000,
                "timestamp": datetime.now(TZ_PARIS).isoformat(),
                "footer": {
                    "text": "NIDS/NIPS — Système de Détection d'Intrusions",
                },
            }],
        }

        # Envoi synchrone pour garantir l'envoi avant l'arrêt du processus
        self._envoyer_payload_brut(payload)

    def _envoyer_payload_brut(self, payload):
        """Envoie un payload JSON brut au webhook Discord."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib_request.Request(
                self.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "NIDS-Bot/1.0",
                },
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=10) as response:
                if response.status not in (200, 204):
                    logger.error(
                        f"Discord webhook a répondu avec le code {response.status}"
                    )
        except Exception as e:
            logger.error(f"Erreur d'envoi Discord : {e}")
