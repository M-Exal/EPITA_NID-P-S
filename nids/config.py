"""
Configuration centralisée du NIDS / NIPS.

Toutes les variables sont surchargeables par l'environnement
pour faciliter les tests et le déploiement Docker.

En développement local, les variables sont lues depuis le fichier .env
situé à la racine du projet (si présent).
"""

import os
import sys

# Chargement automatique du .env en développement local (hors Docker)
_env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(_env_file):
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _val = _line.split("=", 1)
                os.environ.setdefault(_key.strip(), _val.strip())


class Config:
    # ------------------------------------------------------------------
    # Réseau & Interface
    # ------------------------------------------------------------------
    DEFAULT_IFACE = (
        "eth0"
        if os.path.exists("/sys/class/net/eth0")
        else ("lo0" if sys.platform == "darwin" else "lo")
    )
    INTERFACE = os.getenv("NIDS_IFACE", DEFAULT_IFACE)
    BPF_FILTER = os.getenv("NIDS_BPF_FILTER", "ip")

    # ------------------------------------------------------------------
    # Répertoires et Fichiers de données
    # ------------------------------------------------------------------
    DEFAULT_DATA_DIR = (
        "/app/data"
        if os.path.exists("/app")
        else os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "nids"))
    )
    DATA_DIR = os.getenv("NIDS_DATA_DIR", DEFAULT_DATA_DIR)
    ALERT_LOG = os.path.join(DATA_DIR, "nids_alerts.log")
    ALERT_JSON = os.path.join(DATA_DIR, "nids_alerts.json")
    KEY_FILE = os.path.join(DATA_DIR, "secret.key")
    ENCRYPTED_REPORT = os.path.join(DATA_DIR, "nids_alerts.enc")

    # ------------------------------------------------------------------
    # NIPS (Network Intrusion Prevention System)
    # ------------------------------------------------------------------
    # Si activé, le NIPS bloque activement les adresses IP malveillantes
    NIPS_ENABLED = os.getenv("NIPS_ENABLED", "false").lower() in ("true", "1", "yes")
    BLOCK_COMMAND = os.getenv("NIPS_BLOCK_CMD", "iptables -I INPUT -s {ip} -j DROP")

    # ------------------------------------------------------------------
    # Seuils de Détection (Anomalies)
    # ------------------------------------------------------------------
    # Scan de ports : nombre de ports distincts sur une fenêtre de temps (secondes)
    SCAN_THRESHOLD = int(os.getenv("NIDS_SCAN_THRESHOLD", "15"))
    SCAN_WINDOW = int(os.getenv("NIDS_SCAN_WINDOW", "10"))

    # Déni de service (DoS) : nombre de paquets par IP sur la fenêtre
    DOS_THRESHOLD = int(os.getenv("NIDS_DOS_THRESHOLD", "200"))
    DOS_WINDOW = int(os.getenv("NIDS_DOS_WINDOW", "5"))

    # Brute-force d'authentification : tentatives de connexion SYN vers ports sensibles
    BRUTE_THRESHOLD = int(os.getenv("NIDS_BRUTE_THRESHOLD", "10"))
    BRUTE_WINDOW = int(os.getenv("NIDS_BRUTE_WINDOW", "30"))
    MONITORED_PORTS = [
        int(p) for p in os.getenv("NIDS_MONITORED_PORTS", "22,2222,23,2223").split(",")
    ]

    # Délai anti-spam (cooldown) par (IP, type d'alerte) en secondes
    ALERT_COOLDOWN = int(os.getenv("NIDS_ALERT_COOLDOWN", "30"))

    # ------------------------------------------------------------------
    # Signatures de Détection
    # ------------------------------------------------------------------
    SIGNATURES_SQL = [
        "SELECT", "UNION", "INSERT", "DROP", "UPDATE", "DELETE",
        "' OR '1'='1", "' OR 1=1", "1=1--", "EXEC(",
    ]

    SIGNATURES_XSS = [
        "<script", "</script>", "javascript:", "onerror=", "onload=", "<img src="
    ]

    SIGNATURES_TRAVERSAL = [
        "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "/etc/passwd"
    ]

    # ------------------------------------------------------------------
    # Envoi de rapport par email
    # ------------------------------------------------------------------
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    REPORT_SENDER = os.getenv("REPORT_SENDER", "")
    REPORT_RECEIVER = os.getenv("REPORT_RECEIVER", "")
    NIDS_FERNET_KEY = os.getenv("NIDS_FERNET_KEY", "")

    # ------------------------------------------------------------------
    # Notification Discord (Webhook)
    # ------------------------------------------------------------------
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
