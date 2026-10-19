"""
config.py — Configuration centralisée du NIDS.

Tous les seuils de détection et les paramètres sont regroupés ici afin de
pouvoir les ajuster facilement (cf. "Tests et ajustements" du cahier des
charges). Les valeurs peuvent être surchargées via des variables
d'environnement, ce qui est pratique lorsque le NIDS tourne dans un conteneur
Docker.
"""

import os


def _get_int(nom, defaut):
    """Lit une variable d'environnement entière avec une valeur par défaut."""
    try:
        return int(os.environ.get(nom, defaut))
    except (TypeError, ValueError):
        return defaut


class Config:
    """Paramètres de fonctionnement du NIDS."""

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------
    # Interface réseau à écouter. Dans le conteneur (network_mode:
    # service:honeypot), l'interface du honeypot est "eth0".
    INTERFACE = os.environ.get("NIDS_IFACE", "eth0")

    # Filtre BPF optionnel (ex. "tcp or icmp"). Vide = tout capturer.
    BPF_FILTER = os.environ.get("NIDS_BPF", "")

    # Ports surveillés de près pour la détection de brute-force (SSH/Telnet).
    MONITORED_PORTS = [22, 23, 2222, 2223]

    # ------------------------------------------------------------------
    # Seuils de détection (fenêtres glissantes en secondes)
    # ------------------------------------------------------------------
    # Scan de ports : trop de ports *différents* contactés en peu de temps.
    SCAN_WINDOW = _get_int("NIDS_SCAN_WINDOW", 10)
    SCAN_THRESHOLD = _get_int("NIDS_SCAN_THRESHOLD", 15)      # Seuil de détection

    # Déni de service : trop de paquets depuis une même IP en peu de temps.
    DOS_WINDOW = _get_int("NIDS_DOS_WINDOW", 5)
    DOS_THRESHOLD = _get_int("NIDS_DOS_THRESHOLD", 200)       # Seuil de détection

    # Brute-force : trop de tentatives de connexion (SYN) vers un port d'auth.
    BRUTE_WINDOW = _get_int("NIDS_BRUTE_WINDOW", 30)
    BRUTE_THRESHOLD = _get_int("NIDS_BRUTE_THRESHOLD", 10)    # Seuil de détection

    # ------------------------------------------------------------------
    # Anti-spam d'alertes
    # ------------------------------------------------------------------
    # On ne relève pas deux fois la même alerte (ip, type) avant ce délai.
    ALERT_COOLDOWN = _get_int("NIDS_ALERT_COOLDOWN", 30)

    # ------------------------------------------------------------------
    # Fichiers de sortie
    # ------------------------------------------------------------------
    DATA_DIR = os.environ.get("NIDS_DATA_DIR", "/app/data")
    ALERT_LOG = os.path.join(DATA_DIR, "nids_alerts.log")
    ALERT_JSON = os.path.join(DATA_DIR, "nids_alerts.json")

    # ------------------------------------------------------------------
    # Signatures (détection par signature)
    # ------------------------------------------------------------------
    # Motifs recherchés dans la charge utile (payload) des paquets.
    # Remarque : "--" tout seul serait trop large (faux positifs fréquents),
    # on cherche donc la séquence SQL "; --" (commentaire de fin de requête).
    SIGNATURES_SQL = ["SELECT", "UNION", "DROP", "OR 1=1", "' OR '",
                      "INSERT INTO", "; --"]
    SIGNATURES_XSS = ["<script>", "onerror=", "javascript:"]
    SIGNATURES_TRAVERSAL = ["../../", "/etc/passwd", "..\\..\\"]

    # ------------------------------------------------------------------
    # Envoi du rapport chiffré par mail (voir mail/crypto_utils.py)
    # ------------------------------------------------------------------
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = _get_int("SMTP_PORT", 587)
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    REPORT_SENDER = os.environ.get("REPORT_SENDER", os.environ.get("SMTP_USER", ""))
    REPORT_RECEIVER = os.environ.get("REPORT_RECEIVER", "")

    # Clé de chiffrement Fernet (base64). Si vide, un fichier secret.key est
    # créé/lu dans DATA_DIR.
    FERNET_KEY = os.environ.get("NIDS_FERNET_KEY", "")
    KEY_FILE = os.path.join(DATA_DIR, "secret.key")
