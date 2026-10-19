"""
Point d'entrée principal du NIDS / NIPS.

Capture les paquets réseau en temps réel via Scapy, dispatche vers le moteur
de détection, et génère un rapport chiffré à l'arrêt du service.
"""

import os
import signal
import sys
import time
from scapy.all import sniff

from alerting import AlertManager
from config import Config
from crypto_utils import charger_ou_creer_cle, chiffrer_fichier
from detectors import MoteurDetection


class NIDSService:
    def __init__(self, cfg=Config):
        self.cfg = cfg
        self.alertes = AlertManager(self.cfg)
        self.moteur = MoteurDetection(self.cfg, self.alertes)
        self.cle = self._initialiser_crypto()
        self.en_cours = True

    def _initialiser_crypto(self):
        """Initialise ou charge la clé Fernet pour le chiffrement des rapports."""
        if self.cfg.NIDS_FERNET_KEY:
            cle = self.cfg.NIDS_FERNET_KEY.encode()
        else:
            cle = charger_ou_creer_cle(self.cfg.KEY_FILE)
        return cle

    def arreter(self, signum=None, frame=None):
        """Arrêt gracieux : chiffre le rapport d'alertes."""
        if not self.en_cours:
            return
        print("\n[*] Arrêt du NIDS/NIPS en cours...")
        self.en_cours = False

        # Chiffrement du rapport final
        if os.path.exists(self.cfg.ALERT_LOG):
            taille = chiffrer_fichier(
                self.cfg.ALERT_LOG,
                self.cfg.ENCRYPTED_REPORT,
                self.cle
            )
            print(f"[+] Rapport d'alertes chiffré généré : {self.cfg.ENCRYPTED_REPORT} ({taille} octets)")

        # Envoi optionnel par mail si configuré
        if self.cfg.SMTP_USER and self.cfg.REPORT_RECEIVER:
            try:
                # Import dynamique pour ne pas bloquer si mail n'est pas configuré
                sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mail")))
                from send_report import envoyer_rapport_chiffre
                envoyer_rapport_chiffre(self.cfg)
            except Exception as e:
                print(f"[!] Échec de l'envoi du mail de rapport : {e}")

        sys.exit(0)

    def demarrer(self):
        """Lance la capture Scapy."""
        signal.signal(signal.SIGINT, self.arreter)
        signal.signal(signal.SIGTERM, self.arreter)

        print("=" * 60)
        print("  DÉMARRAGE DU NIDS / NIPS")
        print(f"  Interface : {self.cfg.INTERFACE}")
        print(f"  Filtre BPF: {self.cfg.BPF_FILTER}")
        print(f"  Prévention NIPS active : {self.cfg.NIPS_ENABLED}")
        print(f"  Fichier alertes : {self.cfg.ALERT_LOG}")
        print("=" * 60)

        try:
            sniff(
                iface=self.cfg.INTERFACE,
                filter=self.cfg.BPF_FILTER,
                prn=self.moteur.analyser,
                store=0,
                stop_filter=lambda _: not self.en_cours
            )
        except Exception as e:
            print(f"[!] Erreur de capture Scapy : {e}")
            self.arreter()


if __name__ == "__main__":
    service = NIDSService()
    service.demarrer()
