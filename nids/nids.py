"""
Point d'entrée principal du NIDS / NIPS.

Capture les paquets réseau en temps réel via Scapy, dispatche vers le moteur
de détection, et génère un rapport chiffré à l'arrêt du service.
"""

import os
import signal
import sys
import threading
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

        # Notification Discord d'arrêt (synchrone pour garantir l'envoi)
        self.alertes.discord.envoyer_arret()

        # Génération du rapport consolidé forensique si possible, sinon repli sur le log brut
        source_a_chiffrer = self.cfg.ALERT_LOG
        rapport_txt = os.path.join(self.cfg.DATA_DIR, "nids_report.txt")
        try:
            analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analysis"))
            if analysis_path not in sys.path:
                sys.path.append(analysis_path)
            from analyze import LogAnalyzer
            target_log_dir = os.path.join(self.cfg.DATA_DIR, "..", "metasploitable", "log")
            analyzer = LogAnalyzer(target_dir=target_log_dir, nids_alerts=self.cfg.ALERT_JSON)
            synthese = analyzer.generer_synthese_texte()
            with open(rapport_txt, "w", encoding="utf-8") as f:
                f.write(synthese)
            source_a_chiffrer = rapport_txt
        except Exception:
            pass

        # Chiffrement du rapport final
        if source_a_chiffrer and os.path.exists(source_a_chiffrer):
            taille = chiffrer_fichier(
                source_a_chiffrer,
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

    def _surveiller_commandes_nips(self):
        """Thread d'arrière-plan surveillant les commandes de réinitialisation et de mode NIPS."""
        while self.en_cours:
            try:
                self.moteur.synchroniser_etat_nips()
            except Exception:
                pass
            time.sleep(0.8)

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

        # Notification Discord de démarrage
        self.alertes.discord.envoyer_demarrage()

        # Thread de synchronisation NIPS (commandes Dashboard & purge iptables)
        t_sync = threading.Thread(target=self._surveiller_commandes_nips, daemon=True)
        t_sync.start()

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
