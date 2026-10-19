#!/usr/bin/env python3
"""
nids.py — Programme principal du NIDS (Network Intrusion Detection System).

Capture le trafic réseau en temps réel avec Scapy, l'analyse via le
`MoteurDetection`, journalise les alertes et, à l'arrêt, envoie un rapport
chiffré par e-mail.

Usage :
    sudo python3 nids.py                # capture en direct sur l'interface
    sudo python3 nids.py --iface eth0   # interface explicite
    python3 nids.py --pcap fichier.pcap # analyse hors-ligne d'une capture
    python3 nids.py --duree 120         # s'arrête après 120 s puis envoie le rapport

Dans Docker, il tourne en continu (voir docker-compose.yml) et partage la pile
réseau du honeypot afin de voir tout le trafic qui lui est destiné.
"""

import argparse
import signal
import sys

from scapy.sendrecv import sniff
from scapy.utils import wrpcap, rdpcap

from config import Config
from alerting import AlertManager, envoyer_mail
from detectors import MoteurDetection


class NIDS:
    """Orchestrateur : capture -> analyse -> alerte -> rapport."""

    def __init__(self, config):
        self.cfg = config
        self.alertes = AlertManager(config)
        self.moteur = MoteurDetection(config, self.alertes)
        self.paquets_captures = []   # pour un éventuel enregistrement .pcap
        self.nb_paquets = 0

    def capture_paquet(self, paquet):
        """
        Callback Scapy appelé pour chaque paquet (paramètre `prn` de sniff).
        """
        self.nb_paquets += 1
        self.paquets_captures.append(paquet)
        self.moteur.analyser(paquet)

    def demarrer(self, iface=None, duree=None, bpf=None):
        """
        Lance la capture temps réel.

        :param iface: interface réseau (ex. eth0). None = interface par défaut.
        :param duree: durée de capture en secondes (None = infini).
        :param bpf:   filtre BPF (ex. "tcp or icmp").
        """
        iface = iface or self.cfg.INTERFACE
        bpf = bpf if bpf is not None else self.cfg.BPF_FILTER
        print(f"[NIDS] Démarrage de la capture sur l'interface '{iface}'...")
        print(f"[NIDS] Seuils : scan>{self.cfg.SCAN_THRESHOLD} ports/{self.cfg.SCAN_WINDOW}s, "
              f"DoS>{self.cfg.DOS_THRESHOLD} pqts/{self.cfg.DOS_WINDOW}s, "
              f"brute>{self.cfg.BRUTE_THRESHOLD} SYN/{self.cfg.BRUTE_WINDOW}s")
        print("[NIDS] Ctrl+C pour arrêter et générer le rapport.\n")

        try:
            sniff(
                iface=iface,
                prn=self.capture_paquet,
                filter=bpf or None,
                store=False,         # on gère nous-mêmes le stockage
                timeout=duree,
            )
        except PermissionError:
            print("[NIDS] Droits insuffisants : lancez avec sudo "
                  "(ou cap_add NET_RAW/NET_ADMIN dans Docker).")
            sys.exit(1)
        except OSError as e:
            print(f"[NIDS] Interface '{iface}' indisponible : {e}")
            sys.exit(1)

    def analyser_pcap(self, chemin):
        """Analyse hors-ligne d'un fichier de capture (.pcap)."""
        print(f"[NIDS] Analyse du fichier {chemin}...")
        try:
            paquets = rdpcap(chemin)
        except Exception as e:  # noqa: BLE001
            print(f"[NIDS] Impossible de lire {chemin} : {e}")
            sys.exit(1)
        for paquet in paquets:
            self.capture_paquet(paquet)
        print(f"[NIDS] {len(paquets)} paquets analysés.")

    def terminer(self, sauver_pcap=True, envoyer_rapport=True):
        """Affiche le résumé, sauvegarde la capture et envoie le rapport chiffré."""
        print("\n" + self.alertes.resume())
        print(f"\n[NIDS] {self.nb_paquets} paquets traités au total.")

        if sauver_pcap and self.paquets_captures:
            chemin = f"{self.cfg.DATA_DIR}/capture.pcap"
            try:
                wrpcap(chemin, self.paquets_captures)
                print(f"[NIDS] Capture enregistrée : {chemin}")
            except Exception as e:  # noqa: BLE001
                print(f"[NIDS] Échec de l'enregistrement pcap : {e}")

        if envoyer_rapport:
            print("[NIDS] Envoi du rapport chiffré par e-mail...")
            envoyer_mail(self.cfg)


def main():
    parser = argparse.ArgumentParser(description="NIDS basique en Python (Scapy).")
    parser.add_argument("--iface", help="Interface réseau à écouter.")
    parser.add_argument("--duree", type=int, help="Durée de capture (s).")
    parser.add_argument("--bpf", help="Filtre BPF (ex. 'tcp or icmp').")
    parser.add_argument("--pcap", help="Analyser un fichier .pcap au lieu de capturer.")
    parser.add_argument("--no-mail", action="store_true",
                        help="Ne pas envoyer le rapport par e-mail à la fin.")
    args = parser.parse_args()

    nids = NIDS(Config)

    # Arrêt propre sur Ctrl+C / SIGTERM (ex. docker stop) -> on génère le rapport.
    def _arret(signum, frame):  # noqa: ARG001
        print("\n[NIDS] Arrêt demandé.")
        nids.terminer(envoyer_rapport=not args.no_mail)
        sys.exit(0)

    signal.signal(signal.SIGINT, _arret)
    signal.signal(signal.SIGTERM, _arret)

    if args.pcap:
        nids.analyser_pcap(args.pcap)
        nids.terminer(sauver_pcap=False, envoyer_rapport=not args.no_mail)
    else:
        nids.demarrer(iface=args.iface, duree=args.duree, bpf=args.bpf)
        # Si --duree est atteint, sniff rend la main : on termine normalement.
        nids.terminer(envoyer_rapport=not args.no_mail)


if __name__ == "__main__":
    main()
