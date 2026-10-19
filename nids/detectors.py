"""
Moteur de détection du NIDS et module de prévention du NIPS.

Implémente la détection pour 7 types d'attaques :
  1. SCAN_PORTS (anomalie comportementale)
  2. NULL_SCAN / XMAS_SCAN (drapeaux TCP illégaux)
  3. BRUTE_FORCE (tentatives de connexion répétées sur ports auth)
  4. DOS (inondation volumétrique)
  5. SQL_INJECTION (signature de charge utile)
  6. XSS (signature de scripts web)
  7. PATH_TRAVERSAL (signature de traversée d'arborescence)

Intègre également la prévention active (NIPS) : blocage de l'IP source
via commande système (iptables/nftables).
"""

import os
import subprocess
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


class MoteurDetection:
    """Analyse les paquets, déclenche les alertes (NIDS) et bloque les attaquants (NIPS)."""

    def __init__(self, config, alertes, blocker=None):
        self.cfg = config
        self.alertes = alertes
        # Fonction personnalisable pour bloquer l'IP (utile pour les tests)
        self.blocker = blocker or self._executer_blocage_systeme

        # Suivi d'état par IP source
        self.scan_tracker = defaultdict(deque)
        self.dos_tracker = defaultdict(deque)
        self.brute_tracker = defaultdict(deque)

        # Anti-spam : (ip, type) -> dernier horodatage d'alerte
        self._dernieres_alertes = {}

        # Ensemble des IPs bloquées par le NIPS
        self.ips_bloquees = set()

    # ------------------------------------------------------------------
    # Utilitaires de gestion du temps et anti-spam
    # ------------------------------------------------------------------
    @staticmethod
    def _purger(file_dattente, fenetre, maintenant, avec_port=False):
        """Retire de la file les évènements antérieurs à (maintenant - fenetre)."""
        limite = maintenant - fenetre
        while file_dattente:
            ts = file_dattente[0][0] if avec_port else file_dattente[0]
            if ts < limite:
                file_dattente.popleft()
            else:
                break

    def _peut_alerter(self, ip_src, type_attaque, maintenant):
        """Vérifie si le délai d'anti-spam (cooldown) est écoulé."""
        cle = (ip_src, type_attaque)
        dernier = self._dernieres_alertes.get(cle, 0)
        if maintenant - dernier >= self.cfg.ALERT_COOLDOWN:
            self._dernieres_alertes[cle] = maintenant
            return True
        return False

    # ------------------------------------------------------------------
    # Module de prévention active NIPS
    # ------------------------------------------------------------------
    def _executer_blocage_systeme(self, ip_src):
        """Applique la règle de blocage iptables sur le système hôte/conteneur."""
        cmd = self.cfg.BLOCK_COMMAND.format(ip=ip_src)
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as e:
            print(f"[NIPS] Avertissement: Impossible d'exécuter la commande de blocage : {e}")
            return False

    def bloquer_ip(self, ip_src, type_attaque):
        """Déclenche la prévention active NIPS si activée."""
        if not self.cfg.NIPS_ENABLED:
            return

        if ip_src not in self.ips_bloquees:
            self.ips_bloquees.add(ip_src)
            succes = self.blocker(ip_src)
            statut = "SUCCÈS" if succes else "ÉCHEC/SIMULATION"
            print(f"[NIPS] Action préventive : IP {ip_src} bloquée suite à [{type_attaque}] ({statut})")

    def declencher_alerte_et_prevention(self, type_attaque, ip_src, details, maintenant):
        """Émet l'alerte NIDS et déclenche le blocage NIPS."""
        if self._peut_alerter(ip_src, type_attaque, maintenant):
            self.alertes.log_alert(type_attaque, ip_src, details)
            self.bloquer_ip(ip_src, type_attaque)

    # ------------------------------------------------------------------
    # 1. SCAN DE PORTS (TCP connect / SYN scan)
    # ------------------------------------------------------------------
    def detecte_scan(self, paquet, maintenant):
        if not (paquet.haslayer(IP) and paquet.haslayer(TCP)):
            return
        ip_src = paquet[IP].src
        dport = paquet[TCP].dport

        suivi = self.scan_tracker[ip_src]
        suivi.append((maintenant, dport))
        self._purger(suivi, self.cfg.SCAN_WINDOW, maintenant, avec_port=True)

        ports_distincts = {p for _, p in suivi}
        if len(ports_distincts) > self.cfg.SCAN_THRESHOLD:
            details = f"({len(ports_distincts)} ports en {self.cfg.SCAN_WINDOW}s)"
            self.declencher_alerte_et_prevention("SCAN_PORTS", ip_src, details, maintenant)

    # ------------------------------------------------------------------
    # 2. SCANS FURTIFS (NULL / XMAS / FIN)
    # ------------------------------------------------------------------
    def detecte_flags_anormaux(self, paquet, maintenant):
        if not (paquet.haslayer(IP) and paquet.haslayer(TCP)):
            return
        flags = int(paquet[TCP].flags)
        ip_src = paquet[IP].src

        if flags == 0:  # NULL scan
            self.declencher_alerte_et_prevention(
                "NULL_SCAN", ip_src, "(paquet TCP sans drapeau)", maintenant
            )
        elif flags == 0x29:  # XMAS scan : FIN(0x01) + PSH(0x08) + URG(0x20)
            self.declencher_alerte_et_prevention(
                "XMAS_SCAN", ip_src, "(drapeaux FIN+PSH+URG)", maintenant
            )

    # ------------------------------------------------------------------
    # 3. BRUTE-FORCE AUTHENTIFICATION (SSH / Telnet)
    # ------------------------------------------------------------------
    def detecte_brute_force(self, paquet, maintenant):
        if not (paquet.haslayer(IP) and paquet.haslayer(TCP)):
            return
        if paquet[TCP].flags == "S" and paquet[TCP].dport in self.cfg.MONITORED_PORTS:
            ip_src = paquet[IP].src
            suivi = self.brute_tracker[ip_src]
            suivi.append(maintenant)
            self._purger(suivi, self.cfg.BRUTE_WINDOW, maintenant)

            if len(suivi) > self.cfg.BRUTE_THRESHOLD:
                details = f"({len(suivi)} tentatives port {paquet[TCP].dport} en {self.cfg.BRUTE_WINDOW}s)"
                self.declencher_alerte_et_prevention("BRUTE_FORCE", ip_src, details, maintenant)

    # ------------------------------------------------------------------
    # 4. DÉNI DE SERVICE (DoS Flood)
    # ------------------------------------------------------------------
    def detecte_dos(self, paquet, maintenant):
        if not paquet.haslayer(IP):
            return
        ip_src = paquet[IP].src

        suivi = self.dos_tracker[ip_src]
        suivi.append(maintenant)
        self._purger(suivi, self.cfg.DOS_WINDOW, maintenant)

        if len(suivi) > self.cfg.DOS_THRESHOLD:
            details = f"({len(suivi)} paquets en {self.cfg.DOS_WINDOW}s)"
            self.declencher_alerte_et_prevention("DOS", ip_src, details, maintenant)

    # ------------------------------------------------------------------
    # 5. INJECTION SQL (SQLi)
    # 6. CROSS-SITE SCRIPTING (XSS)
    # 7. PATH TRAVERSAL (LFI)
    # ------------------------------------------------------------------
    def detecte_signatures_payload(self, paquet, maintenant):
        if not (paquet.haslayer(IP) and paquet.haslayer(Raw)):
            return
        ip_src = paquet[IP].src
        charge = paquet[Raw].load.decode(errors="ignore")
        charge_maj = charge.upper()

        # 5. Injection SQL
        for motif in self.cfg.SIGNATURES_SQL:
            if motif.upper() in charge_maj:
                extrait = charge.strip()[:80]
                self.declencher_alerte_et_prevention(
                    "SQL_INJECTION", ip_src, f'payload="{extrait}"', maintenant
                )
                return

        # 6. XSS
        for motif in self.cfg.SIGNATURES_XSS:
            if motif.lower() in charge.lower():
                extrait = charge.strip()[:80]
                self.declencher_alerte_et_prevention(
                    "XSS", ip_src, f'payload="{extrait}"', maintenant
                )
                return

        # 7. Path Traversal
        for motif in self.cfg.SIGNATURES_TRAVERSAL:
            if motif in charge:
                extrait = charge.strip()[:80]
                self.declencher_alerte_et_prevention(
                    "PATH_TRAVERSAL", ip_src, f'payload="{extrait}"', maintenant
                )
                return

    # ------------------------------------------------------------------
    # Point d'entrée principal
    # ------------------------------------------------------------------
    def analyser(self, paquet):
        """Analyse un paquet Scapy avec l'ensemble des modules de détection."""
        if not paquet.haslayer(IP):
            return
        maintenant = time.time()
        try:
            self.detecte_scan(paquet, maintenant)
            self.detecte_flags_anormaux(paquet, maintenant)
            self.detecte_brute_force(paquet, maintenant)
            self.detecte_dos(paquet, maintenant)
            self.detecte_signatures_payload(paquet, maintenant)
        except Exception as e:
            print(f"[NIDS] Erreur d'analyse paquet : {e}")
