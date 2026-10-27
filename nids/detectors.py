"""
Moteur de détection du NIDS et module de prévention du NIPS.

Base saine pour votre implémentation :
  1. SCAN_PORTS (anomalie comportementale)
  2. NULL_SCAN / XMAS_SCAN (drapeaux TCP illégaux)
  3. BRUTE_FORCE (tentatives de connexion répétées sur ports auth)
  4. DOS (inondation volumétrique)
  5. SQL_INJECTION (signature de charge utile)
  6. XSS (signature de scripts web)
  7. PATH_TRAVERSAL (signature de traversée d'arborescence)

Module de prévention active (NIPS) : blocage IP via iptables.
"""

import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP  # noqa: F401
from scapy.packet import Raw  # noqa: F401


class MoteurDetection:
    """Analyse les paquets, déclenche les alertes (NIDS) et bloque les attaquants (NIPS)."""

    def __init__(self, config, alertes, blocker=None):
        self.cfg = config
        self.alertes = alertes
        self.blocker = blocker or self._executer_blocage_systeme

        # Suivi d'état par IP source (pour fenêtres glissantes)
        self.scan_tracker = defaultdict(deque)
        self.dos_tracker = defaultdict(deque)
        self.brute_tracker = defaultdict(deque)

        # Anti-spam : (ip, type) -> dernier horodatage d'alerte
        self._dernieres_alertes = {}

        # Ensemble des IPs bloquées par le NIPS
        self.ips_bloquees = set()

    # ------------------------------------------------------------------
    # Prévention active NIPS
    # ------------------------------------------------------------------
    def _executer_blocage_systeme(self, ip_src):
        """Applique la règle de blocage iptables (à implémenter si besoin)."""
        # TODO: Implémenter le blocage système (ex: iptables -I INPUT -s <ip> -j DROP)
        return True

    def bloquer_ip(self, ip_src, type_attaque):
        """Déclenche la prévention active NIPS."""
        if self.cfg.NIPS_ENABLED and ip_src not in self.ips_bloquees:
            self.ips_bloquees.add(ip_src)
            self.blocker(ip_src)
            print(f"[NIPS] IP {ip_src} bloquée ({type_attaque})")

    def declencher_alerte_et_prevention(self, type_attaque, ip_src, details, maintenant):
        """Émet l'alerte NIDS et déclenche le blocage NIPS avec cooldown anti-spam."""
        cle = (ip_src, type_attaque)
        derniere = self._dernieres_alertes.get(cle)
        if derniere is not None and (maintenant - derniere) < self.cfg.ALERT_COOLDOWN:
            return
        self._dernieres_alertes[cle] = maintenant
        self.alertes.log_alert(type_attaque, ip_src, details)
        self.bloquer_ip(ip_src, type_attaque)

    # ------------------------------------------------------------------
    # Détections
    # ------------------------------------------------------------------
    def detecte_scan(self, paquet, maintenant):
        """1. Scan de ports (TCP Connect / SYN scan)."""
        # TODO: À implémenter
        pass

    def detecte_flags_anormaux(self, paquet, maintenant):
        """2. Scans furtifs (NULL scan / XMAS scan)."""
        # TODO: À implémenter
        pass

    def detecte_brute_force(self, paquet, maintenant):
        """3. Brute force d'authentification (SSH / Telnet / FTP)."""
        if not paquet.haslayer(TCP):
            return
        ip_src = paquet[IP].src
        if paquet[TCP].flags != "S" or paquet[TCP].dport not in self.cfg.MONITORED_PORTS:
            return
        self.brute_tracker[ip_src].append(maintenant)
        # Purger les entrées hors fenêtre
        while self.brute_tracker[ip_src] and self.brute_tracker[ip_src][0] < maintenant - self.cfg.BRUTE_WINDOW:
            self.brute_tracker[ip_src].popleft()
        if len(self.brute_tracker[ip_src]) > self.cfg.BRUTE_THRESHOLD:
            details = (
                f"Brute force détecté : {len(self.brute_tracker[ip_src])} tentatives SYN "
                f"sur port {paquet[TCP].dport} en {self.cfg.BRUTE_WINDOW}s"
            )
            self.declencher_alerte_et_prevention("BRUTE_FORCE", ip_src, details, maintenant)

    def detecte_dos(self, paquet, maintenant):
        """4. Déni de service (DoS Flood volumétrique)."""
        # TODO: À implémenter
        pass

    def detecte_signatures_payload(self, paquet, maintenant):
        """5, 6, 7. Signatures de payload : SQLi, XSS, Path Traversal."""
        # TODO: À implémenter
        pass

    # ------------------------------------------------------------------
    # Analyse silencieuse des paquets
    # ------------------------------------------------------------------
    def analyser(self, paquet):
        """Point d'entrée principal : reçoit chaque paquet capturé par Scapy."""
        if not paquet.haslayer(IP):
            return
        maintenant = time.time()
        # Les fonctions de détection sont appelées ici (silencieuses tant que non implémentées)
        self.detecte_scan(paquet, maintenant)
        self.detecte_flags_anormaux(paquet, maintenant)
        self.detecte_brute_force(paquet, maintenant)
        self.detecte_dos(paquet, maintenant)
        self.detecte_signatures_payload(paquet, maintenant)
