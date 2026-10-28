"""
Moteur de détection du NIDS et module de prévention du NIPS.

Détections implémentées :
  1. SCAN_PORTS (anomalie comportementale : scan de ports TCP)
  2. NULL_SCAN / XMAS_SCAN (drapeaux TCP illégaux)
  3. BRUTE_FORCE (tentatives de connexion répétées sur ports auth)

À implémenter par les autres membres du groupe :
  4. DOS (inondation volumétrique)
  5. SQL_INJECTION (signature de charge utile)
  6. XSS (signature de scripts web)
  7. PATH_TRAVERSAL (signature de traversée d'arborescence)
"""

import subprocess  # noqa: F401
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP
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
        if not paquet.haslayer(TCP):
            return
        # N'analyser que les paquets SYN d'initiation de connexion (SYN pur).
        # Les paquets de réponse du serveur cible (SYN-ACK, RST-ACK) vers les ports
        # éphémères du client ne doivent pas être pris pour un scan émis par le serveur.
        try:
            flags_str = str(paquet[TCP].flags)
            if flags_str != "S" and int(paquet[TCP].flags) != 0x02:
                return
        except Exception:
            return

        ip_src = paquet[IP].src
        dport = paquet[TCP].dport
        self.scan_tracker[ip_src].append((maintenant, dport))

        # Purge hors fenêtre
        while self.scan_tracker[ip_src] and self.scan_tracker[ip_src][0][0] < maintenant - self.cfg.SCAN_WINDOW:
            self.scan_tracker[ip_src].popleft()

        ports_uniques = {p for _, p in self.scan_tracker[ip_src]}
        if len(ports_uniques) > self.cfg.SCAN_THRESHOLD:
            details = (
                f"Scan de ports détecté : {len(ports_uniques)} ports distincts contactés "
                f"en {self.cfg.SCAN_WINDOW}s"
            )
            self.declencher_alerte_et_prevention("SCAN_PORTS", ip_src, details, maintenant)

    def detecte_flags_anormaux(self, paquet, maintenant):
        """2. Scans furtifs (NULL scan / XMAS scan)."""
        if not paquet.haslayer(TCP):
            return
        ip_src = paquet[IP].src
        flags = paquet[TCP].flags
        dport = paquet[TCP].dport

        try:
            val_flags = int(flags)
        except (ValueError, TypeError):
            val_flags = -1

        # NULL Scan (flags == 0)
        if val_flags == 0 or flags == 0:
            details = f"NULL scan détecté (flags=0) vers le port {dport}"
            self.declencher_alerte_et_prevention("NULL_SCAN", ip_src, details, maintenant)
            return

        # XMAS Scan : FIN (0x01) + PSH (0x08) + URG (0x20) = 0x29 (41)
        if val_flags == 0x29 or str(flags) in ("FPU", "FPUA"):
            details = f"XMAS scan détecté (flags=FPU/0x29) vers le port {dport}"
            self.declencher_alerte_et_prevention("XMAS_SCAN", ip_src, details, maintenant)
            return

    def detecte_brute_force(self, paquet, maintenant):
        """3. Brute force d'authentification (SSH / Telnet / FTP)."""
        if not paquet.haslayer(TCP):
            return
        ip_src = paquet[IP].src
        # SYN flag seul sur un port surveillé (authentification)
        flags_str = str(paquet[TCP].flags)
        if flags_str != "S" or paquet[TCP].dport not in self.cfg.MONITORED_PORTS:
            return
        self.brute_tracker[ip_src].append(maintenant)
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
        """5, 6, 7. Signatures de payload : SQLi, XSS, Path Traversal.

        Inspecte la charge utile (couche Raw) des paquets TCP sur le port 80.
        Recherche les signatures définies dans la configuration de façon
        insensible à la casse. Déclenche une alerte dès la première signature
        correspondante.
        """
        if not (paquet.haslayer(TCP) and paquet.haslayer(Raw)):
            return
        tcp_layer = paquet[TCP]
        # N'inspecter que les requêtes entrantes vers le serveur Web (dport=80),
        # pas les réponses sortantes (sport=80) pour éviter les faux positifs et alertes en double
        if tcp_layer.dport != 80:
            return

        ip_src = paquet[IP].src
        charge = paquet[Raw].load.decode("utf-8", errors="ignore").upper()

        # 5. SQL_INJECTION
        for sig in self.cfg.SIGNATURES_SQL:
            if sig.upper() in charge:
                details = f"signature SQLi détectée : {sig!r}"
                self.declencher_alerte_et_prevention(
                    "SQL_INJECTION", ip_src, details, maintenant
                )
                return

        # 6. XSS
        for sig in self.cfg.SIGNATURES_XSS:
            if sig.upper() in charge:
                details = f"signature XSS détectée : {sig!r}"
                self.declencher_alerte_et_prevention(
                    "XSS", ip_src, details, maintenant
                )
                return

        # 7. PATH_TRAVERSAL
        for sig in self.cfg.SIGNATURES_TRAVERSAL:
            if sig.upper() in charge:
                details = f"signature traversal détectée : {sig!r}"
                self.declencher_alerte_et_prevention(
                    "PATH_TRAVERSAL", ip_src, details, maintenant
                )
                return

    # ------------------------------------------------------------------
    # Analyse des paquets
    # ------------------------------------------------------------------
    def analyser(self, paquet):
        """Point d'entrée principal : reçoit chaque paquet capturé par Scapy."""
        if not paquet.haslayer(IP):
            return
        maintenant = time.time()
        self.detecte_flags_anormaux(paquet, maintenant)
        self.detecte_signatures_payload(paquet, maintenant)
        self.detecte_scan(paquet, maintenant)
        self.detecte_brute_force(paquet, maintenant)
        self.detecte_dos(paquet, maintenant)
