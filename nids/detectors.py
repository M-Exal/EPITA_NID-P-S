"""
detectors.py — Moteur de détection du NIDS.

On reprend les fonctions vues en cours (`detecte_scan`, `detecte_dos`,
`detecte_brute_force`, `detecte_sql_injection`) mais on les rend robustes :

  * Fenêtres glissantes temporelles  -> on compte les évènements sur les N
    dernières secondes, pas depuis le début (évite les faux positifs et la
    mémoire qui gonfle indéfiniment).
  * Anti-spam d'alertes (cooldown)    -> une même (IP, type) n'est pas
    re-signalée en boucle.
  * Deux approches combinées :
      - détection d'ANOMALIES (seuils statistiques : scan, DoS, brute-force) ;
      - détection de SIGNATURES (motifs dans le payload : SQLi, XSS, traversal,
        drapeaux TCP anormaux NULL/XMAS).

La classe `MoteurDetection` est instanciée par nids.py et reçoit chaque paquet
capturé par Scapy.
"""

import time
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


class MoteurDetection:
    """Analyse les paquets et déclenche des alertes via l'AlertManager."""

    def __init__(self, config, alertes):
        self.cfg = config
        self.alertes = alertes

        # ------- Trackers (état par IP source) -------
        # Scan : IP -> deque de (timestamp, port_destination)
        self.scan_tracker = defaultdict(deque)
        # DoS : IP -> deque de timestamps (tous paquets)
        self.dos_tracker = defaultdict(deque)
        # Brute-force : IP -> deque de timestamps (SYN vers ports d'auth)
        self.brute_tracker = defaultdict(deque)

        # Anti-spam : (ip, type) -> dernier horodatage d'alerte
        self._dernieres_alertes = {}

    # ------------------------------------------------------------------
    # Utilitaires internes
    # ------------------------------------------------------------------
    @staticmethod
    def _purger(file_dattente, fenetre, maintenant, avec_port=False):
        """
        Retire de la file les évènements plus vieux que `fenetre` secondes.

        Les deques sont triées chronologiquement : on dépile par la gauche
        tant que l'évènement le plus ancien est hors fenêtre.
        """
        limite = maintenant - fenetre
        while file_dattente:
            ts = file_dattente[0][0] if avec_port else file_dattente[0]
            if ts < limite:
                file_dattente.popleft()
            else:
                break

    def _peut_alerter(self, ip_src, type_attaque, maintenant):
        """Renvoie True si le cooldown anti-spam est écoulé pour (ip, type)."""
        cle = (ip_src, type_attaque)
        dernier = self._dernieres_alertes.get(cle, 0)
        if maintenant - dernier >= self.cfg.ALERT_COOLDOWN:
            self._dernieres_alertes[cle] = maintenant
            return True
        return False

    # ------------------------------------------------------------------
    # Détection d'ANOMALIES
    # ------------------------------------------------------------------
    def detecte_scan(self, paquet, maintenant):
        """
        Scan de ports : une même IP contacte trop de ports DIFFÉRENTS dans la
        fenêtre (caractéristique d'un `nmap -p-`).
        """
        if not paquet.haslayer(TCP):
            return
        ip_src = paquet[IP].src
        dport = paquet[TCP].dport

        suivi = self.scan_tracker[ip_src]
        suivi.append((maintenant, dport))
        self._purger(suivi, self.cfg.SCAN_WINDOW, maintenant, avec_port=True)

        ports_distincts = {p for _, p in suivi}
        if len(ports_distincts) > self.cfg.SCAN_THRESHOLD:  # Seuil de détection
            if self._peut_alerter(ip_src, "SCAN_PORTS", maintenant):
                self.alertes.log_alert(
                    "SCAN_PORTS", ip_src,
                    f"({len(ports_distincts)} ports en {self.cfg.SCAN_WINDOW}s)")

    def detecte_dos(self, paquet, maintenant):
        """
        Déni de service : volume de paquets anormalement élevé depuis une IP
        (SYN flood, UDP flood, ICMP flood…).
        """
        if not paquet.haslayer(IP):
            return
        ip_src = paquet[IP].src

        suivi = self.dos_tracker[ip_src]
        suivi.append(maintenant)
        self._purger(suivi, self.cfg.DOS_WINDOW, maintenant)

        if len(suivi) > self.cfg.DOS_THRESHOLD:  # Seuil de détection
            if self._peut_alerter(ip_src, "DOS", maintenant):
                self.alertes.log_alert(
                    "DOS", ip_src,
                    f"({len(suivi)} paquets en {self.cfg.DOS_WINDOW}s)")

    def detecte_brute_force(self, paquet, maintenant):
        """
        Brute-force : trop de tentatives de connexion (SYN) vers un port
        d'authentification (SSH 22/2222, Telnet 23/2223).
        """
        if not (paquet.haslayer(TCP) and paquet.haslayer(IP)):
            return
        # On ne compte que les SYN "purs" (flag S, pas SYN-ACK) = demandes de
        # connexion entrantes vers un service surveillé.
        if paquet[TCP].flags == "S" and paquet[TCP].dport in self.cfg.MONITORED_PORTS:
            ip_src = paquet[IP].src
            suivi = self.brute_tracker[ip_src]
            suivi.append(maintenant)
            self._purger(suivi, self.cfg.BRUTE_WINDOW, maintenant)

            if len(suivi) > self.cfg.BRUTE_THRESHOLD:  # Seuil de détection
                if self._peut_alerter(ip_src, "BRUTE_FORCE", maintenant):
                    self.alertes.log_alert(
                        "BRUTE_FORCE", ip_src,
                        f"({len(suivi)} tentatives vers le port "
                        f"{paquet[TCP].dport} en {self.cfg.BRUTE_WINDOW}s)")

    # ------------------------------------------------------------------
    # Détection de SIGNATURES
    # ------------------------------------------------------------------
    def detecte_sql_injection(self, paquet, maintenant):
        """
        Injection SQL (et XSS / path traversal) : recherche de motifs connus
        dans la charge utile (payload) du paquet.
        """
        if not (paquet.haslayer(Raw) and paquet.haslayer(IP)):
            return
        charge = paquet[Raw].load.decode(errors="ignore")
        charge_maj = charge.upper()
        ip_src = paquet[IP].src

        for motif in self.cfg.SIGNATURES_SQL:
            if motif.upper() in charge_maj:
                if self._peut_alerter(ip_src, "SQL_INJECTION", maintenant):
                    extrait = charge.strip()[:80]
                    self.alertes.log_alert(
                        "SQL_INJECTION", ip_src, f'payload="{extrait}"')
                return  # une signature suffit

        for motif in self.cfg.SIGNATURES_XSS:
            if motif.lower() in charge.lower():
                if self._peut_alerter(ip_src, "XSS", maintenant):
                    self.alertes.log_alert(
                        "XSS", ip_src, f'payload="{charge.strip()[:80]}"')
                return

        for motif in self.cfg.SIGNATURES_TRAVERSAL:
            if motif in charge:
                if self._peut_alerter(ip_src, "PATH_TRAVERSAL", maintenant):
                    self.alertes.log_alert(
                        "PATH_TRAVERSAL", ip_src, f'payload="{charge.strip()[:80]}"')
                return

    def detecte_flags_anormaux(self, paquet, maintenant):
        """
        Scan furtif : drapeaux TCP illégaux utilisés par nmap pour contourner
        certains pare-feu (NULL scan = aucun flag, XMAS = FIN+PSH+URG).
        """
        if not (paquet.haslayer(TCP) and paquet.haslayer(IP)):
            return
        flags = int(paquet[TCP].flags)
        ip_src = paquet[IP].src

        if flags == 0:  # NULL scan
            if self._peut_alerter(ip_src, "NULL_SCAN", maintenant):
                self.alertes.log_alert("NULL_SCAN", ip_src, "(paquet TCP sans drapeau)")
        elif flags == 0x29:  # XMAS scan : FIN(0x01)+PSH(0x08)+URG(0x20)
            if self._peut_alerter(ip_src, "XMAS_SCAN", maintenant):
                self.alertes.log_alert("XMAS_SCAN", ip_src, "(drapeaux FIN+PSH+URG)")

    # ------------------------------------------------------------------
    # Point d'entrée : appelé pour chaque paquet capturé
    # ------------------------------------------------------------------
    def analyser(self, paquet):
        """Dispatche le paquet vers tous les détecteurs (avec gestion d'erreurs)."""
        if not paquet.haslayer(IP):
            return
        maintenant = time.time()
        try:
            self.detecte_scan(paquet, maintenant)
            self.detecte_dos(paquet, maintenant)
            self.detecte_brute_force(paquet, maintenant)
            self.detecte_sql_injection(paquet, maintenant)
            self.detecte_flags_anormaux(paquet, maintenant)
        except Exception as e:  # noqa: BLE001 — un paquet malformé ne doit pas tuer le NIDS
            print(f"[NIDS] Erreur d'analyse d'un paquet : {e}")
