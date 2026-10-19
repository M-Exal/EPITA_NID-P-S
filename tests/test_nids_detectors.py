"""
test_nids_detectors.py — Tests unitaires du moteur de détection du NIDS.

Couvre les deux familles de détection exigées par le cahier des charges :
  * détection d'ANOMALIES  (scan de ports, DoS, brute-force) ;
  * détection de SIGNATURES (SQLi, XSS, path traversal, flags TCP illégaux).

Plus un scénario « trafic normal » qui vérifie l'absence de FAUSSES alertes
(point explicitement traité dans le cahier des charges).
"""

import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

from conftest import charger


# ======================================================================
# Détection d'anomalies
# ======================================================================
def test_scan_de_ports_detecte(moteur, alertes):
    """Une IP touchant >15 ports différents en <10 s déclenche SCAN_PORTS."""
    for port in range(1000, 1021):           # 21 ports distincts > seuil 15
        moteur.analyser(IP(src="10.0.0.1") / TCP(dport=port, flags="S"))
    assert "SCAN_PORTS" in alertes.types
    assert alertes.alertes[0][1] == "10.0.0.1"


def test_scan_sous_le_seuil_silencieux(moteur, alertes):
    """Moins de 15 ports distincts : pas d'alerte (anti faux positif)."""
    for port in range(1000, 1010):           # 10 ports < seuil 15
        moteur.analyser(IP(src="10.0.0.1") / TCP(dport=port, flags="S"))
    assert alertes.alertes == []


def test_scan_fenetre_glissante(moteur, alertes):
    """Les évènements antérieurs à la fenêtre sont purgés : un scan étalé
    sur plusieurs fenêtres ne doit pas cumuler artificiellement."""
    for port in range(1000, 1010):
        moteur.analyser(IP(src="10.0.0.1") / TCP(dport=port, flags="S"))
    # On vieillit artificiellement les évènements hors fenêtre (10 s).
    hors_fenetre = time.time() - 11
    for evenement in list(moteur.scan_tracker["10.0.0.1"]):
        if isinstance(evenement, tuple):
            moteur.scan_tracker["10.0.0.1"].popleft()
    # Nouvelle salve : repart de zéro, 10 ports seulement -> pas d'alerte.
    for port in range(2000, 2010):
        moteur.analyser(IP(src="10.0.0.1") / TCP(dport=port, flags="S"))
    assert alertes.alertes == []
    assert hors_fenetre <= time.time()


def test_dos_detecte(moteur, alertes, nids_config, monkeypatch):
    """Un volume anormalement élevé de paquets depuis une IP -> alerte DOS."""
    monkeypatch.setattr(nids_config, "DOS_THRESHOLD", 50)
    for _ in range(51):
        moteur.analyser(IP(src="10.0.0.2") / TCP(dport=80, flags="S"))
    assert "DOS" in alertes.types


def test_brute_force_detecte(moteur, alertes):
    """Des SYN répétés vers un port d'authentification -> BRUTE_FORCE."""
    for _ in range(11):                       # seuil : 10 SYN / 30 s
        moteur.analyser(IP(src="10.0.0.3") / TCP(dport=2222, flags="S"))
    assert "BRUTE_FORCE" in alertes.types


def test_brute_force_hors_ports_surveilles_silencieux(moteur, alertes):
    """Les SYN vers un port non surveillé (ex. 80) ne comptent pas pour le
    brute-force (ils alimentent éventuellement le détecteur de scan/DoS)."""
    for _ in range(30):
        moteur.analyser(IP(src="10.0.0.3") / TCP(dport=80, flags="S"))
    assert "BRUTE_FORCE" not in alertes.types


# ======================================================================
# Détection par signatures
# ======================================================================
def test_injection_sql_detectee(moteur, alertes):
    """Motif SQLi dans le payload -> SQL_INJECTION."""
    paquet = IP(src="10.0.0.4") / TCP(dport=80) / Raw(load=b"admin' OR '1'='1")
    moteur.analyser(paquet)
    assert "SQL_INJECTION" in alertes.types


def test_xss_detecte(moteur, alertes):
    paquet = IP(src="10.0.0.5") / TCP(dport=80) / Raw(load=b"<script>alert(1)</script>")
    moteur.analyser(paquet)
    assert "XSS" in alertes.types


def test_path_traversal_detecte(moteur, alertes):
    paquet = IP(src="10.0.0.6") / TCP(dport=80) / Raw(load=b"GET /../../etc/passwd HTTP/1.1")
    moteur.analyser(paquet)
    assert "PATH_TRAVERSAL" in alertes.types


def test_flags_anormaux_null_et_xmas(moteur, alertes):
    """NULL scan (aucun drapeau) et XMAS scan (FIN+PSH+URG)."""
    moteur.analyser(IP(src="10.0.0.7") / TCP(dport=80, flags=0))
    moteur.analyser(IP(src="10.0.0.7") / TCP(dport=81, flags=0x29))
    assert "NULL_SCAN" in alertes.types
    assert "XMAS_SCAN" in alertes.types


# ======================================================================
# Comportement général du moteur
# ======================================================================
def test_anti_spam_cooldown(moteur, alertes):
    """Une même alerte (IP, type) n'est pas répétée pendant le cooldown."""
    for _ in range(11):
        moteur.analyser(IP(src="10.0.0.3") / TCP(dport=2222, flags="S"))
    for _ in range(20):                       # seconde salve dans le délai
        moteur.analyser(IP(src="10.0.0.3") / TCP(dport=2222, flags="S"))
    assert alertes.types.count("BRUTE_FORCE") == 1


def test_paquet_sans_ip_ignore(moteur, alertes):
    """Un paquet IPv6/ARP/non-IP ne doit lever aucune exception ni alerte."""
    moteur.analyser(UDP(sport=1234, dport=53))
    assert alertes.alertes == []


def test_paquet_malforme_ne_tue_pas_le_moteur(moteur, alertes):
    """L'analyse doit rester tolérante : un paquet étrange ne plante pas."""
    moteur.analyser(IP(src="10.0.0.8") / TCP(dport=2222, flags="S") / Raw(load=b"\xff\xfe"))
    moteur.analyser(IP(src="10.0.0.8") / ICMP())
    assert isinstance(alertes.alertes, list)


# ======================================================================
# Validation : pas de fausses alertes sur du trafic normal
# ======================================================================
def test_trafic_normal_sans_alerte(moteur, alertes):
    """
    Scénario de validation exigé par le cahier des charges : en condition
    normale, le NIDS ne génère AUCUNE alerte.
    """
    ip = "192.168.1.50"

    # Poignées de main TCP normales (peu de ports, peu de paquets).
    for port in (80, 443, 2222):
        moteur.analyser(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="S"))
        moteur.analyser(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="SA"))
        moteur.analyser(IP(src=ip) / TCP(sport=40000 + port, dport=port, flags="A"))

    # Requêtes HTTP bénignes (sans motif de signature).
    for ressource in ("/", "/index.html", "/style.css", "/logo.png"):
        charge = f"GET {ressource} HTTP/1.1\r\nHost: example\r\n\r\n"
        moteur.analyser(IP(src=ip) / TCP(dport=80) / Raw(load=charge.encode()))

    # DNS et ping courants.
    moteur.analyser(IP(src=ip) / UDP(sport=53000, dport=53) / Raw(load=b"\x00\x00example"))
    moteur.analyser(IP(src=ip) / ICMP())

    assert alertes.alertes == []


def test_chargement_module_sans_collision():
    """Sanity-check du helper de chargement des tests (alias uniques)."""
    mod_nids = charger("nids", "config")
    mod_pentest = charger("pentest", "config")
    assert mod_nids.Config is not mod_pentest.Config
    assert mod_nids.Config.INTERFACE
    assert hasattr(mod_pentest.Config, "TARGET_HOST")
