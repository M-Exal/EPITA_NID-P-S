import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


def test_detecte_scan_ports(moteur, mock_alertes, mock_blocker):
    """Test #1 : Scan de ports (ports distincts au-dessus du seuil)."""
    ip_attaquant = "192.168.1.100"
    for port in [21, 22, 80, 443]:
        paquet = IP(src=ip_attaquant, dst="192.168.1.1") / TCP(dport=port, flags="S")
        moteur.analyser(paquet)

    assert "SCAN_PORTS" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_null_scan(moteur, mock_alertes, mock_blocker):
    """Test #2A : Scan furtif NULL (aucun drapeau TCP)."""
    ip_attaquant = "192.168.1.101"
    paquet = IP(src=ip_attaquant, dst="192.168.1.1") / TCP(dport=80, flags=0)
    moteur.analyser(paquet)

    assert "NULL_SCAN" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_xmas_scan(moteur, mock_alertes, mock_blocker):
    """Test #2B : Scan furtif XMAS (drapeaux FIN+PSH+URG = 0x29)."""
    ip_attaquant = "192.168.1.102"
    paquet = IP(src=ip_attaquant, dst="192.168.1.1") / TCP(dport=22, flags="FPU")
    moteur.analyser(paquet)

    assert "XMAS_SCAN" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_brute_force(moteur, mock_alertes, mock_blocker):
    """Test #3 : Brute force d'authentification sur port sensible (seuil = 3)."""
    ip_attaquant = "192.168.1.103"
    for _ in range(4):
        paquet = IP(src=ip_attaquant, dst="192.168.1.1") / TCP(dport=22, flags="S")
        moteur.analyser(paquet)

    assert "BRUTE_FORCE" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_dos(moteur, mock_alertes, mock_blocker):
    """Test #4 : DoS flood volumétrique (seuil = 5 paquets)."""
    ip_attaquant = "192.168.1.104"
    for _ in range(6):
        paquet = IP(src=ip_attaquant, dst="192.168.1.1") / TCP(dport=80, flags="A")
        moteur.analyser(paquet)

    assert "DOS" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_sql_injection(moteur, mock_alertes, mock_blocker):
    """Test #5 : Détection par signature d'injection SQL."""
    ip_attaquant = "192.168.1.105"
    payload = "GET /index.php?id=1' UNION SELECT username, password FROM users -- HTTP/1.1\r\n\r\n"
    paquet = (
        IP(src=ip_attaquant, dst="192.168.1.1")
        / TCP(dport=80)
        / Raw(load=payload.encode())
    )
    moteur.analyser(paquet)

    assert "SQL_INJECTION" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_xss(moteur, mock_alertes, mock_blocker):
    """Test #6 : Détection par signature de Cross-Site Scripting (XSS)."""
    ip_attaquant = "192.168.1.106"
    payload = "POST /comment HTTP/1.1\r\n\r\n<script>alert('pwned')</script>"
    paquet = (
        IP(src=ip_attaquant, dst="192.168.1.1")
        / TCP(dport=80)
        / Raw(load=payload.encode())
    )
    moteur.analyser(paquet)

    assert "XSS" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_detecte_path_traversal(moteur, mock_alertes, mock_blocker):
    """Test #7 : Détection par signature de Directory Traversal."""
    ip_attaquant = "192.168.1.107"
    payload = "GET /download?file=../../../../etc/passwd HTTP/1.1\r\n\r\n"
    paquet = (
        IP(src=ip_attaquant, dst="192.168.1.1")
        / TCP(dport=80)
        / Raw(load=payload.encode())
    )
    moteur.analyser(paquet)

    assert "PATH_TRAVERSAL" in mock_alertes.types
    assert ip_attaquant in mock_blocker.bloques


def test_cooldown_anti_spam(moteur, mock_alertes):
    """Vérifie le cooldown anti-spam."""
    ip_attaquant = "192.168.1.108"
    paquet = (
        IP(src=ip_attaquant, dst="192.168.1.1")
        / TCP(dport=80)
        / Raw(load=b"SELECT * FROM users")
    )
    moteur.analyser(paquet)
    moteur.analyser(paquet)
    assert len(mock_alertes.alertes) == 1
