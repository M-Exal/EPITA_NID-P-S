"""
test_metasploit.py — Tests du module d'automatisation Metasploit du pentest.

Aucun démon msfrpcd réel n'est requis : on vérifie
  * la dégradation propre quand pymetasploit3 est absent ;
  * la dégradation propre quand la connexion au démon échoue ;
  * le pilotage complet via un client RPC *simulé* (mock) ;
  * l'analyse de la sortie Metasploit (extraction des identifiants).
"""

import pytest

from conftest import charger


@pytest.fixture
def module():
    return charger("pentest", "pentest")


@pytest.fixture
def pentester(module, pentest_config):
    # Réessais réduits : aucun test ne doit attendre le délai de production.
    pentest_config.MSF_RPC_RETRIES = 1
    pentest_config.MSF_RPC_DELAY = 0
    pentest_config.MSF_TIMEOUT = 5
    return module.Pentester(pentest_config)


# --------------------------------------------------------------------------- #
# Faux client RPC (remplace pymetasploit3)
# --------------------------------------------------------------------------- #
class FakeConsole:
    """Console RPC simulée : mémorise les commandes, rejoue une sortie figée."""

    SORTIE = (
        "[*] 127.0.0.1:2222 - Starting bruteforce\n"
        "[-] 127.0.0.1:2222 - Failed: 'admin:admin'\n"
        "[+] 127.0.0.1:2222 - Success: 'root:toor' 'uid=0(root) gid=0(root)'\n"
        "[*] Scanned 1 of 1 hosts (100% complete)\n"
    )

    def __init__(self):
        self.commandes = []
        self._lu = False

    def write(self, data):
        self.commandes.append(data)

    def read(self):
        # Premier appel : livre toute la sortie et signale la fin (busy=False).
        if not self._lu:
            self._lu = True
            return {"data": self.SORTIE, "busy": False}
        return {"data": "", "busy": False}

    def destroy(self):
        pass


class FakeConsoles:
    def __init__(self):
        self.derniere = None

    def console(self):
        self.derniere = FakeConsole()
        return self.derniere


class FakeClient:
    """MsfRpcClient simulé : accepte la même signature d'appel."""

    def __init__(self, password, server=None, port=None, ssl=None, username=None):
        self.password = password
        self.server = server
        self.consoles = FakeConsoles()


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_fallback_sans_pymetasploit3(module, pentester, monkeypatch):
    """pymetasploit3 absent : la méthode n'échoue pas, elle le signale."""
    monkeypatch.setattr(module, "MSF_DISPONIBLE", False)
    resultat = pentester.metasploit_ssh_login()

    assert resultat == []
    entree = pentester.resultats["attaques"]["metasploit_ssh_login"]
    assert entree["statut"] == "indisponible"


def test_fallback_connexion_impossible(module, pentester, monkeypatch):
    """msfrpcd injoignable : réessais épuisés puis dégradation propre."""
    monkeypatch.setattr(module, "MSF_DISPONIBLE", True)

    def _client_qui_echoue(*args, **kwargs):
        raise ConnectionRefusedError("msfrpcd injoignable")

    monkeypatch.setattr(module, "MsfRpcClient", _client_qui_echoue, raising=False)
    resultat = pentester.metasploit_ssh_login()

    assert resultat == []
    entree = pentester.resultats["attaques"]["metasploit_ssh_login"]
    assert entree["statut"] == "indisponible"
    assert "connexion" in entree["raison"].lower()


def test_pilotage_complet_mocke(module, pentester, monkeypatch):
    """Client RPC simulé : identifiants extraits et résultats enregistrés."""
    monkeypatch.setattr(module, "MSF_DISPONIBLE", True)
    monkeypatch.setattr(module, "MsfRpcClient", FakeClient, raising=False)

    resultat = pentester.metasploit_ssh_login()

    assert resultat == ["root:toor"]
    entree = pentester.resultats["attaques"]["metasploit_ssh_login"]
    assert entree["statut"] == "ok"
    assert entree["module"] == "auxiliary/scanner/ssh/ssh_login"
    assert entree["identifiants_trouves"] == ["root:toor"]


def test_commandes_envoyees_a_la_console(module, pentester, monkeypatch):
    """Le script de ressource attendu est bien transmis à Metasploit."""
    monkeypatch.setattr(module, "MSF_DISPONIBLE", True)

    capture = {}

    class ClientCapture(FakeClient):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            capture["consoles"] = self.consoles

    monkeypatch.setattr(module, "MsfRpcClient", ClientCapture, raising=False)
    pentester.metasploit_ssh_login()

    envoyees = "".join(capture["consoles"].derniere.commandes)
    assert "use auxiliary/scanner/ssh/ssh_login" in envoyees
    assert f"set RHOSTS {pentester.cible}" in envoyees
    assert "run" in envoyees


def test_extraction_succes():
    """Analyse d'une sortie Metasploit : seules les lignes Success comptent."""
    Pentester = charger("pentest", "pentest").Pentester
    sortie = (
        "[-] Failed: 'admin:admin'\n"
        "[+] 10.0.0.2:2222 - Success: 'root:toor' 'uname -a'\n"
        "[+] 10.0.0.2:2222 - Success: 'user:12345'\n"
    )
    assert Pentester._extraire_succes_msf(sortie) == ["root:toor", "user:12345"]


def test_ecriture_listes(pentester, pentest_config):
    """Les dictionnaires user/pass sont écrits dans DATA_DIR pour msfrpcd."""
    user_file, pass_file = pentester._ecrire_listes_msf()
    import os

    assert os.path.exists(user_file) and os.path.exists(pass_file)
    with open(user_file, encoding="ascii") as f:
        assert "root" in f.read()
