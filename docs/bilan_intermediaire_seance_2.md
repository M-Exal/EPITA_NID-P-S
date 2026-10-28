# 🛡️ Bilan Intermédiaire — Projet Sécurité Python (Séance 2)

**EPITA — Majeure Sécurité (ING3)**  
*Projet : Honeypot & Système de Détection / Prévention d'Intrusion (NIDS / NIPS)*  
**Date :** Octobre 2026  

---

## 1. Composition de l'Équipe & Répartition des Rôles

Conformément au fichier `AUTHORS`, l'équipe se compose de 4 membres avec des périmètres de responsabilité clairs et complémentaires :

| Membre | Rôle Attribué | Responsabilités Principales |
| :--- | :--- | :--- |
| **Alexis Blanc-Feuillet** (`alexis`) | **Lead Tech & Architecture Détection (NIDS / SIEM)** | • Architecture globale et coordination technique.<br>• Moteur de capture et analyse temps réel Scapy (`nids/`).<br>• Dashboard SOC web en direct (*CyBear SIEM* - Flask / SSE).<br>• Chaîne d'alertes instantanées (Webhook Discord). |
| **Maximilien** (`maximilien`) | **Responsable Pentest & Attaques Réseau** | • Développement du module de pentest automatisé (`pentest/pentest.py`).<br>• Implémentation des attaques niveau transport / réseau (Scan TCP Connect, Scan furtif XMAS `flags=FPU`, Brute-force SSH, DoS Flood).<br>• Calibration des volumes d'attaque par rapport aux seuils NIDS. |
| **Antoine Goetschy** (`antoine`) | **Responsable DevOps & Infrastructure Sécurité** | • Conteneurisation Docker multi-services (`docker-compose.yml`).<br>• Configuration du réseau isolé (`honeynet`) et partage de pile réseau.<br>• Pipeline d'intégration continue CI/CD (GitHub Actions).<br>• Module de chiffrement Fernet (AES-128/HMAC-SHA256) et prévention active NIPS (iptables). |
| **Léa Bonet** (`lea.bonet`) | **Responsable Pentest Web & Analyse des Données** | • Implémentation des attaques applicatives Web contre DVWA / Mutillidae (SQLi, XSS, Path Traversal).<br>• Module d'analyse et de corrélation des journaux (`analysis/analyze.py`).<br>• Rédaction des comptes-rendus d'avancement et préparation du support de soutenance. |

---

## 2. Choix & Configuration du Honeypot

### Cible retenue : Metasploitable 2
Nous avons sélectionné **Metasploitable 2** déployé sous forme de conteneur Docker officiel (`tleemcjr/metasploitable2:latest`).

### Justification :
Contrairement à des honeypots émulés basiques qui se contentent de simuler quelques bannières, Metasploitable 2 fournit un environnement Linux complet avec de véritables services applicatifs et d'authentification vulnérables :
* **Serveur Web Apache** : Héberge les applications cibles **DVWA** (*Damn Vulnerable Web Application*) et **Mutillidae**.
* **Services d'authentification** : Démons OpenSSH (port 22), Telnet (port 23), FTP vsftpd (port 21).
* **Bases de données & partages** : MySQL (port 3306), Samba (ports 139/445).

### Couplage Réseau NIDS ↔ Honeypot :
Le conteneur de détection est attaché directement au namespace réseau de Metasploitable 2 :
```yaml
network_mode: "service:metasploitable"
cap_add:
  - NET_ADMIN
  - NET_RAW
```
Le NIDS écoute directement sur l'interface `eth0` partagée, lui permettant de voir 100% du trafic entrant/sortant de la cible.

---

## 3. Spécification des 8 Attaques du Pentest Automatisé

Le script modulaire `pentest/pentest.py` implémente 8 scénarios distincts dont les volumes sont calibrés pour dépasser les seuils de détection :

1. **Scan de ports TCP (Reconnaissance)** :
   * *Méthode* : Connexions TCP Connect séquentielles sur la liste des ports cibles (21, 22, 23, 80, 139, 445, 3306...).
   * *Seuil NIDS* : > 15 ports distincts en moins de 10 secondes.
2. **Scan furtif XMAS (Scans anormaux)** :
   * *Méthode* : Envoi de paquets Scapy avec les drapeaux illégaux FIN, PSH, URG (`flags='FPU'`).
   * *Seuil NIDS* : Détection immédiate par signature de drapeaux TCP non conformes.
3. **Scan furtif NULL (Scans anormaux)** :
   * *Méthode* : Envoi de paquets TCP Scapy sans aucun drapeau activé (`flags=0`), combinaison illégale au sens de la RFC 793.
   * *Seuil NIDS* : Détection immédiate par signature de drapeaux TCP vides (`NULL_SCAN`).
4. **Force brute SSH (Authentification)** :
   * *Méthode* : Tentatives répétées d'authentification via `paramiko` avec un dictionnaire de comptes faibles (`msfadmin:msfadmin`, `root:root`).
   * *Seuil NIDS* : > 10 paquets SYN vers le port 22 en 30 secondes.
5. **Déni de Service DoS (Inondation volumétrique)** :
   * *Méthode* : Boucle rapide d'inondation TCP/HTTP (250 requêtes).
   * *Seuil NIDS* : > 200 paquets par IP en moins de 5 secondes.
6. **Injection SQL (Web)** :
   * *Méthode* : Requêtes HTTP GET/POST ciblées vers DVWA contenant des charges utiles SQL (`' OR '1'='1`, `UNION SELECT...`).
   * *Seuil NIDS* : Inspection de la charge utile (DPI) sur port 80.
7. **Cross-Site Scripting XSS (Web)** :
   * *Méthode* : Injection de balises de script malveillant (`<script>alert('XSS')</script>`, `<img src=x onerror=...>`) dans les formulaires DVWA.
   * *Seuil NIDS* : Détection de signatures de balises de script.
8. **Traversée de Répertoire Path Traversal (Web)** :
   * *Méthode* : Requêtes HTTP visant à lire `/etc/passwd` via des séquences `../../../../etc/passwd` et encodages URL (`%2e%2e%2f`).
   * *Seuil NIDS* : Détection de motifs de navigation d'arborescence.

Les résultats de chaque attaque sont enregistrés dans `data/pentest/pentest_results.json` (avec repli vers `/tmp` si le dossier est en lecture seule).

---

## 4. Outils & Technologies Utilisés

* **Langage & Environnement** : Python 3.10+ / 3.14, `venv`, pip.
* **Capture Réseau & Paquets** : `scapy` (reniflage passif et génération de paquets bruts).
* **Conteneurisation** : Docker, Docker Compose v2 (profils d'exécution `attaque`, réseau partagé `service:metasploitable`).
* **Supervision & Alertes** :
  * Dashboard SIEM temps réel autonome en Flask avec streaming SSE (*Server-Sent Events*).
  * Webhook Discord avec notifications riches (couleurs de sévérité, mentions `@here`).
* **Sécurité & Chiffrement** : Cryptographie symétrique authentifiée Fernet (AES-128-CBC + HMAC-SHA256).
* **Qualité de code & CI/CD** : GitHub Actions, pytest (51 tests unitaires, dont 43 actifs — 8 marqués `skip` en attente des détecteurs NIDS et du NIPS restants).

---

## 5. État d'Avancement Réel (Séance 2 — mis à jour)

| Composant | Statut | Détails |
| :--- | :---: | :--- |
| **Environnement Docker** | ✅ Terminé | Metasploitable 2 + NIDS configurés sur réseau `honeynet`. |
| **Supervision SIEM Temps Réel** | ✅ Terminé | Dashboard SOC web accessible sur `http://localhost:5050` avec flux SSE + panneau d'attaques web (`/attaques`). |
| **Système d'Alertes Discord** | ✅ Terminé | Webhook fonctionnel avec notification de criticité et d'intrusion (désactivation propre via `webhook_url=''`). |
| **Pipeline CI/CD & Tests** | ✅ Terminé | 51 tests unitaires (43 actifs, 8 `skip` en attente d'implémentation), validation automatisée GitHub Actions. |
| **Script Pentest Automatisé** | ✅ Terminé | Les 8 scénarios d'attaque sont implémentés et testés (scans TCP / XMAS / NULL, brute force SSH, DoS, SQLi, XSS, Path Traversal) avec session authentifiée DVWA. Reste à valider l'exécution complète via Docker et la génération de `data/pentest/pentest_results.json`. |
| **Module d'Analyse des Logs** | 🔄 En cours | Structure de base `analysis/analyze.py` en place ; parsing des alertes NIDS et des logs Metasploitable encore à implémenter. |
| **Moteur NIDS Scapy** | 🔄 En cours | 4 détecteurs sur 7 implémentés et testés : SCAN_PORTS, XMAS_SCAN, NULL_SCAN, BRUTE_FORCE. Restent : DOS, signatures payload (SQLi / XSS / Path Traversal), blocage iptables NIPS et cooldown anti-spam. |

---

## 6. Travail Restant (Suite Séance 2 → Séance 3)

1. **Détecteurs NIDS restants** :
   - Implémentation du détecteur DoS et des signatures de payload (SQLi, XSS, Path Traversal) dans `nids/detectors.py` (Maximilien, Léa).
   - Ajout du cooldown anti-spam entre alertes (Alexis).
2. **Prévention active NIPS** :
   - Implémentation du blocage système iptables dans `_executer_blocage_systeme` (`nids/detectors.py`) et dé-skip des tests `test_nips_prevention.py` (Antoine).
3. **Exécution du Pentest & Récolte des Logs** :
   - Lancement automatisé via `docker compose --profile attaque run --rm pentest` (Antoine).
   - Validation de la génération du fichier `data/pentest/pentest_results.json` (aucun résultat persisté à ce jour).
4. **Analyse des Données Collectées** :
   - Implémentation du parsing et des statistiques dans `analysis/analyze.py` (Léa).
   - Corrélation entre requêtes émises par le pentest et logs enregistrés par la cible.
5. **Validation des Tests Unitaires** :
   - Dé-skip des tests liés aux détecteurs nouvellement implémentés, puis exécution complète de la suite pour préparer le passage à la séance 3.
