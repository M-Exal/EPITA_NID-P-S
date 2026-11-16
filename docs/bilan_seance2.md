## 1. Bilan de la Séance 2

Lors du lancement de la séance 2, le socle de base était posé (Metasploitable 2 sous Docker, dashboard Flask minimaliste et 43 tests actifs sur 51). Durant la séance 2 et ses prolongements immédiats, l'ensemble des briques techniques critiques a été achevé et validé :

### A. Pentest automatisé & éprouvement du honeypot (`pentest.py`)

- **8 scénarios d'attaque complets opérationnels** : scans TCP Connect (avec banner grabbing), scans furtifs illégaux XMAS (`flags=FPU`) et NULL scan (RFC 793), brute-force SSH avec dictionnaire, déni de service volumétrique (DoS Flood), et attaques web ciblées contre DVWA (SQLi, XSS, Path Traversal).
- **Contournement actif du NIPS** : implémentation d'un pool d'adresses IP sources et d'une rotation IP automatique sur timeout (Netlink/ARP) pour simuler un attaquant distribué ou résilient.
- **Terminal interactif post-compromission** : intégration d'un shell SSH Web direct (xterm.js + WebSockets) dès qu'un compte est découvert par brute-force.

### B. Moteur NIDS Scapy complet (`detectors.py`)

- Les 7 familles de détection sont implémentées et actives :
  1. `SCAN_PORTS` (seuil de ports/IP par fenêtre de temps glissante) ;
  2. `XMAS_SCAN` & `NULL_SCAN` (anomalies de drapeaux TCP) ;
  3. `BRUTE_FORCE` (seuil de paquets SYN port 22) ;
  4. `DOS` (inondation volumétrique > 200 paquets/5 s) ;
  5. Signatures applicatives web par inspection profonde de paquets (DPI HTTP) : `SQL_INJECTION`, `XSS` et `PATH_TRAVERSAL`.
- Intégration d'un mécanisme de cooldown anti-spam pour préserver les performances et la lisibilité des alertes.

### C. Prévention active NIPS & quarantaine système (`nids.py`)

- **Blocage réseau dynamique** : règle `iptables -I INPUT -s <IP> -j DROP` dès détection d'une attaque critique (débrayable et administrable depuis le SIEM).
- **Quarantaine système dynamique sur la cible** : verrouillage réel du compte compromis (`passwd -l <user>`) exécuté directement dans le conteneur Metasploitable 2, avec persistance dans `nips_state.json`.

### D. Analyse forensique & corrélation multi-sources (`analyze.py`)

- Corrélation croisée temps réel entre 3 sources de données :
  - alertes du NIDS (`nids_alerts.json`) ;
  - journaux réels de Metasploitable 2 (`/var/log/auth.log` et `/var/log/apache2/access.log`) ;
  - résultats de campagne du pentest (`pentest_results.json`).
- Calcul automatisé du taux de détection, des statistiques d'impact et de l'exposition via l'API SIEM (`/api/analyse`).

### E. Chiffrement & alerting (`mail/`)

- Chiffrement symétrique authentifié Fernet (AES-128-CBC + HMAC-SHA256) des alertes et rapports.
- Script d'envoi par e-mail chiffré (`send_report.py`) conforme au cahier des charges client, doublé d'un bot Discord temps réel.

---

## 2. Point sur l'état du projet (entrée en séance 3)

| Exigence du sujet / Composant     | Statut      | Commentaire                                                          |
| --------------------------------- | ----------- | -------------------------------------------------------------------- |
| Honeypot Dockerisé                | 100% validé | Metasploitable 2 sur réseau privé isolé `honeynet`.                  |
| Script de Pentest Automatisé      | 100% validé | 8 attaques modulaires avec logs détaillés et session DVWA.           |
| Moteur NIDS (Scapy)               | 100% validé | Détection comportementale (volumétrie) et signatures (DPI).          |
| Prévention NIPS (Bonus)           | 100% validé | Filtrage iptables + quarantaine PAM des comptes compromis.           |
| Analyse Forensique & Corrélation  | 100% validé | Corrélation NIDS ↔ Apache ↔ SSH ↔ Pentest.                           |
| Rapport Final Chiffré par Mail    | 100% validé | Chiffrement Fernet + client SMTP TLS prêt à l'emploi.                |
| Dashboard SIEM SOC & Webhook      | 100% validé | Interface web temps réel (SSE), dark mode, panneau `/attaques`.      |
| Qualité de code & Tests           | 72 / 72 OK  | 100% de succès sur pytest, 0 test ignoré (skip).                     |
| Support de Soutenance             | Prêt        | Document complet rédigé dans `support_soutenance.md`.                |

> **Note**
> Le groupe dispose d'une avance technique majeure : toutes les fonctionnalités demandées pour les séances 3 et 4 sont déjà codées, testées et intégrées.

---

## 3. Objectifs et priorités pour la séance 3

Selon le planning officiel (séances 3 et 4 : création et finalisation du projet, rédaction du rapport et préparation de la soutenance), le travail technique étant complété, vous devez concentrer cette séance sur :

1. **Répétition générale du démonstrateur en direct (live demo)** :
   - démarrer la stack : `docker compose up --build` ;
   - exécuter la campagne complète depuis le panneau web (<http://localhost:5050/attaques>) ou en CLI (`docker compose --profile attaque run --rm pentest`) ;
   - valider la réception des alertes SIEM/Discord, la quarantaine NIPS, le calcul de la corrélation forensique et l'envoi du mail chiffré.
2. **Formalisation du rapport écrit / livrable client** :
   - consolider les résultats forensiques obtenus (taux de détection, graphiques d'analyse) dans le livrable écrit final si demandé par le professeur.
3. **Préparation et répétition orale de la soutenance (15 min)** :
   - se caler sur la trame minutée de `support_soutenance.md` ;
   - répartir les interventions entre les 4 membres (Alexis, Maximilien, Antoine, Léa) et chronométrer l'enchaînement des 10 slides prévues.
