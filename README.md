# Architecture de Sécurité : NIDS / NIPS & Metasploitable 2 (Honeypot)

Ce projet implémente une solution intégrée de surveillance, détection d'intrusion (**NIDS**), prévention active (**NIPS**) et pentest automatisé, déployée au moyen de conteneurs Docker.

Dans cette architecture, **Metasploitable 2** est utilisé comme honeypot / cible vulnérable centrale afin d'attirer et d'analyser le trafic hostile en conditions réelles.

---

## 1. Architecture Globale

```
                          ┌────────────────────────────┐
                          │     Module de Pentest      │
                          │   (Attaquant Automatisé)   │
                          └─────────────┬──────────────┘
                                        │ (Trafic d'attaque)
                                        ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Réseau Privé Docker (Bridge : honeynet)                                                │
│                                                                                        │
│   ┌───────────────────────────────────┐       ┌────────────────────────────────────┐   │
│   │   HONEYPOT : Metasploitable 2     │       │   NIDS / NIPS (Scapy + iptables)   │   │
│   │                                   │       │                                    │   │
│   │  • HTTP / DVWA (Port 80)          │       │  • Sniffing passif sur eth0        │   │
│   │  • SSH (Port 22)                  │◄═════►│  • Analyse comportementale         │   │
│   │  • Telnet (Port 23)               │       │  • Détection de signatures         │   │
│   │  • FTP vsftpd (Port 21)           │       │  • Blocage actif (iptables DROP)   │   │
│   │  • MySQL, Samba, etc.             │       │                                    │   │
│   └───────────────────────────────────┘       └────────────────────────────────────┘   │
│                     ▲                                                                  │
│                     └────── Pile Réseau Partagée (network_mode: service:...)           ┘
└────────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                      ┌───────────────────────────────────┐
                      │    Alertes & Journalisation       │
                      │  • nids_alerts.json / log         │
                      │  • Chiffrement Fernet (AES/HMAC)  │
                      │  • Notification par mail (SMTP)   │
                      └───────────────────────────────────┘
```

### Le Rôle de Metasploitable 2 en tant que Honeypot
Contrairement à des honeypots émulés basiques, **Metasploitable 2** fournit un environnement Linux complet délibérément vulnérable :
* **Services applicatifs réels** : Serveur Web Apache exécutant des applications cibles telles que **DVWA** (*Damn Vulnerable Web Application*) et **Mutillidae**.
* **Services d'authentification et d'accès distant** : Serveur OpenSSH, démon Telnet, serveur FTP (*vsftpd* avec sa fameuse backdoor historique).
* **Bases de données et partages** : MySQL, PostgreSQL, Samba.

Cette diversité permet de tester une palette réaliste d'attaques réseau et applicatives, sans simulation artificielle.

### Le Couplage Réseau NIDS ↔ Honeypot
Le conteneur NIDS s'attache à la cible via la directive :
```yaml
network_mode: "service:metasploitable"
```
Cette configuration place le NIDS dans le **même espace de noms réseau (network namespace)** que le conteneur Metasploitable 2 :
* Le NIDS partage l'adresse IP et l'interface réseau (`eth0`) de la cible.
* Tous les paquets entrants et sortants de Metasploitable 2 traversent l'interface observée par le NIDS.
* Les règles de filtrage (`iptables`) appliquées par le NIPS impactent immédiatement le trafic dirigé vers Metasploitable 2.

---

## 2. Fonctionnement de la Détection (NIDS)

Le NIDS capture le trafic réseau en temps réel via la bibliothèque **Scapy** (`sniff()`) et combine deux paradigmes d'analyse complémentaires :

### A. Détection Comportementale (Anomalies Statistiques)

La détection comportementale repose sur des structures de files d'attente à fenêtre glissante (`collections.deque`). À chaque paquet entrant, les événements hors fenêtre temporelle sont purgés afin d'évaluer la fréquence d'une activité sur un intervalle $T$ donné.

1. **Scan de ports TCP (Reconnaissance)** :
   * **Principe** : L'attaquant envoie des paquets TCP (SYN ou Connect) sur une multitude de ports distincts pour cartographier les services actifs.
   * **Règle de détection** : Une alerte `SCAN_PORTS` est émise si une même adresse IP source contacte plus de $N$ ports distincts (seuil par défaut : 15 ports) au cours d'une fenêtre de $T$ secondes (ex : 10 secondes).
   
2. **Déni de Service (DoS Flood)** :
   * **Principe** : L'attaquant cherche à saturer la bande passante ou la pile TCP de la cible en envoyant un volume massif de requêtes dans un temps restreint.
   * **Règle de détection** : Une alerte `DOS` est déclenchée si le nombre total de paquets émis par une même IP dépasse le seuil configuré (ex : 200 paquets en moins de 5 secondes).

3. **Attaque par Force Brute (Authentification)** :
   * **Principe** : L'attaquant tente de deviner les identifiants en effectuant des connexions répétées sur des services d'authentification (SSH sur port 22, Telnet sur port 23, FTP sur port 21).
   * **Règle de détection** : Une alerte `BRUTE_FORCE` est levée lors de l'observation d'un volume excessif de paquets d'initialisation TCP (`flags == 'S'`) ciblant les ports d'administration surveillés dans un intervalle court.

---

### B. Détection par Signatures (Inspection Profonde des Paquets / DPI)

La détection par signatures inspecte la structure des en-têtes et le contenu de la charge utile (`Raw payload`) des paquets à la recherche de motifs révélateurs d'une attaque.

1. **Scans Furtifs TCP (Drapeaux Invalides)** :
   * **NULL Scan** : Paquet TCP sans aucun drapeau activé (`flags == 0`). Ce paquet enfreint la RFC 793 et sert à contourner certains pare-feux non avec état. Détecté sous l'étiquette `NULL_SCAN`.
   * **XMAS Scan** : Paquet TCP arborant les drapeaux FIN, PSH et URG simultanément (`flags == 0x29`). Détecté sous l'étiquette `XMAS_SCAN`.

2. **Injections SQL (SQLi)** :
   * Le NIDS inspecte les charges utiles HTTP transitant vers le port 80.
   * Recherche de motifs SQL classiques : `UNION SELECT`, `' OR '1'='1`, `DROP TABLE`, `1=1--`, etc.
   * Déclenché sous l'étiquette `SQL_INJECTION`.

3. **Cross-Site Scripting (XSS)** :
   * Recherche de signatures de scripts dans les requêtes Web : `<script>`, `javascript:`, `onerror=`, `onload=`, `<img src=`, etc.
   * Déclenché sous l'étiquette `XSS`.

4. **Traversée de Répertoire (Path Traversal / LFI)** :
   * Détection de tentatives d'accès aux fichiers sensibles du système sous-jacent : `../`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`.
   * Déclenché sous l'étiquette `PATH_TRAVERSAL`.

---

### C. Mécanisme Anti-Spam (Cooldown)

Pour éviter la saturation des journaux d'alertes lorsqu'un attaquant transmet des milliers de requêtes malveillantes par seconde :
* Un cache en mémoire associe la paire `(IP_SOURCE, TYPE_ATTAQUE)` à son dernier horodatage d'alerte.
* Une temporisation minimale (*cooldown*, par défaut 30 secondes) est exigée avant de réémettre une alerte identique pour la même source.

---

## 3. Fonctionnement de la Prévention (NIPS)

Le passage du mode détection passive (**NIDS**) au mode prévention active (**NIPS**) confère au système la capacité d'interrompre l'attaque en cours d'exécution.

```
       [ Attaquant : 172.18.0.5 ]
                   │
                   │  1. Envoi de paquets malveillants
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Pile Réseau (eth0)                                          │
│                                                              │
│  [ Scapy ] ──► Analyse paquet ──► [ Alerte Déclenchée ]     │
│                                           │                  │
│                                           ▼                  │
│  [ Netfilter / iptables ] ◄── Exécute blocage système        │
│    Règle : "iptables -I INPUT -s 172.18.0.5 -j DROP"         │
│                                                              │
│  [ Cible Metasploitable 2 ]                                  │
│    2. Tout paquet ultérieur de 172.18.0.5 est jeté au        │
│       niveau noyau Linux avant d'atteindre les démons.       │
└──────────────────────────────────────────────────────────────┘
```

### Le Processus de Neutralisation

1. **Déclenchement** : Dès qu'une menace est qualifiée (anomalie critique ou signature confirmée), le moteur appelle le sous-système de prévention.
2. **Capacités Linux requises** : Le conteneur NIDS dispose des capacités `cap_add: [NET_ADMIN, NET_RAW]`.
3. **Application de la règle** :
   ```bash
   iptables -I INPUT -s <IP_ATTAQUANT> -j DROP
   ```
   L'option `-I INPUT` insère la règle en **toute première position** de la chaîne `INPUT`. Dès lors, le noyau Linux rejette immédiatement (`DROP`) tout paquet provenant de cette IP, sans réponse TCP RST ni ICMP.
4. **Dé-doublonnage des blocages** : Les adresses IP bloquées sont mémorisées dans un ensemble (`set`) pour éviter l'exécution redondante de commandes système.

---

## 4. Chiffrement & Transmission Sécurisée

Conformément au cahier des charges, les données sensibles recueillies par le NIDS ne doivent pas être transmises en clair :
* **Format des alertes** : Enregistrées localement en format texte structuré (`nids_alerts.log`) et JSON (`nids_alerts.json`).
* **Chiffrement Symétrique Authentifié** : Utilisation du standard **Fernet** (implémentation de la bibliothèque Python `cryptography`), qui combine :
  * Chiffrement symétrique **AES-128 en mode CBC**.
  * Signature d'intégrité et d'authenticité **HMAC-SHA256**.
* **Transmission du Rapport** : À l'arrêt gracieux du service (`SIGTERM`/`SIGINT`), le journal d'alertes est chiffré (`nids_alerts.enc`) puis transmis par e-mail au destinataire désigné via un canal SMTP sécurisé en TLS.
* **Déchiffrement** : L'administrateur déchiffre le rapport à l'aide de l'utilitaire `decrypt_report.py` et de la clé secrète partagée.

---

## 5. Guide d'Utilisation

### Prérequis
* Docker Engine 20.10+
* Docker Compose v2+

### A. Démarrer l'Environnement (Honeypot + NIDS)

```bash
# Lancement en tâche de fond de Metasploitable 2 et du service NIDS/NIPS
docker-compose up -d
```

Pour vérifier que les conteneurs sont actifs :
```bash
docker-compose ps
```

Pour observer la capture et les alertes du NIDS en direct :
```bash
docker-compose logs -f nids
```

---

### B. Lancer le Pentest Automatisé

Le pentest exécute les 7 types d'attaques contre Metasploitable 2 :
```bash
# Exécution du conteneur d'attaque via son profil dédié
docker-compose --profile attaque run --rm pentest
```

Le script exécute successivement :
1. Un scan de ports TCP Connect sur les services connus de Metasploitable.
2. Un scan furtif XMAS (drapeaux FIN+PSH+URG).
3. Une tentative de force brute SSH (avec les identifiants typiques de Metasploitable 2).
4. Une attaque par déni de service (inondation de connexions rapides).
5. Des injections SQL dirigées vers DVWA (port 80).
6. Des charges utiles XSS dirigées vers DVWA.
7. Des tentatives de Path Traversal ciblant `/etc/passwd`.

---

### C. Analyse et Consolidation des Résultats

Pour générer la synthèse consolidée entre les attaques subies par la cible et les détections du NIDS :
```bash
python3 analysis/analyze.py
```

Pour obtenir la sortie au format JSON :
```bash
python3 analysis/analyze.py --json
```

---

### D. Exécution des Tests Unitaires

Pour valider l'intégrité de l'ensemble des modules (détecteurs, prévention NIPS, gestion des alertes, chiffrement, configuration) :
```bash
pytest -v
```
