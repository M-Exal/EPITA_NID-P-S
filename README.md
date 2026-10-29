# Architecture de Sécurité : NIDS / NIPS & Metasploitable 2 (Honeypot)

Ce projet implémente une solution intégrée de surveillance, détection d'intrusion (**NIDS**), prévention active (**NIPS**), analyse forensique de journaux et pentest automatisé, déployée au moyen de conteneurs Docker.

Dans cette architecture, **Metasploitable 2** est utilisé comme honeypot et cible vulnérable centrale afin d'attirer et d'analyser le trafic hostile en conditions réelles.

---

## 1. Architecture Globale

```
                          ┌────────────────────────────┐
                          │     Module de Pentest      │
                          │   (Attaquant Automatisé)   │
                          │   8 scénarios d'attaque    │
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
│   │  • MySQL, Samba, etc.             │       │  • Quarantaine système (PAM)       │   │
│   └───────────────────────────────────┘       └────────────────────────────────────┘   │
│                     ▲                                                                  │
│                     └────── Pile Réseau Partagée (network_mode: service:...)           ┘
└────────────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
  ┌───────────────────────────────────┐   ┌───────────────────────────────────┐
  │    Alertes & Journalisation       │   │    Analyse Forensique & Logs      │
  │  • nids_alerts.json / log         │   │  • analysis/analyze.py            │
  │  • Chiffrement Fernet (AES/HMAC)  │   │  • auth.log & access.log cibles   │
  │  • Notification par mail (SMTP)   │   │  • Corrélation croisée 3 sources  │
  │  • Bot Discord (Webhook temps réel│   │  • Calcul du taux de détection %  │
  └─────────────────┬─────────────────┘   └─────────────────┬─────────────────┘
                    │                                       │
                    └───────────────────┬───────────────────┘
                                        │ (Volume partagé /app/data)
                                        ▼
                      ┌───────────────────────────────────┐
                      │    Dashboard SIEM (SOC Web)       │
                      │  • Flask + SSE (Temps Réel)       │
                      │  • SOC : http://localhost:5050/   │
                      │  • Attaques : /attaques           │
                      │  • Analyse Forensique : /api/analyse
                      │  • KPI, Matrice Kill-Chain, Live  │
                      └───────────────────────────────────┘
```

### Le Rôle de Metasploitable 2 en tant que Honeypot
Contrairement à des honeypots émulés basiques, **Metasploitable 2** fournit un environnement Linux complet délibérément vulnérable :
* **Services applicatifs réels** : Serveur Web Apache exécutant des applications cibles telles que **DVWA** (*Damn Vulnerable Web Application*) et **Mutillidae**.
* **Services d'authentification et d'accès distant** : Serveur OpenSSH, démon Telnet, serveur FTP (*vsftpd* avec sa porte dérobée historique).
* **Bases de données et partages** : MySQL, PostgreSQL, Samba.

Cette diversité permet de tester une palette réaliste d'attaques réseau et applicatives, sans simulation artificielle, tout en générant de véritables journaux système (`/var/log/auth.log` et `/var/log/apache2/access.log`).

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

## 2. Structure du Dépôt

```
EPITA_NID-P-S/
├── analysis/               # Module d'analyse forensique et corrélation des journaux
│   ├── analyze.py          # Analyseur multi-sources (NIDS, Honeypot, Pentest)
│   └── requirements.txt    # Dépendances bibliothèque standard
├── dashboard/              # Interface Web SIEM et Panneau d'Attaques
│   ├── app.py              # Backend Flask, SSE streaming, endpoints API
│   ├── static/             # Feuilles de style neobrutales, icônes, scripts
│   └── templates/          # Vues HTML (SIEM, Panneau d'attaque, terminal)
├── data/                   # Données persistantes partagées
│   ├── metasploitable/log/ # Journaux synchronisés de la cible (auth.log, access.log)
│   ├── nids/               # Alertes JSON, clés Fernet, rapports chiffrés
│   └── pentest/            # Résultats d'exécution des campagnes d'attaque
├── docs/                   # Comptes-rendus de séances et support de soutenance
│   ├── bilan_seance_1.md
│   ├── bilan_intermediaire_seance_2.md
│   └── support_soutenance.md # Trame et script oral (15 min chrono)
├── mail/                   # Chiffrement et expédition sécurisée de rapports
│   ├── crypto_utils.py     # Chiffrement/déchiffrement Fernet (AES-128 + HMAC)
│   ├── decrypt_report.py   # Utilitaire CLI de déchiffrement
│   └── send_report.py      # Client SMTP avec support TLS
├── nids/                   # Moteur de capture et détection Scapy
│   ├── alerting.py         # Gestionnaire d'alertes JSON et log
│   ├── config.py           # Seuils temporels et signatures d'attaque
│   ├── detectors.py        # 7 détecteurs comportementaux et DPI, module NIPS
│   ├── discord_notifier.py # Intégration Webhook Discord
│   └── nids.py             # Point d'entrée de la sonde Scapy
├── pentest/                # Moteur d'attaque automatisé
│   ├── config.py           # Configuration cibles, ports et pools IP
│   └── pentest.py          # Orchestrateur des 8 scénarios d'attaque
├── scripts/                # Scripts utilitaires et lanceurs unitaires
│   ├── quarantine_agent.sh # Démon de quarantaine PAM sur Metasploitable
│   ├── run_all_attacks.py  # Exécution séquentielle du pentest
│   ├── run_*.py            # Lanceurs unitaires par type d'attaque
│   └── simulate_attacks.py # Simulateur d'alertes pour démonstration
├── tests/                  # Suite de tests unitaires (72 tests pytest)
├── docker-compose.yml      # Orchestration multi-conteneurs
└── README.md
```

---

## 3. Fonctionnement de la Détection (NIDS)

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

1. **Scans Furtifs TCP (Drapeaux Invalides RFC 793)** :
   * **NULL Scan** : Paquet TCP sans aucun drapeau activé (`flags == 0`). Détecté sous l'étiquette `NULL_SCAN`.
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

## 4. Fonctionnement de la Prévention (NIPS) & Quarantaine

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
│                                                              │
│  [ Agent de Quarantaine PAM ]                                │
│    3. Verrouillage système du compte compromis (passwd -l)   │
└──────────────────────────────────────────────────────────────┘
```

1. **Déclenchement** : Dès qu'une menace est qualifiée, le moteur appelle le sous-système de prévention si `NIPS_ENABLED=true`.
2. **Capacités Linux requises** : Le conteneur NIDS dispose des capacités `cap_add: [NET_ADMIN, NET_RAW]`.
3. **Application de la règle** :
   ```bash
   iptables -I INPUT -s <IP_ATTAQUANT> -j DROP
   ```
   L'option `-I INPUT` insère la règle en **toute première position** de la chaîne `INPUT`. Dès lors, le noyau Linux rejette immédiatement (`DROP`) tout paquet provenant de cette IP, sans réponse TCP RST ni ICMP.
4. **Quarantaine Système Dynamique** : En cas de compromission de compte (Brute-Force SSH avéré), l'agent [quarantine_agent.sh](file:///Users/alex/EPITA/ing3/EPITA_NID-P-S/scripts/quarantine_agent.sh) applique un verrouillage immédiat au niveau PAM (`passwd -l`), tuant les sessions actives de l'attaquant.

---

### NIDS (Détection) vs NIPS (Prévention)

| Mode | Variable d'environnement | Comportement | Cas d'usage |
| :--- | :--- | :--- | :--- |
| **NIDS (Démo / Validation)** | `NIPS_ENABLED=false` *(par défaut)* | **Détection pure** : alertes loguées, notifiées sur Discord et affichées sur le SIEM, **sans bloquer l'IP source**. | **Soutenance & Démonstration** : déroule l'intégralité du pentest sans interruption. |
| **NIPS (Production / Mitigation)** | `NIPS_ENABLED=true` | **Prévention active** : blocage immédiat via `iptables DROP` dès le seuil franchi. | **Mitigation opérationnelle** : neutralisation au niveau du noyau Linux. |

---

## 5. Analyse Forensique & Corrélation Multi-Sources

Le module [analysis/analyze.py](file:///Users/alex/EPITA/ing3/EPITA_NID-P-S/analysis/analyze.py) assure la consolidation et la vérification croisée des données recueillies au cours des attaques :

1. **Données du NIDS** : Distribution des alertes par type, sévérité et adresses IP sources (`data/nids/nids_alerts.json`).
2. **Données du Honeypot** : Analyse des connexions SSH échouées/réussies (`auth.log`) et des requêtes HTTP sur DVWA avec empreintes SQLi, XSS et traversées de répertoires (`access.log`).
3. **Données du Pentest** : Répertoire des modules d'attaque exécutés (`data/pentest/pentest_results.json`).
4. **Matrice de Corrélation** : Évalue pour chaque attaque émise si la trace correspondante figure dans les journaux de la cible et si l'alerte attendue a bien été levée par le NIDS, calculant le **taux de détection global** ($100\%$).

### Exécution en Ligne de Commande :
```bash
# Rapport texte synthétique dans la console :
python3 analysis/analyze.py

# Sortie au format JSON :
python3 analysis/analyze.py --json

# Synchronisation directe depuis le conteneur actif :
python3 analysis/analyze.py --sync-docker
```

---

## 6. Chiffrement & Transmission Sécurisée par E-mail

Conformément aux exigences du cahier des charges, les données d'intrusion font l'objet d'un chiffrement robuste avant expédition :
* **Standard Utilisé** : **Fernet** (bibliothèque Python `cryptography`), associant :
  * Chiffrement symétrique **AES-128 en mode CBC**.
  * Signature d'intégrité et d'authenticité **HMAC-SHA256**.
* **Transmission du Rapport** : À l'arrêt du service ou sur demande, la synthèse forensique consolidée est chiffrée (`nids_alerts.enc`) puis transmise par courriel via SMTP sécurisé en TLS.
* **Notifications Discord en Temps Réel** : Transmission instantanée des alertes vers un canal Discord (`DISCORD_WEBHOOK_URL`) avec sévérité et tags d'intrusion.
* **Déchiffrement** : Utilitaire [mail/decrypt_report.py](file:///Users/alex/EPITA/ing3/EPITA_NID-P-S/mail/decrypt_report.py) permettant de restaurer le rapport en clair à l'aide de la clé secrète partagée.

---

## 7. Supervision SIEM (CyBear SIEM)

Le dashboard web de supervision SOC ([dashboard/](file:///Users/alex/EPITA/ing3/EPITA_NID-P-S/dashboard)) offre une vue temps réel sur l'ensemble de l'activité défensive et offensive :
* **URL du SOC** : **`http://localhost:5050`**
* **Flux temps réel** : Streaming via Server-Sent Events (SSE) sans rechargement de page.
* **Composants d'affichage** :
  * Compteurs KPI (Total alertes, adresses IP uniques, alertes critiques).
  * Matrice Kill-Chain croisant adresses IP et vecteurs d'attaque.
  * Flux d'alertes en direct avec horodatage et niveau de criticité.
  * **Modale d'Analyse Forensique** (bouton *Rapport Forensique*) : Affiche les métriques cibles, le taux de détection et permet d'exporter le rapport JSON complet.

### Panneau d'Attaques Web Interactif (`/attaques`)
* **URL** : **`http://localhost:5050/attaques`**
* Déclenchement à la demande des 8 scénarios d'attaque : Scan TCP Connect, Scan XMAS, Scan NULL, Brute-Force SSH, DoS Flood, Injections SQL, XSS et Traversée de répertoire.
* Console terminal sombre intégrée avec retour en streaming direct.

---

## 8. Guide de Démarrage Rapide

### Prérequis
* Docker Engine 20.10+
* Docker Compose v2+
* Python 3.10+ (pour exécution locale des tests)

### A. Configuration (.env)
```bash
cp .env.example .env
```
Renseignez les variables nécessaires (`DISCORD_WEBHOOK_URL`, identifiants SMTP si envoi de mail souhaité).

### B. Lancement de l'Environnement Complet
```bash
# Démarrage des conteneurs en arrière-plan :
docker compose up -d

# Vérification du statut des services :
docker compose ps
```

Accédez aux interfaces :
* **SIEM SOC** : http://localhost:5050/
* **Panneau d'Attaque** : http://localhost:5050/attaques

### C. Lancement du Pentest Automatisé
```bash
# Via le conteneur Docker dédié :
docker compose --profile attaque run --rm pentest

# Ou via les lanceurs unitaires :
python3 scripts/run_scan_ports.py
python3 scripts/run_xmas_scan.py
python3 scripts/run_null_scan.py
python3 scripts/run_brute_force_ssh.py
python3 scripts/run_dos.py
python3 scripts/run_sql_injection.py
python3 scripts/run_xss.py
python3 scripts/run_path_traversal.py
```

### D. Exécution des Tests Unitaires
```bash
# Exécution de la suite complète (72 tests) :
python3 -m pytest -v
```

### E. Préparation de la Soutenance
Consultez le document [docs/support_soutenance.md](file:///Users/alex/EPITA/ing3/EPITA_NID-P-S/docs/support_soutenance.md) pour la trame détaillée de présentation orale de 15 minutes (Slide par slide, timing et script narratif pour l'équipe).
