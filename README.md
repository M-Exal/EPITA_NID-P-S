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
                      │  • Bot Discord (Webhook temps réel)│
                      └─────────────┬─────────────────────┘
                                    │ (Volume partagé /app/data)
                                    ▼
                      ┌───────────────────────────────────┐
                      │    Dashboard SIEM (SOC Web)       │
                      │  • Flask + SSE (Temps Réel)       │
                      │  • SOC : http://localhost:5050/   │
                      │  • Attaques : /attaques           │
                      │  • KPI, Matrice Kill-Chain, Live  │
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

1. **Déclenchement** : Dès qu'une menace est qualifiée (anomalie critique ou signature confirmée), le moteur appelle le sous-système de prévention si `NIPS_ENABLED=true`.
2. **Capacités Linux requises** : Le conteneur NIDS dispose des capacités `cap_add: [NET_ADMIN, NET_RAW]`.
3. **Application de la règle** :
   ```bash
   iptables -I INPUT -s <IP_ATTAQUANT> -j DROP
   ```
   L'option `-I INPUT` insère la règle en **toute première position** de la chaîne `INPUT`. Dès lors, le noyau Linux rejette immédiatement (`DROP`) tout paquet provenant de cette IP, sans réponse TCP RST ni ICMP.
4. **Dé-doublonnage des blocages** : Les adresses IP bloquées sont mémorisées dans un ensemble (`set`) pour éviter l'exécution redondante de commandes système.

---

### NIDS (Détection) vs NIPS (Prévention) : Quand Activer Chaque Mode ?

Le système propose deux modes opératoires selon le contexte :

| Mode | Variable d'environnement | Comportement | Cas d'usage recommandé |
| :--- | :--- | :--- | :--- |
| **NIDS (Démo / Validation)** | `NIPS_ENABLED=false` *(par défaut)* | **Détection pure** : les alertes sont levées, loguées, notifiées sur Discord et affichées sur le SIEM, **sans bloquer l'IP source**. | **Soutenance & Démonstration** : permet de dérouler l'intégralité du pentest d'un seul run sans interruption. |
| **NIPS (Production / Mitigation)** | `NIPS_ENABLED=true` | **Prévention active** : dès la première alerte qualifiée, l'IP source est immédiatement bloquée via `iptables DROP`. | **Environnement de production / Démonstration isolée du blocage** : mitigation immédiate de l'attaquant au niveau noyau. |

> [!WARNING]
> En mode **NIPS actif** (`NIPS_ENABLED=true`), dès que la première attaque du conteneur `pentest` est détectée (ex: `SCAN_PORTS`), son adresse IP est bannie au niveau du noyau. C'est pourquoi le mode démo (`NIPS_ENABLED=false`) est activé par défaut dans `docker-compose.yml`.

#### Activer le Mode Production (NIPS actif) :
```bash
# Via variable en ligne de commande :
NIPS_ENABLED=true docker compose up -d

# Ou en modifiant le fichier .env :
# NIPS_ENABLED=true
```

#### Débloquer Manuellement une IP en Soutenance (sans redémarrer) :
Pour démontrer le blocage puis réautoriser l'IP de test sans redémarrer les conteneurs :
```bash
# 1. Lister les règles de filtrage actives :
docker exec -it metasploitable iptables -L INPUT -n --line-numbers

# 2. Supprimer la règle de blocage pour une IP spécifique :
docker exec -it metasploitable iptables -D INPUT -s <IP_ATTAQUANT> -j DROP

# 3. Ou supprimer la règle par son numéro de ligne (ex: règle n°1) :
docker exec -it metasploitable iptables -D INPUT 1
```
*(Note : le conteneur NIDS et Metasploitable 2 partageant la même pile réseau, la commande peut également s'exécuter via `docker exec -it nids_service iptables ...`).*

---

## 4. Chiffrement & Transmission Sécurisée

Conformément au cahier des charges, les données sensibles recueillies par le NIDS ne doivent pas être transmises en clair :
* **Format des alertes** : Enregistrées localement en format texte structuré (`nids_alerts.log`) et JSON (`nids_alerts.json`).
* **Chiffrement Symétrique Authentifié** : Utilisation du standard **Fernet** (implémentation de la bibliothèque Python `cryptography`), qui combine :
  * Chiffrement symétrique **AES-128 en mode CBC**.
  * Signature d'intégrité et d'authenticité **HMAC-SHA256**.
* **Transmission du Rapport** : À l'arrêt gracieux du service (`SIGTERM`/`SIGINT`), le journal d'alertes est chiffré (`nids_alerts.enc`) puis transmis par e-mail au destinataire désigné via un canal SMTP sécurisé en TLS.
* **Notifications Discord en Temps Réel** : Relais instantané de toute détection vers un channel Discord via Webhook (`DISCORD_WEBHOOK_URL`), avec embeds stylisés par niveau de gravité (`CRITIQUE`, `HAUTE`, `MOYENNE`), tags d'alerte et mention `@here` automatique pour les attaques critiques.
* **Déchiffrement** : L'administrateur déchiffre le rapport à l'aide de l'utilitaire `decrypt_report.py` et de la clé secrète partagée.

---

## 5. Supervision SIEM en Temps Réel (CyBear SIEM)

Un module de supervision web type **SOC / SIEM** est inclus dans le projet (`dashboard/`) :
* **Technologie** : Backend Flask avec flux **SSE (*Server-Sent Events*)** pour la transmission instantanée sans rechargement de page.
* **Interface** : Thème sombre typé cybersécurité, autonome sans dépendance CDN externe.
* **Indicateurs & Visualisations** :
  * **Compteurs KPI** : Total des détections, nombre d'IPs hostiles uniques, alertes critiques, dernière détection horodatée.
  * **Chronologie des Attaques** : Diagramme en barres dynamique par tranche de minute.
  * **Jauge de Sévérité** : Répartition proportionnelle CSS *conic-gradient* (*Critique / Haute / Moyenne*).
  * **Typologie des Attaques Pentest** : Statut d'apparition, volume et pourcentages.
  * **Matrice Kill-Chain** : Corrélation multi-étapes croisant chaque IP source avec les vecteurs d'attaque.
  * **Flux d'Alertes en Direct** : Défilement animé des intrusions au fil de leur détection par Scapy.

L'interface est accessible par défaut sur **`http://localhost:5050`** (port 5050 choisi pour éviter tout conflit avec AirPlay sur macOS).

### Panneau d'Attaques Web Interactif (`/attaques`)

En complément de la supervision passive, une interface offensive dédiée est intégrée au dashboard pour piloter les scénarios de test :
* **Accès** : Bouton **"⚔️ Attaques"** dans le bandeau du SIEM ou directement via **`http://localhost:5050/attaques`**.
* **Cartes interactives disponibles** :
  1. 🔍 **Scan de Ports TCP Connect** (`scan_ports`) — Déclenche `SCAN_PORTS`.
  2. 🎄 **Scan Furtif XMAS** (`xmas_scan`) — Envoi de paquets avec drapeaux FIN, PSH et URG (0x29).
  3. 👻 **Scan Furtif NULL** (`null_scan`) — Envoi de paquets TCP sans drapeaux (flags=0, RFC 793).
  4. 🔑 **Brute-Force SSH** (`brute_force_ssh`) — Tentatives d'authentification SSH répétées.
* **Déclenchement unitaire à la demande** : Bouton **"▶ Lancer"** sur chaque carte pour exécuter le vecteur de scan ou de brute-force.
* **Console d'audit en direct** : Terminal intégré sombre avec autoscroll affichant les sorties des scripts en temps réel et le code de retour final (`✅ Succès` ou code d'erreur).
* **Corrélation immédiate avec le SOC** : Les scans génèrent du trafic hostile inspecté par Scapy ; les alertes correspondantes s'affichent en direct sur le SOC (**`http://localhost:5050/`**) et Discord.

---

## 6. Guide d'Utilisation

### Prérequis
* Docker Engine 20.10+
* Docker Compose v2+

### A. Configuration Préalable (.env)

Copiez le modèle de configuration et renseignez vos variables si souhaité :
```bash
cp .env.example .env
```
Pour activer les alertes Discord, ajoutez simplement l'URL de votre webhook :
```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

### B. Démarrer l'Environnement Complet (Honeypot + NIDS + SIEM Dashboard)

```bash
# Lancement en arrière-plan : Metasploitable 2, NIDS/NIPS et Dashboard SIEM
docker compose up -d
```

Pour reconstruire le Dashboard après modification du code :
```bash
docker compose up -d --build dashboard
```

Pour vérifier que les trois conteneurs sont actifs :
```bash
docker compose ps
```

Ouvrez immédiatement votre navigateur sur le SIEM :
👉 **[http://localhost:5050](http://localhost:5050)**

Pour observer les journaux du NIDS en direct :
```bash
docker compose logs -f nids
```

---

### C. Tester la Supervision en Temps Réel (Simulation Rapide)

Vous pouvez simuler l'injection successive des 7 attaques du pentest pour vérifier l'affichage direct sur le dashboard sans attendre le trafic réseau réel :
```bash
# Exécution du simulateur d'attaques
python3 scripts/simulate_attacks.py
```
Les indicateurs, la matrice et le flux de `http://localhost:5050` se mettront à jour instantanément sous vos yeux.

---

### D. Lancer le Pentest Automatisé (3 Méthodes)

Le pentest exécute les 7 types d'attaques réelles contre la cible Metasploitable 2. Trois méthodes d'exécution sont à votre disposition selon vos besoins :

#### Méthode 1 : Via le Panneau d'Attaques Web (Recommandé pour soutenance)
1. Ouvrez votre navigateur sur **`http://localhost:5050/attaques`** (ou cliquez sur le bouton **"⚔️ Attaques"** depuis le SIEM).
2. Pour tester un vecteur de scan ou d'authentification : cliquez sur **"▶ Lancer"** sur la carte souhaitée (`Scan de Ports TCP`, `Scan Furtif XMAS`, `Scan Furtif NULL`, ou `Brute Force SSH`).
3. Les sorties défilent en streaming direct dans le terminal intégré au fur et à mesure des tentatives, et les alertes NIDS correspondantes apparaissent instantanément sur le tableau de bord SOC (**`http://localhost:5050/`**) et Discord.

#### Méthode 2 : Via les scripts autonomes en CLI (`scripts/run_*.py`)
Chaque attaque dispose d'un script standalone exécutable directement en ligne de commande :
```bash
# Exécution d'une attaque ciblée :
python3 scripts/run_scan_ports.py       # 1. Scan TCP Connect
python3 scripts/run_xmas_scan.py        # 2. Scan TCP XMAS (flags FPU)
python3 scripts/run_null_scan.py        # 3. Scan Furtif TCP NULL (flags 0)
python3 scripts/run_brute_force_ssh.py   # 4. Force Brute SSH (25 paires)
```
*(Note : les scripts détectent automatiquement s'ils s'exécutent sur l'hôte en ciblant `127.0.0.1` avec les ports 2222/8080, ou au sein du conteneur en ciblant `metasploitable`).*

#### Méthode 3 : Via le conteneur Docker dédié
```bash
# Exécution du conteneur d'attaque via son profil dédié
docker compose --profile attaque run --rm pentest
```

---

### E. Analyse et Consolidation des Résultats

Pour générer la synthèse consolidée entre les attaques subies par la cible et les détections du NIDS :
```bash
python3 analysis/analyze.py
```

Pour obtenir la sortie au format JSON :
```bash
python3 analysis/analyze.py --json
```

---

### F. Exécution des Tests Unitaires

Pour valider l'intégrité de l'ensemble des modules (détecteurs, prévention NIPS, gestion des alertes, notification Discord, dashboard SIEM, routes d'attaque, chiffrement, configuration) :
```bash
python3 -m pytest -v
```

---

### G. Développement et Démonstration en Local (hors Docker)

Le projet s'adapte automatiquement à l'environnement hôte (macOS / Linux) sans nécessiter Docker pour le prototypage rapide :
* Détection automatique de l'interface réseau : bascule transparente sur `lo0` (macOS) ou `lo` (Linux).
* Résolution automatique de la cible : repli sur `127.0.0.1` si `metasploitable` n'est pas joignable en DNS.
* Chargement automatique du `.env` en local.

**Pré-requis — création et activation de l'environnement virtuel :**
```bash
# Créer le venv (une seule fois)
python3 -m venv venv

# Activer le venv (à faire dans chaque terminal)
source venv/bin/activate      # Linux / macOS
# .\venv\Scripts\activate     # Windows

# Installer les dépendances
pip install -r dashboard/requirements.txt

# Si les fichiers de données appartiennent à root (créés par Docker) :
sudo chown -R $USER:$USER data/
```

```bash
# 1. Démarrer le moteur NIDS (Scapy nécessite les droits root) :
#    Le venv étant activé, passer le chemin explicite de son python :
sudo venv/bin/python3 nids/nids.py

# 2. Dans un second terminal (venv activé) — Dashboard SIEM + WebSocket :
source venv/bin/activate
python3 dashboard/app.py

# 3. Ouvrir l'interface dans le navigateur :
#    • SOC Temps Réel : http://localhost:5050/
#    • Panneau d'Attaque : http://localhost:5050/attaques

# 4. Lancer une attaque :
#    • Via le bouton "▶ Lancer" ou "🚀 Lancer Toutes les Attaques" dans /attaques
#    • En ligne de commande (depuis la racine du projet) :
python3 scripts/run_brute_force_ssh.py   # Brute force SSH
python3 scripts/run_scan_ports.py        # Scan de ports
python3 scripts/run_xmas_scan.py         # Scan XMAS
python3 scripts/run_null_scan.py         # Scan NULL

# 5. Terminal SSH interactif :
#    Après le Brute Force SSH, les identifiants valides apparaissent dans
#    la section "🔑 Accès validé(s) découvert(s)". Cliquer sur
#    "⚡ Connexion SSH" ouvre un terminal interactif dans une nouvelle fenêtre.
#    → Cliquer dans la zone noire du terminal pour activer la saisie.
```

