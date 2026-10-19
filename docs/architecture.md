# Architecture du système

## Vue d'ensemble

```
                 même réseau Docker (honeynet)
   ┌──────────────────────────────────────────────────────────────┐
   │                                                              │
   │   ┌─────────────┐   attaques    ┌──────────────┐             │
   │   │  pentest    │ ────────────▶ │   honeypot   │             │
   │   │  (conteneur │               │   (Cowrie)   │             │
   │   │  d'attaque) │               │  SSH 2222    │             │
   │   └─────────────┘               │  Telnet 2223 │             │
   │                                 └──────┬───────┘             │
   │                                        │ pile réseau         │
   │                                        │ partagée            │
   │                                 ┌──────▼───────┐             │
   │                                 │     nids     │             │
   │                                 │   (Scapy)    │             │
   │                                 └──────────────┘             │
   └──────────────────────────────────────────────────────────────┘

   data/cowrie/log/cowrie.json ──▶ analysis (pandas) ──▶ graphiques + rapport
   data/nids/nids_alerts.log   ──▶ chiffrement Fernet ──▶ courriel SMTP
```

## Composants

### 1. Honeypot — Cowrie (`honeypot/`, service `honeypot`)

Honeypot logiciel à faible/moyenne interaction simulant un serveur SSH et
Telnet. Toute tentative d'intrusion (connexions, identifiants testés,
commandes tapées dans le faux shell) est journalisée au format JSON dans
`data/cowrie/log/cowrie.json`.

- `honeypot/userdb.txt` : identifiants volontairement faibles acceptés, afin
  que le brute-force du script de pentest « réussisse » parfois et fasse
  exécuter des commandes à l'attaquant (données précieuses pour l'analyse).

### 2. Script de pentest automatisé (`pentest/`, service `pentest`)

Classe `Pentester` : **une méthode par type d'attaque**, gestion complète des
exceptions (une attaque qui échoue n'interrompt jamais les suivantes) et
sauvegarde des résultats dans `data/pentest/pentest_results.json`.

| Méthode            | Attaque simulée                       | Outil / librairie |
|--------------------|---------------------------------------|-------------------|
| `scan_ports`       | scan de ports TCP                     | nmap (repli socket) |
| `syn_scan`         | scan SYN furtif (half-open)           | Scapy             |
| `brute_force_ssh`  | attaque par dictionnaire sur SSH      | paramiko          |
| `dos_attack`       | inondation de connexions (volume contrôlé) | socket        |
| `sql_injection`    | payloads SQLi (éprouve le NIDS)       | socket            |

### 3. NIDS (`nids/`, service `nids`)

| Fichier          | Rôle |
|------------------|------|
| `nids.py`        | orchestration : capture → analyse → alerte → rapport |
| `detectors.py`   | moteur de détection (fenêtres glissantes + signatures) |
| `alerting.py`    | journal d'alertes (.log + .json) et envoi du rapport chiffré |
| `crypto_utils.py`| chiffrement Fernet du rapport |
| `config.py`      | seuils et paramètres (surchargeables par variables d'environnement) |

Deux familles de détection, combinées :

1. **Détection d'anomalies** (seuils statistiques sur fenêtres glissantes) :
   - `SCAN_PORTS` : > 15 ports *différents* contactés en 10 s ;
   - `DOS` : > 200 paquets reçus d'une même IP en 5 s ;
   - `BRUTE_FORCE` : > 10 SYN vers les ports SSH/Telnet en 30 s.
2. **Détection de signatures** (motifs dans la charge utile) :
   - `SQL_INJECTION`, `XSS`, `PATH_TRAVERSAL` : motifs SQL/XSS/traversal ;
   - `NULL_SCAN`, `XMAS_SCAN` : drapeaux TCP illégaux.

Points clés :

- **Fenêtres glissantes** : les compteurs sont purgés à chaque paquet ; un
  pic ancien ne déclenche plus d'alerte (pas de cumul artificiel).
- **Anti-spam** : une même alerte `(IP, type)` n'est pas refaite pendant 30 s.
- **Tolérance aux pannes** : un paquet malformé est ignoré, il n'arrête jamais
  le capteur.
- Le NIDS tourne avec `network_mode: service:honeypot` : il sniffe
  **exactement** le trafic destiné au honeypot, sur son interface `eth0`.

### 4. Analyse des données (`analysis/`, service `analysis`)

`analyze.py` lit le journal JSON Lines de Cowrie, le charge dans un
**DataFrame pandas**, calcule les statistiques (IP les plus actives,
identifiants testés, commandes exécutées, taux de succès du brute-force) et
produit des graphiques PNG + un rapport texte dans `data/analysis/`.

### 5. Rapport chiffré (`mail/`, module `alerting.py`)

Le rapport d'alertes est chiffré avec **Fernet** (AES-128-CBC + HMAC :
confidentialité **et** intégrité) puis envoyé en pièce jointe via SMTP.
Le destinataire le déchiffre avec `mail/decrypt_report.py` et la clé partagée.

## Réponses aux questions du cahier des charges

### Quelle est l'utilité réelle d'un honeypot et d'un NIDS ?

- **Honeypot** : appâte les attaquants, concentre et journalise leurs
  techniques (identifiants, outils, commandes) sur un système volontairement
  exposé. C'est une sonde de renseignement : aucun trafic légitime ne devrait
  l'atteindre, donc tout ce qui s'y passe est suspect par construction.
- **NIDS** : surveille le trafic réel du réseau en temps réel, détecte les
  scans, les inondations et les charges utiles malveillantes, et alerte
  l'opérateur. Le honeypot fournit des données passées ; le NIDS agit en
  présent.

Les deux se complètent : les attaques observées par le honeypot alimentent
les signatures et les seuils du NIDS (boucle : pentest → logs → analyse →
règles du NIDS → validation par les tests).

### Où déployer ces éléments en entreprise ?

- **Honeypot** : dans une *DMZ*, derrière le pare-feu périmétrique, exposé
  publiquement — il ne doit jamais être accessible depuis le réseau interne
  (ségrégation stricte). Il ne sert à rien derrière un pare-feu qui bloquerait
  tout le trafic entrant.
- **NIDS** : à l'**emplacement stratégique de contrôle du trafic** qu'on veut
  observer — jonction Internet/DMZ et/ou jonction LAN/LAN-verseur (SPAN/TAP).
  Dans notre labo, il partage la pile réseau du honeypot : équivalent d'un
  capteur branché sur le même lien que la cible protégée.

### Quelle architecture pour reproduire des conditions réelles ?

Trois conteneurs sur un même réseau Docker (`honeynet`) :

1. `honeypot` (cible) avec ses ports exposés ;
2. `nids` collé à la pile réseau du honeypot (position de capteur) ;
3. `pentest` (attaquant) sur le même réseau, qui attaque sous un nom de
   service — il joue le rôle de l'attaquant externe.

C'est la topologie labo qui reproduit le schéma « attaque → cible → capteur
sur le même lien » : tout paquet échangé avec le honeypot est visible par le
NIDS, sans capture sur la pile réseau de l'hôte et sans perturber le trafic des autres
conteneurs.

### Comment valider l'absence de fausses alertes ?

Trois niveaux, tous automatisés (`tests/`) :

1. **Trafic bénin simulé** (`test_trafic_normal_sans_alerte`,
   `test_trafic_normal_aucune_alerte`) : poignées de main TCP, requêtes HTTP
   classiques, DNS, ping → **zéro alerte** attendue.
2. **Scénarios d'attaque rejoués** (`test_flux_attaques_detecte`) : un pcap
   contenant scan, DoS, brute-force et SQLi doit produire exactement ces
   quatre types d'alertes.
3. **Ajustement des seuils** : les seuils sont des variables d'environnement
   (`NIDS_SCAN_THRESHOLD`, `NIDS_DOS_THRESHOLD`, `NIDS_BRUTE_THRESHOLD`) ;
   on les ajuste après chaque campagne de tests sans reconstruire l'image,
   en s'appuyant sur les logs réels du honeypot.

En complément, les fenêtres glissantes et le cooldown anti-spam évitent les
alertes répétées ou issues d'évènements anciens.
