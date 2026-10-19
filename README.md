# Projet Sécurité — Honeypot, Pentest automatisé et NIDS

Système intégrant un **honeypot** (Cowrie), un **script de pentest automatisé**
(Python) et un **NIDS** (Network Intrusion Detection System) développé en
Python avec Scapy. L'ensemble tourne sous **Docker**.

Le pentest attaque le honeypot, le honeypot journalise les attaques, le NIDS
capture le trafic et alerte sur les menaces détectées ; le rapport final est
envoyé par courriel **chiffré** (Fernet).

## Architecture

| Service    | Rôle                                                        | Image / Techno                     |
|------------|-------------------------------------------------------------|------------------------------------|
| `honeypot` | Honeypot SSH/Telnet, journalise tout (JSON)                 | `cowrie/cowrie`                    |
| `nids`     | Capture du trafic (Scapy) + détection + alertes + rapport   | `python:3.12-slim` (Dockerfile)    |
| `pentest`  | Conteneur d'attaque : scan, brute-force, DoS, SQLi          | `python:3.12-slim` (Dockerfile)    |
| `analysis` | Analyse des logs Cowrie : pandas + graphiques matplotlib    | `python:3.12-slim` (Dockerfile)    |

Le NIDS partage la pile réseau du honeypot (`network_mode: service:honeypot`) :
il voit exactement le trafic qui lui est destiné, sans passer par la pile
réseau de l'hôte.

Détails complets : [docs/architecture.md](docs/architecture.md).

## Démarrage rapide

Pré-requis : Docker + Docker Compose.

```bash
# 1. (optionnel) configuration de l'envoi du rapport chiffré
cp .env.example .env          # puis renseigner SMTP_* si souhaité

# 2. démonstration complète : honeypot + NIDS + pentest + analyse
./scripts/demo.sh --sans-mail # sans envoi de courriel

# ou étape par étape
docker compose up -d --build honeypot nids
sleep 15
docker compose run --rm pentest      # toutes les attaques
docker compose stop nids             # résumé + rapport chiffré
docker compose run --rm analysis     # graphiques + rapport d'analyse
```

Résultats produits :

```
data/cowrie/log/cowrie.json        # attaques reçues par le honeypot
data/pentest/pentest_results.json  # résultats du pentest automatisé
data/nids/nids_alerts.log|.json    # alertes du NIDS
data/nids/capture.pcap             # capture réseau complète
data/analysis/                     # graphiques PNG + rapport_analyse.txt
```

Arrêt et nettoyage : `./scripts/clean.sh` (ajoutez `--images` pour les images).

## Tests

45 tests unitaires et d'intégration couvrent le NIDS, le pentest, l'analyse
et le chiffrement, dont un scénario « trafic normal sans fausse alerte ».

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r tests/requirements-dev.txt
.venv/bin/python -m pytest tests -q
```

## Structure du dépôt

```
├── docker-compose.yml    # orchestration des 4 services
├── honeypot/             # userdb.txt : identifiants faibles acceptés
├── pentest/              # pentest.py : attaques modulaires (1 méthode / attaque)
├── nids/                 # capture (nids.py), détection (detectors.py),
│                         # alertes (alerting.py), chiffrement (crypto_utils.py)
├── analysis/             # récupération + analyse des logs Cowrie
├── mail/                 # envoi / déchiffrement du rapport chiffré
├── scripts/              # demo.sh (démonstration), clean.sh (nettoyage)
├── tests/                # pytest : unitaires + intégration
├── data/                 # volumes : logs, alertes, analyses (non versionnés)
└── docs/                 # architecture, guide d'utilisation, planning
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — composants, flux, choix de déploiement
- [docs/utilisation.md](docs/utilisation.md) — guide pas à pas (démonstration, courriel chiffré, réglages)
- [docs/planning.md](docs/planning.md) — répartition des rôles et planning du projet
