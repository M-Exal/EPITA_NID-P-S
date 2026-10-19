# Guide d'utilisation

## Pré-requis

- Docker ≥ 24 et Docker Compose v2 ;
- Python 3.10+ (pour les tests et l'analyse exécutés hors conteneur) ;
- (optionnel) un compte SMTP pour recevoir le rapport chiffré.

## 1. Installation

```bash
git clone git@github.com:M-Exal/EPITA_NID-P-S.git
cd EPITA_NID-P-S
cp .env.example .env          # puis renseigner si vous voulez le courriel
```

Les images des services `nids`, `pentest` et `analysis` sont construites à la
première exécution (`--build`). Le honeypot utilise l'image publique
`cowrie/cowrie`.

## 2. Démonstration complète

```bash
./scripts/demo.sh --sans-mail
```

Le script enchaîne : démarrage honeypot + NIDS → pentest → arrêt du NIDS
(rapport) → analyse → affichage des résultats. Chaque étape est commutable :

```bash
./scripts/demo.sh            # avec envoi du courriel (fichier .env requis)
./scripts/demo.sh --arret    # reprend à l'étape « arrêt du NIDS »
./scripts/clean.sh           # nettoyage (conteneurs + data/)
./scripts/clean.sh --images  # nettoyage approfondi
```

### Équivalent manuel

```bash
docker compose up -d --build honeypot nids
sleep 15
docker compose run --rm pentest              # toutes les attaques
docker compose run --rm pentest --scan      # une attaque précise
docker compose stop nids                     # résumé + rapport chiffré
docker compose run --rm analysis             # graphiques + rapport
docker compose down --remove-orphans
```

### Honeypot : vérifier que tout fonctionne

```bash
docker compose ps
docker logs -f cowrie_honeypot
# depuis l'hôte (ports exposés) :
ssh -p 2222 user@127.0.0.1        # faux shell SSH
telnet 127.0.0.1 2223             # faux shell Telnet
```

Les tentatives apparaissent immédiatement dans
`data/cowrie/log/cowrie.json` (un objet JSON par ligne).

## 3. Pentest automatisé

```bash
docker compose run --rm pentest --help
docker compose run --rm pentest --all
docker compose run --rm pentest --scan --bruteforce
docker compose run --rm pentest --target 192.168.1.10 --ssh-port 2222 --dos
```

Résultats : `data/pentest/pentest_results.json`.

Exécution directe sur la machine hôte (contre le honeypot exposé en 2222) :

```bash
python3 pentest/pentest.py --target 127.0.0.1 --ssh-port 2222 --scan
```

> À n'utiliser que contre votre propre honeypot, en environnement de labo.

## 4. NIDS

```bash
# dans Docker (recommandé : capteur collé au honeypot)
docker compose up -d --build nids
docker compose stop nids          # résumé + capture.pcap + rapport chiffré

# sur la machine hôte (nécessite sudo pour la capture)
sudo python3 nids/nids.py --iface eth0 --duree 120 --no-mail

# analyse hors-ligne d'une capture
python3 nids/nids.py --pcap data/nids/capture.pcap --no-mail
```

Sorties dans `data/nids/` :

- `nids_alerts.log` — journal texte des alertes ;
- `nids_alerts.json` — alertes structurées (une ligne par alerte) ;
- `capture.pcap` — capture complète rejouable avec `--pcap`.

### Réglage des seuils

Éditez `.env` (ou l'environnement du service `nids` dans
`docker-compose.yml`) puis relancez `docker compose up -d nids` :

| Variable               | Signification                              | Défaut |
|------------------------|--------------------------------------------|--------|
| `NIDS_SCAN_THRESHOLD`  | ports distincts avant alerte SCAN_PORTS    | 15     |
| `NIDS_SCAN_WINDOW`     | fenêtre du scan (secondes)                 | 10     |
| `NIDS_DOS_THRESHOLD`   | paquets/IP avant alerte DOS                | 200    |
| `NIDS_DOS_WINDOW`      | fenêtre du DoS (secondes)                  | 5      |
| `NIDS_BRUTE_THRESHOLD` | SYN vers SSH/Telnet avant BRUTE_FORCE      | 10     |
| `NIDS_BRUTE_WINDOW`    | fenêtre du brute-force (secondes)          | 30     |
| `NIDS_ALERT_COOLDOWN`  | délai minimal entre 2 alertes identiques   | 30     |

## 5. Analyse des données du honeypot

```bash
docker compose run --rm analysis
# ou, avec pandas/matplotlib installés :
python3 analysis/analyze.py --log data/cowrie/log/cowrie.json --out data/analysis
```

Produits : `rapport_analyse.txt` + graphiques PNG (`top_ip.png`,
`top_usernames.png`, `top_passwords.png`, `types_evenements.png`).

## 6. Rapport chiffré par courriel

Le rapport d'alertes est chiffré (Fernet) avant l'envoi SMTP.

1. **Gmail** : activer la validation en 2 étapes, puis créer un
   *mot de passe d'application* (myaccount.google.com/apppasswords).
   **Outlook / Office 365** : l'authentification basique étant désactivée,
   utiliser un mot de passe d'application ou OAuth2.
2. Renseigner `SMTP_USER`, `SMTP_PASSWORD`, `REPORT_RECEIVER` (et
   `NIDS_FERNET_KEY` si vous partagez une clé) dans `.env`.
3. Lancer la démonstration : l'envoi a lieu à l'arrêt du NIDS.
4. Envoi manuel d'un autre fichier :

```bash
python3 mail/send_report.py data/analysis/rapport_analyse.txt
```

### Déchiffrement côté destinataire

```bash
NIDS_FERNET_KEY="<clé partagée>" python3 mail/decrypt_report.py rapport.enc
```

Sans variable d'environnement, la clé est lue dans `secret.key` du dossier
courant (générée automatiquement à la première utilisation).

## 7. Tests

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r tests/requirements-dev.txt
.venv/bin/python -m pytest tests -q
```

Les tests n'ont besoin d'aucun service : le pentest vise 127.0.0.1, le NIDS
est exercé via des paquets rejoués depuis un pcap généré.
