# Planning et répartition des tâches

## Groupe

| Membre      | Rôle principal                    | Responsabilités |
|-------------|-----------------------------------|-----------------|
| Maximilien  | Chef de projet / Développeur NIDS | coordination, détection (`detectors.py`), alertes, intégration Docker |
| Antoine     | Développeur Python                | script de pentest automatisé (`pentest.py`), tests unitaires |
| Alexis      | Analyste de données               | récupération et analyse des logs Cowrie (`analyze.py`), graphiques |
| Léa         | Rapport / Soutenance              | documentation, diaporama, vidéo, rapport chiffré (`mail/`) |

Chaque membre participe à l'ensemble des phases (installation, tests,
soutenance), conformément au cahier des charges.

## Outils utilisés

| Catégorie        | Outils |
|------------------|--------|
| IDE / édition    | VS Code, éditeur du choix de chacun |
| Langage          | Python 3.10+ |
| Bibliothèques    | Scapy, paramiko, pandas, matplotlib, cryptography (Fernet), requests/smtplib (stdlib), pytest |
| Conteneurisation | Docker, Docker Compose |
| Honeypot         | Cowrie (logiciel libre) |
| Gestion de projet| tableaux de bord partagés (Trello), dépôt Git GitHub, messagerie du groupe |
| Tests            | pytest (unitaires + intégration) |

## Planning prévisionnel

| Étape | Contenu | Livrable |
|-------|---------|----------|
| **Séance 1** — Lancement | présentation du sujet, constitution du quatuor, répartition des rôles, recherche documentaire (honeypots, NIDS, Scapy), installation de Cowrie, amorçage du script de pentest | compte rendu de séance, choix du honeypot |
| **Séance 2** — Bilan intermédiaire | état d'avancement au **27 novembre** : membres, honeypot retenu, attaques prévues, planning, code initial | PDF de bilan |
| **Séance 3** — Script + analyse | finalisation du pentest automatisé, récupération des données du honeypot, analyse (pandas) et graphiques, début du NIDS (capture Scapy) | script complet + résultats d'analyse |
| **Séance 4** — Finalisation | détection complète (anomalies + signatures), alertes, rapport chiffré par mail, tests et réglage des seuils, début de la soutenance | NIDS fonctionnel + tests verts |
| **15 décembre** — Préparation | travaux prévus pour cette session : intégration Docker complète, campagne de tests, rédaction du rapport, premières diapositives | rapport en cours, diaporama amorcé |
| **Séance 5** — Soutenance | vidéo + présentation orale de 15 min (démarche, étapes, résultats, conclusions), session de questions | vidéo, diaporama, dépôt final |

## Planning réel

| Étape | État | Commentaire |
|-------|------|-------------|
| Choix du honeypot (Cowrie) | Terminé | déployé via Docker Compose, `userdb.txt` d'identifiants faibles |
| Script de pentest automatisé | Terminé | 5 attaques modulisées (1 méthode chacune), gestion d'erreurs complète, résultats JSON |
| Récupération des données | Terminé | `analysis/analyze.py` lit `cowrie.json` (JSON Lines) |
| Analyse + graphiques | Terminé | pandas + matplotlib, rapport texte et 4 graphiques |
| NIDS : capture | Terminé | Scapy, partage de pile réseau du honeypot, sauvegarde pcap |
| NIDS : détection | Terminé | anomalies (scan, DoS, brute-force) + signatures (SQLi, XSS, traversal, flags) |
| NIDS : alertes + mail chiffré | Terminé | journaux .log/.json, chiffrement Fernet, SMTP |
| Tests | Terminé | 45 tests pytest, dont scénarios « trafic normal sans alerte » |
| Documentation | Terminé | README, architecture, guide d'utilisation |
| Vidéo et diaporama de soutenance | À faire | dernière séance |
| Réglage fin des seuils sur trafic réel | À faire | après campagne d'attaques complète |

## Travaux prévus pour la session du 15 décembre

1. Lancer `./scripts/demo.sh` de bout en bout et consigner les résultats
   (alertes NIDS, logs Cowrie, graphiques) pour le rapport.
2. Ajuster les seuils du NIDS en fonction des logs réels et rejouer les
   tests (`pytest tests -q`) pour confirmer l'absence de fausses alertes.
3. Rédiger le rapport : architecture, démonstration, analyse des données,
   résultats et conclusion.
4. Préparer le diaporama de soutenance (introduction, honeypot, script de
   pentest, méthodologie de récupération, analyse, NIDS, conclusions) et
   caler la répartition de la parole entre les quatre membres.
