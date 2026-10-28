# 🛡️ Bilan — Séance 1

**EPITA — Majeure Sécurité (ING3)** — *Groupe : CyBears*
**Projet : Honeypot & Système de Détection / Prévention d'Intrusion (NIDS / NIPS)**

**Équipe :** Alexis Blanc-Feuillet, Maximilien Brunet, Antoine Goetschy, Léa Bonet.

**Honeypot retenu :** Metasploitable 2 (conteneur Docker `tleemcjr/metasploitable2:latest`), hébergeant DVWA et Mutillidae, auquel le NIDS est couplé via le partage de pile réseau (`network_mode: service:metasploitable`).

**Réalisé lors de cette séance :** mise en place de l'environnement Docker multi-services (Metasploitable 2 + NIDS sur le réseau `honeynet`), du dashboard SIEM temps réel (*CyBear SIEM*, Flask/SSE sur `http://localhost:5050`), des alertes instantanées via webhook Discord, du chiffrement Fernet des journaux (AES-128 + HMAC-SHA256) et du pipeline CI/CD GitHub Actions avec les premiers tests unitaires.
