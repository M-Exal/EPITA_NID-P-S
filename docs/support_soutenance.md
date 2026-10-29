# Support & Trame de Soutenance Orale (15 minutes)

**EPITA — Majeure Sécurité (ING3)**  
**Projet : Honeypot, Automatisation de Pentest & NIDS / NIPS en Python**  
**Équipe : CyBears** (Alexis Blanc-Feuillet, Maximilien Brunet, Antoine Goetschy, Léa Bonet)  
**Format :** Présentation "client" de 15 minutes + session de questions (Séance 5).

---

## Grille de Répartition du Temps & des Rôles (15 min chrono)

| Slide | Titre & Thématique | Intervenant Principal | Durée Estimée |
| :---: | :--- | :--- | :---: |
| **01** | Introduction & Problématique Métier / Client | **Alexis** (Lead Tech) | 1 min 30 |
| **02** | Choix & Justification du Honeypot (Metasploitable 2) | **Léa** (Pentest Web & Data) | 1 min 30 |
| **03** | Architecture Système & Réseau Conteneurisé (Docker) | **Antoine** (DevOps & Infra) | 1 min 30 |
| **04** | Pentest Automatisé : Conception & Scénarios d'Attaque | **Maximilien** (Pentest Réseau) | 2 min 00 |
| **05** | Méthodologie de Collecte & Rapatriement des Données | **Léa** | 1 min 30 |
| **06** | Analyse Forensique des Journaux & Corrélation Croisée | **Léa** | 2 min 00 |
| **07** | Moteur NIDS Scapy : Capture Temps Réel & Algorithmes | **Alexis** | 2 min 00 |
| **08** | Prévention Active NIPS & Quarantaine Système Dynamique | **Antoine** | 1 min 30 |
| **09** | Supervision SIEM Temps Réel & Rapport Chiffré par Email | **Alexis** | 1 min 30 |
| **10** | Conclusions, Limites Techniques & Perspectives Futures | **Tous** (Conclusion collective) | 1 min 00 |
| **—** | **Session de Questions / Réponses du Jury** | **Tous** | ~10 min |

---

## Detail Slide par Slide (Contenu Visuel & Script Narratif)

---

### Slide 01 — Introduction & Contexte Client
* **Intervenant :** Alexis
* **Éléments Visuels :**
  * Schéma d'une infrastructure d'entreprise exposée sur Internet avec DMZ.
  * Logo de l'équipe *CyBears* et intitulé de la mission.
* **Message Clé :**
  * Un Honeypot seul observe mais ne protège pas ; un NIDS seul détecte mais manque souvent de contexte sur la compromission réelle. Notre solution fusionne un leurre réaliste, un moteur de reniflage Scapy temps réel et une chaîne de prévention active (NIPS).
* **Script Narratif Oral :**
  > *"Bonjour à tous. Face à la recrudescence des menaces persistantes et des scans automatisés, déployer un honeypot permet d'attirer et d'étudier l'agresseur, mais pose le défi de l'analyse en temps réel. Notre mandat consistait à concevoir une solution complète : éprouver un honeypot via un script de pentest automatisé, collecter et corréler les données forensiques, et développer un NIDS/NIPS capable de neutraliser les attaques en direct tout en expédiant un rapport chiffré aux équipes de sécurité."*

---

### Slide 02 — Choix & Justification du Honeypot
* **Intervenant :** Léa
* **Éléments Visuels :**
  * Tableau comparatif : Cowrie / Dionaea vs **Metasploitable 2**.
  * Liste des services vulnérables exposés (Apache, OpenSSH, MySQL, vsftpd).
* **Message Clé :**
  * Pourquoi Metasploitable 2 ? Les honeypots à faible interaction (low-interaction) se font rapidement repérer par un attaquant chevronné en raison d'émulations incomplètes. Metasploitable 2 fournit un noyau Linux complet avec de véritables démons applicatifs et des cibles web réelles (DVWA, Mutillidae).
* **Script Narratif Oral :**
  > *"Pour notre cible, nous avons évalué plusieurs honeypots. Nous avons écarté les émulateurs superficiels pour retenir Metasploitable 2 en conteneur Docker. Ce choix nous offre un véritable serveur de production délibérément vulnérable : pile TCP/IP native, démons OpenSSH réels avec mécanismes PAM, et serveurs Web hébergeant DVWA. Cela nous permet d'observer de réelles traces système dans auth.log et access.log, indispensables pour notre analyse de logs."*

---

### Slide 03 — Architecture Docker & Isolation Réseau
* **Intervenant :** Antoine
* **Éléments Visuels :**
  * Schéma d'architecture Docker Compose : réseau bridge `honeynet`.
  * Zoom sur le couplage réseau : `network_mode: service:metasploitable`.
* **Message Clé :**
  * Le NIDS partage le namespace réseau de Metasploitable 2 pour voir 100% du trafic sur l'interface `eth0` et injecter des règles de blocage `iptables` sans altérer la configuration de la machine hôte.
* **Script Narratif Oral :**
  > *"L'infrastructure repose sur Docker Compose et le réseau isolé honeynet. La clé de voûte de notre architecture est le couplage direct du NIDS au conteneur cible via 'network_mode: service:metasploitable'. Grâce aux capacités NET_RAW et NET_ADMIN, notre sonde Scapy écoute en promiscuité directe sur l'interface eth0 partagée, garantissant qu'aucun paquet n'échappe à la détection, tout en permettant au NIPS d'appliquer des règles de pare-feu iptables immédiates."*

---

### Slide 04 — Pentest Automatisé : Scénarios & Calibration
* **Intervenant :** Maximilien
* **Éléments Visuels :**
  * Schéma des 8 attaques calibrées (Scans TCP/NULL/XMAS, SSH Brute-Force, DoS, SQLi, XSS, Path Traversal).
  * Capture du terminal d'attaque en cours d'exécution.
* **Message Clé :**
  * Code modulaire orienté objet avec gestion des exceptions, manipulation bas niveau de paquets Scapy et calibration précise des seuils pour tester les limites du NIDS.
* **Script Narratif Oral :**
  > *"Notre module de pentest (pentest.py) orchestre 8 scénarios distincts. Nous couvrons l'ensemble de la kill-chain : reconnaissance par scans TCP Connect et scans furtifs illégaux RFC 793 (XMAS et NULL scan via Scapy), phase d'authentification par force brute SSH via Paramiko, inondation DoS volumétrique, et exploitation web ciblée sur DVWA avec des payloads SQLi, XSS et Path Traversal. Chaque attaque est rigoureusement calibrée pour tester la réactivité et la précision des seuils de notre détection."*

---

### Slide 05 & 06 — Méthodologie d'Analyse & Corrélation Croisée
* **Intervenant :** Léa
* **Éléments Visuels :**
  * Graphique de corrélation croisée (Matrice 3 sources : Pentest ↔ Honeypot ↔ NIDS).
  * Statistiques réelles issues d'`analysis/analyze.py` (Top IP, échecs SSH, répartition des signatures HTTP).
* **Message Clé :**
  * **100% de taux de détection** : chaque scénario émis par le pentester a été tracé dans les logs cibles et a déclenché une alerte NIDS sans faux négatif.
* **Script Narratif Oral :**
  > *"L'analyse des journaux (analyze.py) constitue le pont forensique du projet. Nous croisons trois flux de données : les requêtes émises par le pentest, les traces laissées dans auth.log et access.log de Metasploitable, et les alertes générées par le NIDS. Notre algorithme établit une matrice de corrélation automatique : nous validons par exemple que 55 tentatives SSH erronées dans auth.log correspondent bien à l'alerte BRUTE_FORCE, aboutissant à un taux d'efficacité globale de 100% sans angle mort."*

---

### Slide 07 — Moteur NIDS : Détection Temps Réel Scapy
* **Intervenant :** Alexis
* **Éléments Visuels :**
  * Algorithmes de fenêtres glissantes (`deque` temporelles) et inspection de charge utile (DPI).
  * Gestion du cooldown anti-spam et typologie des alertes.
* **Message Clé :**
  * Hybridation détection comportementale/anomalies (volumes glissants) + détection par signature de paquets bruts (drapeaux TCP illégaux et inspection HTTP port 80).
* **Script Narratif Oral :**
  > *"Côté détection, notre moteur Scapy analyse chaque paquet capturé. Pour les attaques volumétriques comme les scans de ports, le DoS ou le brute-force, nous employons des fenêtres glissantes temporelles optimisées avec des deques Python, éliminant les faux positifs liés au trafic légitime. Pour les attaques web, nous effectuons une inspection approfondie de charge utile (DPI) sur la couche Raw TCP port 80 pour intercepter les motifs SQLi, XSS et ../etc/passwd."*

---

### Slide 08 — Prévention Active NIPS & Quarantaine Système
* **Intervenant :** Antoine
* **Éléments Visuels :**
  * Schéma séquentiel : Alerte NIDS → Commande `iptables -I INPUT -s <IP> -j DROP` → Quarantaine PAM `passwd -l`.
  * Démonstration de la rotation d'IP automatique par le pentester face au blocage.
* **Message Clé :**
  * Passage de la détection passive (NIDS) à la remédiation active (NIPS) multi-niveaux : blocage réseau et neutralisation de comptes compromis.
* **Script Narratif Oral :**
  > *"Nous avons dépassé le cahier des charges initial en transformant notre NIDS en véritable NIPS. Lorsque le mode prévention est actif, le franchissement d'un seuil critique déclenche immédiatement un bannissement réseau via iptables DROP, coupant court à l'attaque. Simultanément, un agent de quarantaine autonome verrouille localement les comptes cibles sur la machine compromise via PAM. Face à cela, notre script de pentest illustre l'évasion en intégrant une rotation dynamique d'IP."*

---

### Slide 09 — Supervision SIEM & Rapport Chiffré Fernet
* **Intervenant :** Alexis
* **Éléments Visuels :**
  * Capture d'écran du Dashboard *CyBear SIEM* (Neobrutal Dark Theme, flux SSE en direct).
  * Webhook Discord instantané et flux d'expédition du courriel chiffré (AES-128/HMAC-SHA256).
* **Message Clé :**
  * Interface SOC opérationnelle avec streaming Server-Sent Events, alertes multicanaux et respect strict de l'exigence d'envoi chiffré par email.
* **Script Narratif Oral :**
  > *"Pour exploiter ces données, nous avons développé 'CyBear SIEM', un dashboard web en temps réel sous Flask et Server-Sent Events offrant une vue globale au SOC : métriques, cartes d'attaques, terminal intégré et modale forensique. Dès qu'une intrusion survient, une alerte enrichie est transmise sur Discord. Enfin, conformément aux exigences du client, la synthèse forensique complète est chiffrée avec l'algorithme symétrique Fernet (AES-128 + HMAC-SHA256) puis expédiée automatiquement par e-mail sécurisé via SMTP TLS."*

---

### Slide 10 — Bilan, Limites & Perspectives
* **Intervenant :** Tous
* **Éléments Visuels :**
  * Tableau récapitulatif des livrables (68/68 tests réussis, couverture complète).
  * 3 axes d'amélioration future : TLS/HTTPS Decryption, Machine Learning (Isolation Forests), Intégration Suricata/Wazuh.
* **Script Narratif Oral :**
  > *"En conclusion, ce projet nous a permis de bâtir une chaîne cyberdéfense complète, du leurre à la remédiation. Notre suite compte 72 tests unitaires automatisés validant chaque composant. En perspective, le traitement des flux chiffrés HTTPS via interception SSL Bump et l'introduction d'algorithmes d'apprentissage non supervisé pour déceler des signaux faibles constituent les évolutions naturelles de ce produit. Nous vous remercions pour votre attention et sommes à votre disposition pour vos questions."*

---

## Anticipation des Questions du Jury / Client

1. **"Pourquoi Scapy plutôt que libpcap ou tcpdump natif pour le NIDS ?"**
   * *Réponse :* Scapy permet une manipulation native en Python des couches applicatives et protocolaires avec un décodage direct des objets, idéal pour prototyper rapidement des règles de détection sur-mesure (drapeaux TCP, extraction Raw HTTP) sans overhead de compilation.
2. **"Comment évitez-vous qu'un attaquant sature le NIDS par un DoS volumétrique ?"**
   * *Réponse :* Nous avons implémenté des fenêtres glissantes temporelles nettoyées en temps constant ($O(1)$ à l'amorti via `deque.popleft()`) ainsi qu'un cooldown anti-spam (`ALERT_COOLDOWN`) limitant la génération d'alertes répétées pour une même IP source.
3. **"Pourquoi le chiffrement Fernet plutôt qu'un chiffrement asymétrique RSA ?"**
   * *Réponse :* Fernet associe le chiffrement standard AES-128-CBC à l'authentification d'intégrité HMAC-SHA256 avec horodatage anti-rejeu. Pour des rapports volumineux automatisés machine-to-machine, la cryptographie symétrique offre une rapidité d'exécution et une robustesse d'intégrité optimales.
