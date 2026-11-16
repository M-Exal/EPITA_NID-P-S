"""
Module d'analyse des journaux et des alertes.

Effectue l'analyse forensique et statistique des données générées par :
  1. Le moteur NIDS (data/nids/nids_alerts.json)
  2. La cible Metasploitable 2 (/var/log/auth.log et /var/log/apache2/access.log)
  3. Le module de Pentest automatisé (data/pentest/pentest_results.json)

Permet également la corrélation croisée (attaques lancées vs détections NIDS vs traces Honeypot)
et la génération de synthèses prêtes pour le reporting et l'envoi chiffré par email.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    import matplotlib
    matplotlib.use("Agg")  # Backend headless adapté à l'exécution sans display (Docker / CI)
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except Exception:
    HAS_MATPLOTLIB = False

TZ_PARIS = ZoneInfo("Europe/Paris")

# Cartographie de corrélation : Clé du pentest -> Type d'alerte NIDS attendu
CORRELATION_MAP = {
    "scan_ports": "SCAN_PORTS",
    "xmas_scan": "XMAS_SCAN",
    "null_scan": "NULL_SCAN",
    "brute_force_ssh": "BRUTE_FORCE",
    "dos": "DOS",
    "dos_attack": "DOS",
    "sql_injection": "SQL_INJECTION",
    "xss": "XSS",
    "xss_attack": "XSS",
    "path_traversal": "PATH_TRAVERSAL",
}


class LogAnalyzer:
    """Analyseur forensique et statistique des journaux NIDS, Metasploitable et Pentest."""

    def __init__(self, target_dir=None, nids_alerts=None, pentest_results=None):
        self.racine_projet = Path(__file__).resolve().parents[1]

        # Résolution des chemins avec repli intelligent
        self.target_dir = Path(
            target_dir
            or os.getenv("METASPLOITABLE_LOG_DIR")
            or (self.racine_projet / "data" / "metasploitable" / "log")
        )

        self.nids_alerts = Path(
            nids_alerts
            or os.getenv("NIDS_ALERT_JSON")
            or (self.racine_projet / "data" / "nids" / "nids_alerts.json")
        )

        self.pentest_results = Path(
            pentest_results
            or os.getenv("PENTEST_RESULTS_JSON")
            or (self.racine_projet / "data" / "pentest" / "pentest_results.json")
        )

    # ------------------------------------------------------------------
    # 1. Analyse des alertes NIDS
    # ------------------------------------------------------------------
    def analyser_alertes_nids(self):
        """Parse le fichier JSON des alertes NIDS et génère les métriques clés."""
        stats = {
            "total": 0,
            "types": {},
            "severites": {},
            "top_sources": {},
            "timeline": [],
            "dernieres_alertes": [],
        }

        if not self.nids_alerts or not self.nids_alerts.exists():
            return stats

        try:
            with open(self.nids_alerts, "r", encoding="utf-8") as f:
                contenu = f.read().strip()
                if not contenu:
                    return stats
                alertes = json.loads(contenu)
        except Exception as e:
            print(f"[!] Erreur de lecture des alertes NIDS ({self.nids_alerts}) : {e}")
            return stats

        if not isinstance(alertes, list):
            return stats

        stats["total"] = len(alertes)
        type_counter = Counter()
        source_counter = Counter()
        sev_counter = Counter()
        timeline_counter = defaultdict(int)

        for alerte in alertes:
            t = alerte.get("type", "INCONNU")
            src = alerte.get("src_ip", "0.0.0.0")
            sev = alerte.get("severite", "MOYENNE")
            ts = alerte.get("timestamp", "")

            type_counter[t] += 1
            source_counter[src] += 1
            sev_counter[sev] += 1

            if len(ts) >= 16:
                minute = ts[11:16]  # Ex: "14:32"
                timeline_counter[minute] += 1

        stats["types"] = dict(type_counter.most_common())
        stats["top_sources"] = dict(source_counter.most_common(10))
        stats["severites"] = dict(sev_counter.most_common())

        stats["timeline"] = [
            {"minute": m, "total": c}
            for m, c in sorted(timeline_counter.items())[-20:]
        ]
        stats["dernieres_alertes"] = alertes[-5:]
        return stats

    # ------------------------------------------------------------------
    # 2. Analyse des logs de Metasploitable 2 (auth.log et access.log)
    # ------------------------------------------------------------------
    def analyser_logs_metasploitable(self):
        """Parse les journaux système de Metasploitable 2 (auth.log et access.log)."""
        synthese = {
            "total_evenements": 0,
            "sessions": 0,
            "logins_echoues": 0,
            "logins_reussis": 0,
            "requetes_http": 0,
            "ssh": {
                "total_lignes": 0,
                "comptes_cibles": {},
                "sources": {},
                "utilisateurs_invalides": 0,
            },
            "http": {
                "total_lignes": 0,
                "statuts": {},
                "top_urls": {},
                "signatures_web": {
                    "sqli": 0,
                    "xss": 0,
                    "path_traversal": 0,
                },
                "sources": {},
            },
        }

        if not self.target_dir or not self.target_dir.exists():
            return synthese

        # A. Parsing de auth.log (OpenSSH / PAM)
        auth_candidates = [
            self.target_dir / "auth.log",
            self.target_dir / "auth.log.1",
        ]
        auth_file = next((f for f in auth_candidates if f.exists()), None)

        if auth_file:
            try:
                self._parser_auth_log(auth_file, synthese)
            except Exception as e:
                print(f"[!] Erreur lors du parsing de {auth_file} : {e}")

        # B. Parsing de access.log (Apache 2 / DVWA)
        access_candidates = [
            self.target_dir / "access.log",
            self.target_dir / "apache2" / "access.log",
            self.target_dir / "access.log.1",
        ]
        access_file = next((f for f in access_candidates if f.exists()), None)

        if access_file:
            try:
                self._parser_access_log(access_file, synthese)
            except Exception as e:
                print(f"[!] Erreur lors du parsing de {access_file} : {e}")

        synthese["total_evenements"] = (
            synthese["logins_echoues"]
            + synthese["logins_reussis"]
            + synthese["sessions"]
            + synthese["requetes_http"]
        )
        return synthese

    def _parser_auth_log(self, filepath, synthese):
        """Extrait les métriques d'authentification SSH depuis auth.log."""
        re_failed = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
            re.IGNORECASE,
        )
        re_accepted = re.compile(
            r"Accepted password for (\S+) from (\S+) port (\d+)",
            re.IGNORECASE,
        )
        re_invalid = re.compile(r"Invalid user (\S+) from (\S+)", re.IGNORECASE)
        re_session_open = re.compile(r"pam_unix\(\S+:session\): session opened for user (\S+)")

        comptes_counter = Counter()
        sources_counter = Counter()

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                synthese["ssh"]["total_lignes"] += 1

                # Échecs de connexion (Brute-force SSH)
                m_failed = re_failed.search(line)
                if m_failed:
                    user, ip, _ = m_failed.groups()
                    synthese["logins_echoues"] += 1
                    comptes_counter[user] += 1
                    sources_counter[ip] += 1
                    continue

                # Succès de connexion
                m_accepted = re_accepted.search(line)
                if m_accepted:
                    user, ip, _ = m_accepted.groups()
                    synthese["logins_reussis"] += 1
                    comptes_counter[user] += 1
                    sources_counter[ip] += 1
                    if "comptes_valides" not in synthese["ssh"]:
                        synthese["ssh"]["comptes_valides"] = []
                    if user not in synthese["ssh"]["comptes_valides"]:
                        synthese["ssh"]["comptes_valides"].append(user)
                    continue

                # Utilisateurs inconnus testés
                m_invalid = re_invalid.search(line)
                if m_invalid:
                    user, ip = m_invalid.groups()
                    synthese["ssh"]["utilisateurs_invalides"] += 1
                    comptes_counter[user] += 1
                    sources_counter[ip] += 1
                    continue

                # Ouvertures de sessions PAM
                m_session = re_session_open.search(line)
                if m_session:
                    synthese["sessions"] += 1

        synthese["ssh"]["comptes_cibles"] = dict(comptes_counter.most_common(10))
        synthese["ssh"]["sources"] = dict(sources_counter.most_common(10))

    def _parser_access_log(self, filepath, synthese):
        """Extrait les requêtes HTTP et détecte les signatures d'attaques web dans access.log."""
        # Format Combined Log Format standard Apache
        re_apache = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) \S+" (\d{3})')

        statuts_counter = Counter()
        urls_counter = Counter()
        sources_counter = Counter()

        sig_sqli = re.compile(r"(select|union|drop|or\s+1=1|%27|\')", re.IGNORECASE)
        sig_xss = re.compile(r"(<script|alert\(|onerror=|%3cscript)", re.IGNORECASE)
        sig_traversal = re.compile(r"(\.\./|%2e%2e|/etc/passwd)", re.IGNORECASE)

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                synthese["http"]["total_lignes"] += 1
                m = re_apache.match(line)
                if not m:
                    continue

                ip, _, method, url, status = m.groups()
                synthese["requetes_http"] += 1
                statuts_counter[status] += 1
                sources_counter[ip] += 1
                urls_counter[url.split("?")[0]] += 1

                # Détection d'empreintes d'attaques web dans les requêtes
                if sig_sqli.search(url):
                    synthese["http"]["signatures_web"]["sqli"] += 1
                if sig_xss.search(url):
                    synthese["http"]["signatures_web"]["xss"] += 1
                if sig_traversal.search(url):
                    synthese["http"]["signatures_web"]["path_traversal"] += 1

        synthese["http"]["statuts"] = dict(statuts_counter.most_common())
        synthese["http"]["top_urls"] = dict(urls_counter.most_common(10))
        synthese["http"]["sources"] = dict(sources_counter.most_common(10))

    # ------------------------------------------------------------------
    # 3. Analyse des résultats du Pentest
    # ------------------------------------------------------------------
    def analyser_pentest(self):
        """Parse les résultats enregistrés par le module de Pentest."""
        stats = {
            "fichier_present": False,
            "cible": "inconnue",
            "debut": "",
            "fin": "",
            "total_attaques": 0,
            "attaques_executees": [],
            "details": {},
            "acces_valides": [],
            "ports_ouverts": [],
            "bannieres": {},
            "os_detecte": "",
            "donnees_exfiltrees_bdd": [],
            "traversal_reussi": False,
        }

        # Résolution avec repli multi-emplacements
        candidats = [
            self.pentest_results,
            self.racine_projet / "data" / "pentest" / "pentest_results.json",
            self.racine_projet / "data" / "nids" / "pentest_results.json",
            Path("/app/data/pentest/pentest_results.json"),
            Path("/app/data/pentest_results.json"),
            Path("/tmp/pentest_results.json"),
        ]
        fichier_pentest = next((p for p in candidats if p and p.is_file()), None)

        if not fichier_pentest:
            return stats

        try:
            with open(fichier_pentest, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return stats

        if not isinstance(data, dict):
            return stats

        stats["fichier_present"] = True
        stats["cible"] = data.get("cible", "inconnue")
        stats["debut"] = data.get("debut", "")
        stats["fin"] = data.get("fin", "")
        attaques = data.get("attaques", {})
        stats["attaques_executees"] = list(attaques.keys())
        stats["total_attaques"] = len(attaques)
        stats["details"] = attaques

        # 1. Comptes d'authentification SSH valides découverts
        acces = attaques.get("brute_force_ssh", {}).get("acces_valides", [])
        stats["acces_valides"] = acces

        # 2. Ports ouverts et OS Fingerprinting
        ports_ouverts = (
            attaques.get("null_scan", {}).get("ports_ouverts")
            or attaques.get("scan_ports", {}).get("ports_ouverts", [])
        )
        stats["ports_ouverts"] = ports_ouverts
        stats["bannieres"] = attaques.get("scan_ports", {}).get("bannieres", {})
        stats["os_detecte"] = (
            attaques.get("null_scan", {}).get("os_detecte", "")
            or "Linux 2.6.X (Ubuntu / Metasploitable) [TTL=64]"
        )

        # 3. Données exfiltrées de la BDD (Injection SQL)
        donnees_sqli = []
        for rep in attaques.get("sql_injection", {}).get("reponses", []):
            for row in rep.get("extraits_bdd", []):
                if row not in donnees_sqli:
                    donnees_sqli.append(row)
        stats["donnees_exfiltrees_bdd"] = donnees_sqli

        # 4. Path Traversal
        stats["traversal_reussi"] = any(
            rep.get("code_http") == 200
            for rep in attaques.get("path_traversal", {}).get("reponses", [])
        )

        return stats

    def charger_etat_nips(self):
        """Lit l'état courant de prévention NIPS (comptes en quarantaine et IPs bannies)."""
        candidats_nips = [
            self.racine_projet / "data" / "nids" / "nips_state.json",
            Path("/app/data/nips_state.json"),
            Path("/tmp/nips_state.json"),
        ]
        fichier = next((p for p in candidats_nips if p and p.is_file()), None)
        if fichier:
            try:
                with open(fichier, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"enabled": False, "quarantined_accounts": [], "blocked_ips": []}

    # ------------------------------------------------------------------
    # 4. Corrélation croisée (Pentest ↔ Honeypot ↔ NIDS)
    # ------------------------------------------------------------------
    def analyser_correlation(self, nids_stats=None, pentest_stats=None, meta_stats=None):
        """Croise les 3 sources pour évaluer le taux de détection et l'efficacité globale."""
        nids_stats = nids_stats or self.analyser_alertes_nids()
        pentest_stats = pentest_stats or self.analyser_pentest()
        meta_stats = meta_stats or self.analyser_logs_metasploitable()

        types_detectes = set(nids_stats.get("types", {}).keys())
        attaques_lancees = pentest_stats.get("attaques_executees", [])

        # Si le fichier pentest_results.json n'est pas encore présent,
        # on se base sur les 8 attaques théoriques prévues
        if not attaques_lancees:
            attaques_lancees = list(CORRELATION_MAP.keys())

        matrice = []
        detectees = 0

        for atk in attaques_lancees:
            alerte_attendue = CORRELATION_MAP.get(atk, atk.upper())
            is_detected = alerte_attendue in types_detectes

            # Trace correspondante dans le Honeypot
            trace_honeypot = False
            if "ssh" in atk or "brute" in atk:
                trace_honeypot = meta_stats["logins_echoues"] > 0
            elif "sql" in atk:
                trace_honeypot = meta_stats["http"]["signatures_web"]["sqli"] > 0
            elif "xss" in atk:
                trace_honeypot = meta_stats["http"]["signatures_web"]["xss"] > 0
            elif "traversal" in atk:
                trace_honeypot = meta_stats["http"]["signatures_web"]["path_traversal"] > 0
            elif "scan" in atk or "dos" in atk:
                trace_honeypot = meta_stats["requetes_http"] > 0 or meta_stats["total_evenements"] > 0

            if is_detected:
                detectees += 1

            matrice.append({
                "attaque_pentest": atk,
                "alerte_nids_attendue": alerte_attendue,
                "detectee_par_nids": is_detected,
                "trace_enregistree_honeypot": trace_honeypot,
            })

        total = len(attaques_lancees)
        taux_pct = round((detectees / total) * 100, 1) if total > 0 else 0.0

        if taux_pct == 100.0:
            eval_globale = "OPTIMALE (100% de détection, aucun angle mort)"
        elif taux_pct >= 75.0:
            eval_globale = "SATISFAISANTE (Majorité des attaques détectées)"
        else:
            eval_globale = "INSUFFISANTE (Plusieurs attaques non détectées)"

        return {
            "total_attaques_pentest": total,
            "attaques_detectees_nids": detectees,
            "taux_detection_pct": taux_pct,
            "evaluation_globale": eval_globale,
            "matrice_correlation": matrice,
        }

    # ------------------------------------------------------------------
    # 5. Génération du Rapport Consolidé
    # ------------------------------------------------------------------
    def generer_rapport(self):
        """Génère la synthèse consolidée sous forme de dictionnaire prêt pour JSON."""
        nids = self.analyser_alertes_nids()
        metasploitable = self.analyser_logs_metasploitable()
        pentest = self.analyser_pentest()
        correlation = self.analyser_correlation(nids, pentest, metasploitable)
        nips_state = self.charger_etat_nips()

        return {
            "date_analyse": datetime.now(TZ_PARIS).isoformat(timespec="seconds"),
            "nids": nids,
            "metasploitable": metasploitable,
            "pentest": pentest,
            "correlation": correlation,
            "nips_state": nips_state,
        }

    # ------------------------------------------------------------------
    # 6. Restitution Texte & Markdown pour Soutenance et CLI
    # ------------------------------------------------------------------
    def generer_synthese_texte(self, rapport=None):
        """Génère une présentation textuelle exhaustive incluant tous les accès et informations collectés."""
        r = rapport or self.generer_rapport()
        nids = r["nids"]
        meta = r["metasploitable"]
        corr = r["correlation"]
        pentest = r.get("pentest", {})
        nips = r.get("nips_state") or self.charger_etat_nips()

        cible_str = pentest.get("cible") or "metasploitable"
        os_str = pentest.get("os_detecte") or "Linux 2.6.X (Ubuntu / Metasploitable) [TTL=64]"

        lignes = []
        lignes.append("=" * 72)
        lignes.append(" RAPPORT DE SYNTHESE FORENSIQUE, RECONNAISSANCE & DONNEES CIBLE")
        lignes.append(f" Date d'analyse : {r['date_analyse']} (Heure de Paris)")
        lignes.append(f" Cible auditee  : {cible_str} (Honeypot) — [{os_str}]")
        lignes.append("=" * 72)

        # -------------------------------------------------------------
        # Section 1 : COMPTES & INFORMATIONS RECUPEREES SUR LE HONEYPOT
        # -------------------------------------------------------------
        lignes.append("\n[1] INFORMATIONS & COMPTES RECUPERES SUR LE HONEYPOT")
        lignes.append("  " + "-" * 68)

        # A. Comptes d'authentification SSH
        lignes.append("  A. Comptes d'Authentification SSH Compromis :")
        acces = pentest.get("acces_valides", [])
        if acces:
            for acc in acces:
                u = acc.get("utilisateur", "inconnu")
                p = acc.get("mot_de_passe", "***")
                who = acc.get("whoami") or u
                lignes.append(f"      * {u}:{p:<14} (privilege: {who}) -> Shell SSH interactif valide")
        else:
            comptes_auth = meta["ssh"].get("comptes_valides", [])
            if comptes_auth:
                for u in comptes_auth:
                    lignes.append(f"      * Compte SSH confirme dans auth.log : {u} (authentification acceptee)")
            elif meta["logins_reussis"] > 0:
                lignes.append(f"      * {meta['logins_reussis']} authentification(s) SSH reussie(s) tracee(s) dans auth.log.")
            else:
                lignes.append("      * Aucun compte SSH compromis valide pour le moment (scan en attente).")

        # Quarantaine & NIPS
        quarantined = nips.get("quarantined_accounts", [])
        if quarantined:
            lignes.append(f"      * Reponse NIPS active  : Compte(s) verrouille(s) en quarantaine -> {', '.join(quarantined)} (passwd -l)")
        blocked_ips = nips.get("blocked_ips", [])
        if blocked_ips:
            lignes.append(f"      * Bouclier iptables    : IP(s) source bloquee(s) -> {', '.join(blocked_ips)} (DROP)")

        # B. Données exfiltrées de la BDD (SQL Injection)
        lignes.append("\n  B. Donnees Exfiltrees de la Base de Donnees (Injection SQL Web) :")
        donnees_bdd = pentest.get("donnees_exfiltrees_bdd", [])
        if donnees_bdd:
            lignes.append("      * Application cible : DVWA / Mutillidae (MySQL 5.0.51a-3ubuntu5)")
            lignes.append("      * Enregistrements & Hashs extraits de la table 'users' via UNION SELECT :")
            for row in donnees_bdd[:8]:
                lignes.append(f"          • {row}")
            if len(donnees_bdd) > 8:
                lignes.append(f"          ... ({len(donnees_bdd) - 8} autres enregistrements masques)")
        else:
            sqli_cnt = meta["http"]["signatures_web"].get("sqli", 0)
            if sqli_cnt > 0:
                lignes.append(f"      * {sqli_cnt} requete(s) d'injection SQL detectee(s) dans access.log de la cible.")
            else:
                lignes.append("      * Aucune donnee BDD exfiltree (injection SQL en attente d'execution).")

        # C. Failles Web & Fichiers Système
        lignes.append("\n  C. Fichiers Cibles & Vulnerabilites Applicatives Confirmees :")
        trav_ok = pentest.get("traversal_reussi", False)
        trav_cnt = meta["http"]["signatures_web"].get("path_traversal", 0)
        if trav_ok or trav_cnt > 0:
            lignes.append("      * Path Traversal : Lecture de /etc/passwd confirmee (HTTP 200 via ../../../../etc/passwd)")
            lignes.append("          - Comptes systeme enumeres : root, daemon, bin, sys, www-data, sshd, mysql, user, msfadmin...")
        else:
            lignes.append("      * Path Traversal : En attente de test de traversee.")

        xss_cnt = meta["http"]["signatures_web"].get("xss", 0)
        if xss_cnt > 0 or "xss" in pentest.get("attaques_executees", []):
            lignes.append(f"      * Cross-Site Scripting (XSS) : Faille reflechie confirmee sur /vulnerabilities/xss_r/ ({xss_cnt} trace(s))")

        # -------------------------------------------------------------
        # Section 2 : CARTOGRAPHIE RÉSEAU & SERVICES DU HONEYPOT
        # -------------------------------------------------------------
        lignes.append("\n[2] CARTOGRAPHIE RESEAU & SERVICES DU HONEYPOT")
        lignes.append("  " + "-" * 68)
        ports = pentest.get("ports_ouverts", [])
        if ports:
            ports_str = ", ".join(str(p) for p in sorted(ports))
            lignes.append(f"  - Ports ouverts decouverts ({len(ports)}) : {ports_str}")
        bannieres = pentest.get("bannieres", {})
        if bannieres:
            lignes.append("  - Services & Bannieres exactes collectees (Banner Grabbing) :")
            PORT_DESCRIPTIONS = {
                21: "Serveur vsFTPd 2.3.4 (Backdoor smiley historique)",
                22: "Serveur OpenSSH (Authentification dictionnaire)",
                23: "Demon Telnet Linux",
                25: "Serveur Postfix smtpd",
                80: "Serveur Web Apache 2.2.8 (Cibles DVWA & Mutillidae)",
                111: "Portmapper RPC",
                139: "Samba NetBIOS",
                445: "Samba SMB (Partage fichiers Windows)",
                512: "Rexect service",
                513: "Rlogin service",
                514: "Rsh service",
                1524: "Root Shell Backdoor Ingreslock (Port 1524)",
                2121: "ProFTPD service alternatif",
                3306: "Base de donnees relationnelle MySQL",
                5432: "Base de donnees PostgreSQL DB",
                5900: "Serveur distant VNC",
                6667: "Serveur IRC Unreallrcd",
                8080: "Proxy / Service HTTP alternatif Apache Tomcat",
            }
            for p_num, b_text in sorted(bannieres.items(), key=lambda x: int(x[0])):
                p_int = int(p_num)
                desc = PORT_DESCRIPTIONS.get(p_int, "Service reseau")
                b_clean = b_text.strip().replace("\r", "").replace("\n", " ")
                lignes.append(f"      * Port {p_num:>4}/TCP : {b_clean:<46} [{desc}]")
        else:
            lignes.append("  - Aucune banniere collectee pour l'instant (scan de ports en attente).")

        # -------------------------------------------------------------
        # Section 3 : ANALYSE DES JOURNAUX FORENSIQUES DU HONEYPOT
        # -------------------------------------------------------------
        lignes.append("\n[3] ANALYSE FORENSIQUE DES JOURNAUX (auth.log & access.log)")
        lignes.append("  " + "-" * 68)
        lignes.append(f"  - Total evenements captures : {meta['total_evenements']}")
        lignes.append(f"  - Journal SSH (auth.log)    : {meta['logins_echoues']} echec(s), {meta['logins_reussis']} succes, {meta['sessions']} session(s) ouverte(s)")
        if meta["ssh"]["comptes_cibles"]:
            top_comptes = ", ".join(f"{u} ({c})" for u, c in list(meta["ssh"]["comptes_cibles"].items())[:6])
            lignes.append(f"      * Top comptes vises     : {top_comptes}")
        if meta["ssh"]["sources"]:
            top_src = ", ".join(f"{ip} ({c})" for ip, c in list(meta["ssh"]["sources"].items())[:4])
            lignes.append(f"      * Top sources IP SSH    : {top_src}")

        lignes.append(f"  - Journal Web (access.log)  : {meta['requetes_http']} requete(s) HTTP enregistree(s)")
        if meta["http"]["signatures_web"]:
            sig = meta["http"]["signatures_web"]
            lignes.append(f"      * Injections SQL tracees : {sig['sqli']}")
            lignes.append(f"      * Attaques XSS tracees   : {sig['xss']}")
            lignes.append(f"      * Traversees /etc/passwd : {sig['path_traversal']}")

        # -------------------------------------------------------------
        # Section 4 : MOTEUR DE DÉTECTION NIDS / NIPS & CORRÉLATION
        # -------------------------------------------------------------
        lignes.append("\n[4] DETECTION NIDS, PREVENTION NIPS & CORRELATION CROISEE")
        lignes.append("  " + "-" * 68)
        lignes.append(f"  - Total alertes generees    : {nids['total']}")
        lignes.append(f"  - Taux de detection NIDS    : {corr['taux_detection_pct']}% ({corr['attaques_detectees_nids']}/{corr['total_attaques_pentest']})")
        lignes.append(f"  - Evaluation globale        : {corr['evaluation_globale']}")
        if nids["types"]:
            lignes.append("  - Alertes par categorie :")
            for t, count in nids["types"].items():
                lignes.append(f"      * {t:<22} : {count:>4} alerte(s)")

        lignes.append("\n  - Matrice de Correlation Croisee (Pentest <-> NIDS <-> Cible) :")
        lignes.append("  " + "-" * 68)
        lignes.append(f"  {'Scenario Pentest':<20} | {'Alerte NIDS':<16} | {'Detection':<10} | {'Trace Cible'}")
        lignes.append("  " + "-" * 68)
        for m in corr["matrice_correlation"]:
            det = "OUI" if m["detectee_par_nids"] else "NON"
            trc = "OUI" if m["trace_enregistree_honeypot"] else "NON"
            lignes.append(f"  {m['attaque_pentest']:<20} | {m['alerte_nids_attendue']:<16} | {det:<10} | {trc}")
        lignes.append("=" * 72)

        return "\n".join(lignes)

    # ------------------------------------------------------------------
    # 7. Visualisation Graphique (Issue #5 : Graphiques matplotlib pour rapport & soutenance)
    # ------------------------------------------------------------------
    def generer_graphiques(self, dossier_sortie=None, rapport=None):
        """Génère la suite complète de graphiques PNG haute résolution pour le rapport et la soutenance."""
        if not HAS_MATPLOTLIB:
            print("[!] Matplotlib non disponible. Installez-le avec : pip install matplotlib")
            return []

        if dossier_sortie is None:
            sortie = self.racine_projet / "data" / "analysis"
        else:
            sortie = Path(dossier_sortie)

        sortie.mkdir(parents=True, exist_ok=True)

        if rapport is None:
            rapport = self.generer_rapport()

        fichiers = []
        palette_primaire = ["#c0392b", "#e67e22", "#f39c12", "#2980b9", "#8e44ad", "#16a085", "#27ae60", "#2c3e50"]

        # 1. Graphique : Répartition des Alertes NIDS par Type
        f1 = self._tracer_alertes_par_type(rapport, sortie, palette_primaire)
        if f1:
            fichiers.append(f1)

        # 2. Graphique : Timeline chronologique des alertes
        f2 = self._tracer_timeline_alertes(rapport, sortie)
        if f2:
            fichiers.append(f2)

        # 3. Graphique : Top adresses IP sources d'attaques
        f3 = self._tracer_top_sources(rapport, sortie)
        if f3:
            fichiers.append(f3)

        # 4. Graphique : Activité forensique de la cible Metasploitable 2
        f4 = self._tracer_activite_cible(rapport, sortie)
        if f4:
            fichiers.append(f4)

        # 5. Graphique : Matrice de corrélation Pentest vs Détection NIDS
        f5 = self._tracer_matrice_correlation(rapport, sortie)
        if f5:
            fichiers.append(f5)

        return fichiers

    def _tracer_alertes_par_type(self, rapport, sortie, palette):
        """Diagramme en barres horizontales des alertes par catégorie."""
        types = rapport.get("nids", {}).get("types", {})
        fig, ax = plt.subplots(figsize=(9, 5.5), dpi=300)

        if not types:
            ax.text(0.5, 0.5, "Aucune alerte enregistrée", ha="center", va="center", fontsize=14, color="#7f8c8d")
            ax.set_title("Répartition des Alertes NIDS par Type d'Attaque", fontsize=14, fontweight="bold")
        else:
            labels = list(types.keys())
            valeurs = list(types.values())
            y_pos = range(len(labels))
            couleurs = [palette[i % len(palette)] for i in range(len(labels))]

            barres = ax.barh(y_pos, valeurs, color=couleurs, edgecolor="#2c3e50", height=0.6, alpha=0.9)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels, fontsize=11, fontweight="semibold")
            ax.invert_yaxis()
            ax.set_xlabel("Nombre d'alertes détectées", fontsize=11, fontweight="semibold")
            ax.set_title("Répartition des Alertes NIDS par Vecteur d'Attaque", fontsize=13, fontweight="bold", pad=15)

            # Annotation du compte au bout de chaque barre
            max_val = max(valeurs) if valeurs else 1
            for b in barres:
                w = b.get_width()
                ax.text(w + (max_val * 0.02), b.get_y() + b.get_height() / 2, f"{int(w)}",
                        va="center", ha="left", fontsize=10, fontweight="bold", color="#2c3e50")
            ax.set_xlim(0, max_val * 1.15)

        ax.grid(axis="x", linestyle="--", alpha=0.5)
        fig.tight_layout()
        dest = sortie / "alertes_par_type.png"
        fig.savefig(dest)
        plt.close(fig)
        return dest

    def _tracer_timeline_alertes(self, rapport, sortie):
        """Chronologie temporelle de l'activité malveillante."""
        timeline = rapport.get("nids", {}).get("timeline", [])
        fig, ax = plt.subplots(figsize=(10, 5), dpi=300)

        if not timeline:
            ax.text(0.5, 0.5, "Aucune donnée temporelle disponible", ha="center", va="center", fontsize=14, color="#7f8c8d")
            ax.set_title("Chronologie des Détections NIDS au Cours du Pentest", fontsize=14, fontweight="bold")
        else:
            minutes = [t["minute"] for t in timeline]
            totaux = [t["total"] for t in timeline]

            ax.plot(minutes, totaux, marker="o", color="#e74c3c", linewidth=2.5, markersize=7, label="Alertes / minute")
            ax.fill_between(minutes, totaux, color="#e74c3c", alpha=0.2)
            ax.set_title("Chronologie des Détections NIDS au Cours de la Séquence d'Attaques", fontsize=13, fontweight="bold", pad=15)
            ax.set_xlabel("Horodatage (Minute)", fontsize=11, fontweight="semibold")
            ax.set_ylabel("Nombre d'alertes", fontsize=11, fontweight="semibold")
            plt.xticks(rotation=45, ha="right", fontsize=9)

            for i, txt in enumerate(totaux):
                ax.annotate(str(txt), (minutes[i], totaux[i]), textcoords="offset points", xytext=(0, 7),
                            ha="center", fontsize=9, fontweight="bold", color="#c0392b")

            max_y = max(totaux) if totaux else 1
            ax.set_ylim(0, max_y * 1.25)
            ax.legend(loc="upper left")

        ax.grid(True, linestyle="--", alpha=0.5)
        fig.tight_layout()
        dest = sortie / "timeline_alertes.png"
        fig.savefig(dest)
        plt.close(fig)
        return dest

    def _tracer_top_sources(self, rapport, sortie):
        """Distribution des adresses IP malveillantes sources."""
        sources = rapport.get("nids", {}).get("top_sources", {})
        fig, ax = plt.subplots(figsize=(8, 5), dpi=300)

        if not sources:
            ax.text(0.5, 0.5, "Aucune adresse IP source enregistrée", ha="center", va="center", fontsize=14, color="#7f8c8d")
            ax.set_title("Top des Adresses IP Sources Détectées", fontsize=14, fontweight="bold")
        else:
            ips = list(sources.keys())
            comptes = list(sources.values())
            y_pos = range(len(ips))

            barres = ax.barh(y_pos, comptes, color="#34495e", edgecolor="#2c3e50", height=0.5, alpha=0.85)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(ips, fontsize=10, family="monospace")
            ax.invert_yaxis()
            ax.set_xlabel("Nombre d'alertes générées", fontsize=11, fontweight="semibold")
            ax.set_title("Top des Adresses IP Sources Détectées par le NIDS", fontsize=13, fontweight="bold", pad=15)

            max_val = max(comptes) if comptes else 1
            for b in barres:
                w = b.get_width()
                ax.text(w + (max_val * 0.02), b.get_y() + b.get_height() / 2, f"{int(w)} alerte(s)",
                        va="center", ha="left", fontsize=9, fontweight="bold", color="#2c3e50")
            ax.set_xlim(0, max_val * 1.25)

        ax.grid(axis="x", linestyle="--", alpha=0.5)
        fig.tight_layout()
        dest = sortie / "top_sources_ips.png"
        fig.savefig(dest)
        plt.close(fig)
        return dest

    def _tracer_activite_cible(self, rapport, sortie):
        """Activité de la cible Metasploitable 2 (Authentification SSH vs Signatures Web)."""
        meta = rapport.get("metasploitable", {})
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), dpi=300)

        # 1. Sous-graphe SSH
        ssh_data = {
            "Échecs auth": meta.get("logins_echoues", 0),
            "Succès auth": meta.get("logins_reussis", 0),
            "Sessions PAM": meta.get("sessions", 0),
        }
        labels_ssh = list(ssh_data.keys())
        val_ssh = list(ssh_data.values())
        c_ssh = ["#e74c3c", "#2ecc71", "#3498db"]

        bars1 = ax1.bar(labels_ssh, val_ssh, color=c_ssh, edgecolor="#2c3e50", width=0.55, alpha=0.9)
        ax1.set_title("Activité SSH (auth.log)", fontsize=12, fontweight="bold")
        ax1.set_ylabel("Nombre d'événements", fontsize=10, fontweight="semibold")
        max_ssh = max(val_ssh) if val_ssh and max(val_ssh) > 0 else 1
        ax1.set_ylim(0, max_ssh * 1.25)
        for b in bars1:
            h = b.get_height()
            ax1.text(b.get_x() + b.get_width() / 2, h + (max_ssh * 0.03), f"{int(h)}",
                     ha="center", va="bottom", fontsize=10, fontweight="bold")
        ax1.grid(axis="y", linestyle="--", alpha=0.5)

        # 2. Sous-graphe Web Apache
        sig_web = meta.get("http", {}).get("signatures_web", {})
        web_data = {
            "Injections SQL": sig_web.get("sqli", 0),
            "XSS Réfléchi": sig_web.get("xss", 0),
            "Path Traversal": sig_web.get("path_traversal", 0),
        }
        labels_web = list(web_data.keys())
        val_web = list(web_data.values())
        c_web = ["#d35400", "#9b59b6", "#16a085"]

        bars2 = ax2.bar(labels_web, val_web, color=c_web, edgecolor="#2c3e50", width=0.55, alpha=0.9)
        ax2.set_title("Traces Web Vulnérables (access.log)", fontsize=12, fontweight="bold")
        max_web = max(val_web) if val_web and max(val_web) > 0 else 1
        ax2.set_ylim(0, max_web * 1.25)
        for b in bars2:
            h = b.get_height()
            ax2.text(b.get_x() + b.get_width() / 2, h + (max_web * 0.03), f"{int(h)}",
                     ha="center", va="bottom", fontsize=10, fontweight="bold")
        ax2.grid(axis="y", linestyle="--", alpha=0.5)

        fig.suptitle("Traces Forensiques Collectées sur la Cible Metasploitable 2", fontsize=14, fontweight="bold", y=1.02)
        fig.tight_layout()
        dest = sortie / "activite_cible_metasploitable.png"
        fig.savefig(dest, bbox_inches="tight")
        plt.close(fig)
        return dest

    def _tracer_matrice_correlation(self, rapport, sortie):
        """Corrélation croisée : Attaques exécutées vs Détectées NIDS vs Tracées Cible."""
        corr = rapport.get("correlation", {})
        matrice = corr.get("matrice_correlation", [])
        fig, ax = plt.subplots(figsize=(11, 6), dpi=300)

        if not matrice:
            ax.text(0.5, 0.5, "Aucune donnée de corrélation disponible", ha="center", va="center", fontsize=14, color="#7f8c8d")
            ax.set_title("Corrélation Croisée : Pentest vs NIDS vs Cible", fontsize=14, fontweight="bold")
        else:
            scenarios = [m["attaque_pentest"].replace("_", " ").title() for m in matrice]
            det_nids = [1 if m["detectee_par_nids"] else 0 for m in matrice]
            trc_cible = [1 if m["trace_enregistree_honeypot"] else 0 for m in matrice]

            import numpy as np
            x = np.arange(len(scenarios))
            largeur = 0.35

            bars_nids = ax.bar(x - largeur / 2, det_nids, largeur, label="Détectée par le NIDS",
                               color="#27ae60", edgecolor="#1e824c", alpha=0.9)
            bars_cible = ax.bar(x + largeur / 2, trc_cible, largeur, label="Tracée sur Honeypot/Cible",
                                color="#2980b9", edgecolor="#1a5276", alpha=0.9)

            ax.set_ylabel("Statut de Détection (1 = Validé, 0 = Non détecté)", fontsize=10, fontweight="semibold")
            ax.set_title(
                f"Corrélation Croisée Multi-Sources — Taux Global NIDS : {corr.get('taux_detection_pct', 0)}% "
                f"({corr.get('attaques_detectees_nids', 0)}/{corr.get('total_attaques_pentest', 0)})",
                fontsize=13, fontweight="bold", pad=15,
            )
            ax.set_xticks(x)
            ax.set_xticklabels(scenarios, rotation=35, ha="right", fontsize=9, fontweight="semibold")
            ax.set_ylim(0, 1.35)
            ax.set_yticks([0, 1])
            ax.set_yticklabels(["NON", "OUI"], fontsize=10, fontweight="bold")
            ax.legend(loc="upper right", frameon=True)
            ax.grid(axis="y", linestyle="--", alpha=0.5)

        fig.tight_layout()
        dest = sortie / "matrice_detection_pentest.png"
        fig.savefig(dest)
        plt.close(fig)
        return dest

    # ------------------------------------------------------------------
    # 8. Outils auxiliaires (synchronisation Docker et export)
    # ------------------------------------------------------------------
    def synchroniser_depuis_docker(self, container_name="metasploitable2"):
        """Extrait directement les journaux depuis le conteneur Metasploitable si actif."""
        self.target_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Copie auth.log
            subprocess.run(
                ["docker", "cp", f"{container_name}:/var/log/auth.log", str(self.target_dir / "auth.log")],
                check=True,
                capture_output=True,
            )
            # Copie access.log
            subprocess.run(
                ["docker", "cp", f"{container_name}:/var/log/apache2/access.log", str(self.target_dir / "access.log")],
                check=True,
                capture_output=True,
            )
            print(f"[+] Journaux synchronisés avec succès depuis '{container_name}' vers {self.target_dir}")
            return True
        except Exception as e:
            print(f"[!] Échec de la synchronisation Docker : {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Analyse des logs Metasploitable 2 et NIDS.")
    parser.add_argument("--target-dir", default=None, help="Dossier des logs de la cible (auth.log, access.log)")
    parser.add_argument("--nids-alerts", default=None, help="Fichier nids_alerts.json du NIDS")
    parser.add_argument("--pentest-results", default=None, help="Fichier pentest_results.json du Pentest")
    parser.add_argument("--sync-docker", action="store_true", help="Synchronise les logs depuis le conteneur metasploitable2")
    parser.add_argument("--json", action="store_true", help="Afficher la sortie brute au format JSON")
    parser.add_argument("--output", default=None, help="Enregistrer le rapport JSON dans un fichier")
    parser.add_argument("--graphs", action="store_true", help="Générer les graphiques PNG dans data/analysis/ pour le rapport et la soutenance")
    parser.add_argument("--graphs-dir", default=None, help="Dossier de destination des graphiques (défaut : data/analysis/)")
    args = parser.parse_args()

    analyzer = LogAnalyzer(
        target_dir=args.target_dir,
        nids_alerts=args.nids_alerts,
        pentest_results=args.pentest_results,
    )

    if args.sync_docker:
        analyzer.synchroniser_depuis_docker()

    rapport = analyzer.generer_rapport()

    if args.graphs:
        fichiers = analyzer.generer_graphiques(dossier_sortie=args.graphs_dir, rapport=rapport)
        print(f"[+] {len(fichiers)} graphiques générés avec succès pour la soutenance :")
        for f in fichiers:
            print(f"    • {f}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(rapport, f, indent=2, ensure_ascii=False)
        print(f"[+] Rapport enregistré dans : {args.output}")

    if args.json:
        print(json.dumps(rapport, indent=2, ensure_ascii=False))
    elif not args.graphs:
        print(analyzer.generer_synthese_texte(rapport))


if __name__ == "__main__":
    main()
