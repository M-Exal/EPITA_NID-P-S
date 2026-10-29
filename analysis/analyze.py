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

TZ_PARIS = ZoneInfo("Europe/Paris")

# Cartographie de corrélation : Clé du pentest -> Type d'alerte NIDS attendu
CORRELATION_MAP = {
    "scan_ports": "SCAN_PORTS",
    "xmas_scan": "XMAS_SCAN",
    "null_scan": "NULL_SCAN",
    "brute_force_ssh": "BRUTE_FORCE",
    "dos": "DOS",
    "sql_injection": "SQL_INJECTION",
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
        }

        if not self.pentest_results or not self.pentest_results.exists():
            return stats

        try:
            with open(self.pentest_results, "r", encoding="utf-8") as f:
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
        return stats

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

        return {
            "date_analyse": datetime.now(TZ_PARIS).isoformat(timespec="seconds"),
            "nids": nids,
            "metasploitable": metasploitable,
            "pentest": pentest,
            "correlation": correlation,
        }

    # ------------------------------------------------------------------
    # 6. Restitution Texte & Markdown pour Soutenance et CLI
    # ------------------------------------------------------------------
    def generer_synthese_texte(self, rapport=None):
        """Génère une présentation textuelle claire et structurée."""
        r = rapport or self.generer_rapport()
        nids = r["nids"]
        meta = r["metasploitable"]
        corr = r["correlation"]

        lignes = []
        lignes.append("=" * 68)
        lignes.append(" 🛡️  RAPPORT DE SYNTHÈSE FORENSIQUE & ANALYSE DES JOURNAUX")
        lignes.append(f"    Date d'analyse : {r['date_analyse']} (Heure de Paris)")
        lignes.append("=" * 68)

        # Section NIDS
        lignes.append("\n[1] MOTEUR DE DÉTECTION NIDS / NIPS")
        lignes.append(f"  • Total alertes émises : {nids['total']}")
        if nids["types"]:
            lignes.append("  • Répartition par type d'attaque :")
            for t, count in nids["types"].items():
                lignes.append(f"      - {t:<22} : {count:>4} alerte(s)")
        if nids["top_sources"]:
            lignes.append("  • Top adresses IP suspectes :")
            for ip, count in list(nids["top_sources"].items())[:5]:
                lignes.append(f"      - {ip:<22} : {count:>4} événement(s)")

        # Section Honeypot
        lignes.append("\n[2] CIBLE & HONEYPOT (Metasploitable 2)")
        lignes.append(f"  • Total événements capturés : {meta['total_evenements']}")
        lignes.append(f"  • Authentifications SSH      : {meta['logins_echoues']} échouée(s), {meta['logins_reussis']} réussie(s)")
        lignes.append(f"  • Requêtes Web (Apache/DVWA) : {meta['requetes_http']}")
        if meta["http"]["signatures_web"]:
            sig = meta["http"]["signatures_web"]
            lignes.append(f"      - Injections SQL tracées : {sig['sqli']}")
            lignes.append(f"      - Injections XSS tracées : {sig['xss']}")
            lignes.append(f"      - Traversées répertoire  : {sig['path_traversal']}")

        # Section Corrélation
        lignes.append("\n[3] CORRÉLATION CROISÉE PENTEST ↔ NIDS")
        lignes.append(f"  • Taux de détection NIDS    : {corr['taux_detection_pct']}% ({corr['attaques_detectees_nids']}/{corr['total_attaques_pentest']})")
        lignes.append(f"  • Évaluation globale        : {corr['evaluation_globale']}")
        lignes.append("-" * 68)
        lignes.append(f"  {'Scénario Pentest':<20} | {'Alerte NIDS':<16} | {'Détection':<10} | {'Trace Cible'}")
        lignes.append("-" * 68)
        for m in corr["matrice_correlation"]:
            det = "✅ OUI" if m["detectee_par_nids"] else "❌ NON"
            trc = "✅ OUI" if m["trace_enregistree_honeypot"] else "⚠️  NON"
            lignes.append(f"  {m['attaque_pentest']:<20} | {m['alerte_nids_attendue']:<16} | {det:<10} | {trc}")
        lignes.append("=" * 68)

        return "\n".join(lignes)

    # ------------------------------------------------------------------
    # 7. Outils auxiliaires (synchronisation Docker et export)
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
    args = parser.parse_args()

    analyzer = LogAnalyzer(
        target_dir=args.target_dir,
        nids_alerts=args.nids_alerts,
        pentest_results=args.pentest_results,
    )

    if args.sync_docker:
        analyzer.synchroniser_depuis_docker()

    rapport = analyzer.generer_rapport()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(rapport, f, indent=2, ensure_ascii=False)
        print(f"[+] Rapport enregistré dans : {args.output}")

    if args.json:
        print(json.dumps(rapport, indent=2, ensure_ascii=False))
    else:
        print(analyzer.generer_synthese_texte(rapport))


if __name__ == "__main__":
    main()
