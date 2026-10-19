"""
Analyse consolidée des logs du Honeypot (Cowrie) et des alertes du NIDS.

Permet de générer des métriques et des visualisations pour la soutenance.
"""

import argparse
import json
import os
from collections import Counter
from datetime import datetime


class LogAnalyzer:
    def __init__(self, cowrie_dir=None, nids_alerts=None):
        self.cowrie_dir = cowrie_dir
        self.nids_alerts = nids_alerts

    def analyser_alertes_nids(self):
        """Parse le fichier JSON des alertes NIDS."""
        if not self.nids_alerts or not os.path.exists(self.nids_alerts):
            return {"total": 0, "types": {}, "top_sources": {}}

        with open(self.nids_alerts, "r", encoding="utf-8") as f:
            try:
                alertes = json.load(f)
            except json.JSONDecodeError:
                alertes = []

        types = Counter(a.get("type", "INCONNU") for a in alertes)
        sources = Counter(a.get("src_ip", "INCONNU") for a in alertes)

        return {
            "total": len(alertes),
            "types": dict(types),
            "top_sources": dict(sources.most_common(5)),
        }

    def analyser_logs_cowrie(self):
        """Parse les journaux JSON émis par Cowrie (cowrie.json)."""
        stats = {
            "total_evenements": 0,
            "sessions": 0,
            "logins_echoues": 0,
            "logins_reussis": 0,
            "commandes_executees": [],
            "top_identifiants": Counter(),
            "top_ips": Counter(),
        }

        if not self.cowrie_dir or not os.path.exists(self.cowrie_dir):
            return stats

        fichier_log = os.path.join(self.cowrie_dir, "cowrie.json")
        if not os.path.exists(fichier_log):
            return stats

        with open(fichier_log, "r", encoding="utf-8") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    evt = json.loads(ligne)
                except json.JSONDecodeError:
                    continue

                stats["total_evenements"] += 1
                event_id = evt.get("eventid", "")
                src_ip = evt.get("src_ip", "")
                if src_ip:
                    stats["top_ips"][src_ip] += 1

                if event_id == "cowrie.session.connect":
                    stats["sessions"] += 1
                elif event_id == "cowrie.login.failed":
                    stats["logins_echoues"] += 1
                    user = evt.get("username", "")
                    pwd = evt.get("password", "")
                    stats["top_identifiants"][f"{user}:{pwd}"] += 1
                elif event_id == "cowrie.login.success":
                    stats["logins_reussis"] += 1
                    user = evt.get("username", "")
                    pwd = evt.get("password", "")
                    stats["top_identifiants"][f"{user}:{pwd}"] += 1
                elif event_id == "cowrie.command.input":
                    cmd = evt.get("input", "")
                    if cmd:
                        stats["commandes_executees"].append(cmd)

        stats["top_identifiants"] = dict(stats["top_identifiants"].most_common(5))
        stats["top_ips"] = dict(stats["top_ips"].most_common(5))
        return stats

    def generer_rapport(self):
        """Génère un rapport textuel et statistique complet."""
        nids_stats = self.analyser_alertes_nids()
        cowrie_stats = self.analyser_logs_cowrie()

        rapport = {
            "date_analyse": datetime.now().isoformat(timespec="seconds"),
            "nids": nids_stats,
            "cowrie": cowrie_stats,
        }
        return rapport


def main():
    parser = argparse.ArgumentParser(description="Analyse des logs Honeypot et NIDS.")
    parser.add_argument("--cowrie-dir", default="./data/cowrie/log", help="Dossier des logs Cowrie")
    parser.add_argument("--nids-alerts", default="./data/nids/nids_alerts.json", help="Fichier nids_alerts.json")
    parser.add_argument("--json", action="store_true", help="Sortie brute JSON")
    args = parser.parse_args()

    analyzer = LogAnalyzer(cowrie_dir=args.cowrie_dir, nids_alerts=args.nids_alerts)
    rapport = analyzer.generer_rapport()

    if args.json:
        print(json.dumps(rapport, indent=2, ensure_ascii=False))
    else:
        print("=" * 60)
        print("  RAPPORT D'ANALYSE SÉCURITÉ CONSOLIDÉ")
        print("=" * 60)
        print(f"Total alertes NIDS : {rapport['nids']['total']}")
        print(f"Répartition par type : {rapport['nids']['types']}")
        print(f"Top sources malveillantes : {rapport['nids']['top_sources']}")
        print("-" * 60)
        print(f"Sessions Cowrie ouvertes : {rapport['cowrie']['sessions']}")
        print(f"Logins réussis : {rapport['cowrie']['logins_reussis']} | Échecs : {rapport['cowrie']['logins_echoues']}")
        print(f"Commandes saisies par attaquants : {len(rapport['cowrie']['commandes_executees'])}")


if __name__ == "__main__":
    main()
