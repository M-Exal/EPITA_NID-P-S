#!/usr/bin/env python3
"""
Script standalone : Exécution complète et ordonnancée de la suite d'attaques de pentest
avec génération automatique du rapport forensique et d'audit chiffré à l'issue de la campagne.

Usage :
    python run_all_attacks.py [TARGET_HOST]
"""

import json
import os
import sys

# Forçage du line-buffering pour affichage temps réel dans le terminal web
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(REPO_ROOT, "pentest"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "pentest")),
    os.path.join(REPO_ROOT, "analysis"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "analysis")),
    os.path.join(REPO_ROOT, "mail"),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "mail")),
    "/app/pentest",
    "/app/analysis",
    "/app/mail",
]:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

if len(sys.argv) > 1:
    os.environ["TARGET_HOST"] = sys.argv[1]

try:
    from config import Config
    from pentest import Pentester
except ImportError:
    from pentest.config import Config
    from pentest.pentest import Pentester


def generer_rapport_fin_de_campagne():
    """Génère le rapport de synthèse forensique consolidé, l'enregistre et le chiffre."""
    print("\n" + "=" * 65, flush=True)
    print("  GÉNÉRATION DU RAPPORT FORENSIQUE & AUDIT DE DÉTECTION", flush=True)
    print("=" * 65, flush=True)

    try:
        from analyze import LogAnalyzer
    except ImportError:
        try:
            from analysis.analyze import LogAnalyzer
        except ImportError:
            print("[!] Module d'analyse forensique introuvable.", file=sys.stderr, flush=True)
            return

    # Recherche des emplacements des données
    candidats_nids = [
        os.getenv("NIDS_ALERT_JSON"),
        os.path.join(REPO_ROOT, "data", "nids", "nids_alerts.json"),
        "/app/data/nids_alerts.json",
        "/tmp/nids_alerts.json",
    ]
    nids_alerts = next((p for p in candidats_nids if p and os.path.isfile(p)), None)

    candidats_pentest = [
        os.getenv("PENTEST_RESULTS_JSON"),
        os.path.join(REPO_ROOT, "data", "pentest", "pentest_results.json"),
        os.path.join(REPO_ROOT, "data", "nids", "pentest_results.json"),
        "/app/data/pentest/pentest_results.json",
        "/app/data/pentest_results.json",
        "/tmp/pentest_results.json",
    ]
    pentest_results = next((p for p in candidats_pentest if p and os.path.isfile(p)), None)

    candidats_logs = [
        os.getenv("METASPLOITABLE_LOG_DIR"),
        os.path.join(REPO_ROOT, "data", "metasploitable", "log"),
        "/app/data/metasploitable_logs",
        "/tmp/metasploitable_logs",
    ]
    target_dir = next((p for p in candidats_logs if p and os.path.isdir(p)), None)

    try:
        analyzer = LogAnalyzer(
            target_dir=target_dir,
            nids_alerts=nids_alerts,
            pentest_results=pentest_results,
        )
        rapport_json = analyzer.generer_rapport()
        synthese_txt = analyzer.generer_synthese_texte(rapport_json)

        # Affichage direct dans le terminal
        print(synthese_txt, flush=True)

        # Sauvegarde des rapports sur disque
        dossiers_sauvegarde = [
            os.path.join(REPO_ROOT, "data", "nids"),
            os.path.join(REPO_ROOT, "data", "pentest"),
            "/app/data",
            "/tmp",
        ]

        rapport_txt_path = None
        rapport_json_path = None

        for d in dossiers_sauvegarde:
            if not os.path.isdir(d):
                continue
            try:
                p_txt = os.path.join(d, "rapport_forensique.txt")
                p_json = os.path.join(d, "rapport_forensique.json")
                with open(p_txt, "w", encoding="utf-8") as f:
                    f.write(synthese_txt)
                with open(p_json, "w", encoding="utf-8") as f:
                    json.dump(rapport_json, f, indent=2, ensure_ascii=False)
                if not rapport_txt_path:
                    rapport_txt_path = p_txt
                    rapport_json_path = p_json
                print(f"[+] Rapport texte sauvegardé : {p_txt}", flush=True)
                print(f"[+] Rapport JSON sauvegardé : {p_json}", flush=True)
                break
            except (OSError, PermissionError):
                continue

        # Chiffrement Fernet du rapport
        cle_chargee = None
        candidats_cle = [
            os.getenv("NIDS_KEY_FILE"),
            os.path.join(REPO_ROOT, "data", "nids", "secret.key"),
            "/app/data/secret.key",
            "/tmp/secret.key",
        ]
        cle_path = next((p for p in candidats_cle if p and os.path.isfile(p)), None)

        try:
            from crypto_utils import charger_ou_creer_cle, chiffrer_fichier
        except ImportError:
            try:
                from mail.crypto_utils import charger_ou_creer_cle, chiffrer_fichier
            except ImportError:
                charger_ou_creer_cle, chiffrer_fichier = None, None

        fichier_chiffre = None
        if charger_ou_creer_cle and chiffrer_fichier and rapport_txt_path:
            try:
                if cle_path and os.path.isfile(cle_path):
                    cle_chargee = charger_ou_creer_cle(cle_path)
                else:
                    cible_cle = os.path.join(REPO_ROOT, "data", "nids", "secret.key")
                    cle_chargee = charger_ou_creer_cle(cible_cle)

                dossier_enc = os.path.dirname(rapport_txt_path)
                fichier_chiffre = os.path.join(dossier_enc, "nids_alerts.enc")
                taille = chiffrer_fichier(rapport_txt_path, fichier_chiffre, cle_chargee)
                print(f"[+] Rapport chiffré Fernet (AES-128+HMAC) généré : {fichier_chiffre} ({taille} octets)", flush=True)
            except Exception as e_enc:
                print(f"[!] Erreur de chiffrement du rapport : {e_enc}", flush=True)

        # Expédition par mail si SMTP configuré
        smtp_user = os.getenv("SMTP_USER", "")
        report_receiver = os.getenv("REPORT_RECEIVER", "")
        if smtp_user and report_receiver and fichier_chiffre and os.path.isfile(fichier_chiffre):
            try:
                from send_report import envoyer_rapport_chiffre

                class EmailCfg:
                    ENCRYPTED_REPORT = fichier_chiffre
                    REPORT_SENDER = os.getenv("REPORT_SENDER", smtp_user)
                    REPORT_RECEIVER = report_receiver
                    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
                    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
                    SMTP_USER = smtp_user
                    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

                print(f"[*] Tentative d'envoi du rapport chiffré à {report_receiver} via SMTP...", flush=True)
                envoyer_rapport_chiffre(EmailCfg)
            except Exception as e_mail:
                print(f"[!] Erreur lors de l'envoi du mail de rapport : {e_mail}", flush=True)
        else:
            print("[i] Envoi de mail désactivé ou non configuré dans .env (SMTP_USER / REPORT_RECEIVER manquants).", flush=True)
            print("    Le rapport chiffré reste consultable et déchiffrable via mail/decrypt_report.py.", flush=True)

    except Exception as exc:
        print(f"[!] Erreur lors de la génération du rapport forensique : {exc}", file=sys.stderr, flush=True)


def main():
    cible = os.getenv("TARGET_HOST", Config.TARGET_HOST)
    print(f"[*] Cible : {cible}", flush=True)
    print(f"[*] Démarrage suite de Pentest automatisée — Ordre méthodologique :", flush=True)
    print("    1. Scan furtif NULL (RFC 793) & OS Fingerprinting")
    print("    2. Scan furtif XMAS (Flags FIN+PSH+URG)")
    print("    3. Scan TCP Connect & Banner Grabbing")
    print("    4. Brute-force SSH (Dictionnaire)")
    print("    5. Injection SQL (DVWA / Mutillidae)")
    print("    6. Cross-Site Scripting XSS (DVWA)")
    print("    7. Traversée de répertoire Path Traversal (/etc/passwd)")
    print("    8. Déni de Service DoS Flood (Volumétrie)")
    print("    9. Génération automatique du rapport d'audit forensique")
    print("-" * 65, flush=True)

    pentester = Pentester(cfg=Config)

    try:
        pentester.run_all()
    except Exception as exc:
        print(f"[!] Erreur critique lors de la suite de pentest : {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

    generer_rapport_fin_de_campagne()
    print("=" * 65, flush=True)
    print("[*] Séquence complète et rapport final terminés.", flush=True)
    print("=" * 65, flush=True)


if __name__ == "__main__":
    main()
