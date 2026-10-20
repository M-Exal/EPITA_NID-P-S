#!/usr/bin/env bash
# ============================================================================
#  demo.sh — Démonstration complète du projet, de bout en bout :
#    1. démarrage du honeypot (Cowrie) et du NIDS ;
#    2. lancement du pentest automatisé depuis le conteneur d'attaque ;
#    3. arrêt du NIDS (génération du rapport chiffré + envoi mail) ;
#    4. analyse des données du honeypot (graphiques + rapport) ;
#    5. affichage des résultats.
#
#  Usage :
#    ./scripts/demo.sh              # démonstration complète
#    ./scripts/demo.sh --sans-mail  # ignore l'envoi du rapport chiffré
#    ./scripts/demo.sh --arret      # ne fait que les étapes 3 à 5
#
#  Remarque : les journaux (honeypot, NIDS) s'accumulent d'une exécution à
#  l'autre ; lancez ./scripts/clean.sh avant pour repartir de zéro.
#
#  Pré-requis : Docker + Docker Compose ; un fichier .env renseigné si vous
#  voulez réellement recevoir le rapport chiffré par courriel.
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."   # racine du dépôt, quel que soit le lancement

SANS_MAIL=0
ARRET_SEUL=0
for arg in "$@"; do
    case "$arg" in
        --sans-mail) SANS_MAIL=1 ;;
        --arret)     ARRET_SEUL=1 ;;
        *) echo "Option inconnue : $arg" >&2; exit 2 ;;
    esac
done

etape() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# Cowrie s'exécute sous l'uid 999 : les dossiers montés doivent être
# inscriptibles, sinon l'écriture de cowrie.json échoue (PermissionError).
mkdir -p data/cowrie/log data/cowrie/dl data/nids data/pentest data/analysis
chmod 777 data/cowrie/log data/cowrie/dl

# ------------------------------------------------------------------ #
# Étapes 1 et 2 : honeypot + NIDS + attaques
# ------------------------------------------------------------------ #
if [ "$ARRET_SEUL" -eq 0 ]; then
    etape "Démarrage du honeypot (Cowrie) et du NIDS"
    # --force-recreate : repart d'un conteneur sain à chaque démonstration.
    docker compose up -d --build --force-recreate honeypot nids
    echo "Attente du démarrage de Cowrie (15 s)..."
    sleep 15
    docker compose ps

    etape "Démarrage du démon Metasploit (msfrpcd)"
    # msfrpcd met ~20-40 s à s'initialiser ; le pentest réessaie la connexion.
    docker compose --profile attaque up -d metasploit
    echo "Initialisation de Metasploit (25 s)..."
    sleep 25

    etape "Lancement du pentest automatisé (conteneur d'attaque)"
    docker compose run --rm --build pentest

    etape "Laisse le NIDS capter le trafic et Cowrie journaliser (15 s)"
    sleep 15

    # Le démon Metasploit n'est plus utile une fois le pentest terminé.
    docker compose stop metasploit 2>/dev/null || true
fi

# ------------------------------------------------------------------ #
# Étape 3 : arrêt du NIDS -> résumé + capture + rapport chiffré
# ------------------------------------------------------------------ #
etape "Arrêt du NIDS (résumé des alertes + rapport chiffré)"
if [ "$SANS_MAIL" -eq 1 ]; then
    # On désactive l'envoi mail en effaçant les identifiants SMTP.
    SMTP_USER= SMTP_PASSWORD= REPORT_RECEIVER= docker compose stop nids
else
    docker compose stop nids
fi

# ------------------------------------------------------------------ #
# Étape 4 : analyse des logs du honeypot (conteneur d'analyse)
# ------------------------------------------------------------------ #
etape "Analyse des données du honeypot (pandas + graphiques)"
docker compose run --rm --build analysis

# ------------------------------------------------------------------ #
# Étape 5 : affichage des résultats
# ------------------------------------------------------------------ #
etape "Résultats du pentest (data/pentest/pentest_results.json)"
if [ -f data/pentest/pentest_results.json ]; then
    cat data/pentest/pentest_results.json
else
    echo "Fichier absent : le pentest n'a pas été lancé (cf. --arret)."
fi

etape "Alertes du NIDS (data/nids/nids_alerts.log)"
if [ -f data/nids/nids_alerts.log ]; then
    cat data/nids/nids_alerts.log
else
    echo "Aucune alerte enregistrée."
fi

etape "Rapport d'analyse (data/analysis/rapport_analyse.txt)"
if [ -f data/analysis/rapport_analyse.txt ]; then
    cat data/analysis/rapport_analyse.txt
else
    echo "Rapport absent (voir le log de l'étape 4)."
fi

etape "Fichiers produits"
ls -l data/nids data/pentest data/analysis 2>/dev/null || true

cat <<'MSG'

Démonstration terminée.
  - Le NIDS a écrit ses alertes dans data/nids/ (journal .log et .json).
  - Le rapport chiffré (si .env renseigné) a été joint au courriel :
    déchiffrez-le avec  python3 mail/decrypt_report.py <fichier.enc>
  - Le honeypot a journalisé les attaques dans data/cowrie/log/cowrie.json.
MSG
