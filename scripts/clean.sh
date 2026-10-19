#!/usr/bin/env bash
# ============================================================================
#  clean.sh — Nettoyage complet de la démonstration.
#
#    ./scripts/clean.sh          # arrête les conteneurs et vide data/
#    ./scripts/clean.sh --images  # supprime aussi les images construites
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Arrêt et suppression des conteneurs / réseaux du projet"
if [ "${1:-}" = "--images" ]; then
    docker compose down --rmi local --remove-orphans
else
    docker compose down --remove-orphans
fi

echo "==> Suppression des données générées (logs, alertes, analyses)"
rm -rf data/cowrie/log/* data/cowrie/dl/* data/nids/* data/pentest/* data/analysis/*
rm -f mail/secret.key nids/secret.key

echo "==> Nettoyage des traces Python / tests"
find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf .pytest_cache

echo "Terminé. Lancez ./scripts/demo.sh pour repartir de zéro."
