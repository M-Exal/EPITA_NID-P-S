#!/bin/sh
# Agent de quarantaine autonome sur Metasploitable 2
# Surveille /app/data/nips_state.json pour verrouiller/déverrouiller les comptes système sur la machine cible

STATE_FILE="/app/data/nips_state.json"

echo "[QUARANTINE AGENT] Démarrage du moniteur de quarantaine sur Metasploitable 2..."

while true; do
    if [ -f "$STATE_FILE" ]; then
        # Vérifier si nips est actif et si msfadmin est en quarantaine
        ENABLED=$(grep -o '"enabled": *true' "$STATE_FILE" 2>/dev/null)
        MSF_QUARANTINED=$(grep -o '"quarantined_accounts": *\[[^]]*"msfadmin"[^]]*\]' "$STATE_FILE" 2>/dev/null)

        if [ -n "$ENABLED" ] && [ -n "$MSF_QUARANTINED" ]; then
            # Compte sous quarantaine : verrouiller si ce n'est pas déjà fait
            STATUS=$(passwd -S msfadmin 2>/dev/null | awk '{print $2}')
            if [ "$STATUS" != "L" ]; then
                passwd -l msfadmin >/dev/null 2>&1
                pkill -u msfadmin -9 >/dev/null 2>&1
                echo "[QUARANTINE AGENT] Compte msfadmin verrouillé sur le système (passwd -l)"
            fi
        else
            # Compte hors quarantaine : déverrouiller si verrouillé
            STATUS=$(passwd -S msfadmin 2>/dev/null | awk '{print $2}')
            if [ "$STATUS" = "L" ]; then
                passwd -u msfadmin >/dev/null 2>&1
                echo "[QUARANTINE AGENT] Compte msfadmin déverrouillé sur le système (passwd -u)"
            fi
        fi

        # Même logique pour root
        ROOT_QUARANTINED=$(grep -o '"quarantined_accounts": *\[[^]]*"root"[^]]*\]' "$STATE_FILE" 2>/dev/null)
        if [ -n "$ENABLED" ] && [ -n "$ROOT_QUARANTINED" ]; then
            STATUS_ROOT=$(passwd -S root 2>/dev/null | awk '{print $2}')
            if [ "$STATUS_ROOT" != "L" ]; then
                passwd -l root >/dev/null 2>&1
            fi
        else
            STATUS_ROOT=$(passwd -S root 2>/dev/null | awk '{print $2}')
            if [ "$STATUS_ROOT" = "L" ]; then
                passwd -u root >/dev/null 2>&1
            fi
        fi
    fi
    sleep 1
done
