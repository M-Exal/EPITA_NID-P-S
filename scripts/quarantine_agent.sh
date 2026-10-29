#!/bin/sh
# Agent de quarantaine autonome sur Metasploitable 2
# Surveille /app/data/nips_state.json pour verrouiller/déverrouiller les comptes système sur la machine cible

STATE_FILE="/app/data/nips_state.json"

echo "[QUARANTINE AGENT] Démarrage du moniteur de quarantaine sur Metasploitable 2..."

while true; do
    if [ -f "$STATE_FILE" ]; then
        STATUS_INFO=$(perl -e '
            local $/;
            if (open(my $f, "<", "'"$STATE_FILE"'")) {
                my $c = <$f>;
                my $en = ($c =~ /"enabled"\s*:\s*true/i) ? 1 : 0;
                my $msf = 0;
                if ($en && $c =~ /"quarantined_accounts"\s*:\s*\[([^\]]*)\]/s) {
                    my $accs = $1;
                    $msf = ($accs =~ /"msfadmin"/i) ? 1 : 0;
                }
                print "$en $msf\n";
            } else {
                print "0 0\n";
            }
        ' 2>/dev/null)

        ENABLED=$(echo "$STATUS_INFO" | awk '{print $1}')
        MSF_QUARANTINED=$(echo "$STATUS_INFO" | awk '{print $2}')
        CURRENT_STATUS=$(passwd -S msfadmin 2>/dev/null | awk '{print $2}')

        if [ "$ENABLED" = "1" ] && [ "$MSF_QUARANTINED" = "1" ]; then
            if [ "$CURRENT_STATUS" != "L" ]; then
                passwd -l msfadmin >/dev/null 2>&1
                pkill -u msfadmin -9 >/dev/null 2>&1
                echo "[QUARANTINE AGENT] Compte msfadmin verrouillé sur Metasploitable 2 (passwd -l)"
            fi
        else
            if [ "$CURRENT_STATUS" = "L" ]; then
                passwd -u msfadmin >/dev/null 2>&1
                echo "[QUARANTINE AGENT] Compte msfadmin déverrouillé sur Metasploitable 2 (passwd -u)"
            fi
        fi
    fi
    sleep 1
done
