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
                my %quarantined;
                if ($en && $c =~ /"quarantined_accounts"\s*:\s*\[([^\]]*)\]/s) {
                    my $accs = $1;
                    while ($accs =~ /"([^"]+)"/g) {
                        $quarantined{$1} = 1;
                    }
                }
                print "$en\n";
                for my $u ("msfadmin", "root", "user") {
                    my $q = $quarantined{$u} ? 1 : 0;
                    print "$u $q\n";
                }
            } else {
                print "0\n";
            }
        ' 2>/dev/null)

        ENABLED=$(echo "$STATUS_INFO" | head -n 1)

        echo "$STATUS_INFO" | tail -n +2 | while read -r ACC Q; do
            [ -z "$ACC" ] && continue
            CURRENT_STATUS=$(passwd -S "$ACC" 2>/dev/null | awk '{print $2}')

            if [ "$ENABLED" = "1" ] && [ "$Q" = "1" ]; then
                if [ "$CURRENT_STATUS" != "L" ]; then
                    passwd -l "$ACC" >/dev/null 2>&1
                    pkill -u "$ACC" -9 >/dev/null 2>&1
                    echo "[QUARANTINE AGENT] Compte $ACC verrouillé sur Metasploitable 2 (passwd -l)"
                fi
            else
                if [ "$CURRENT_STATUS" = "L" ]; then
                    passwd -u "$ACC" >/dev/null 2>&1
                    echo "[QUARANTINE AGENT] Compte $ACC déverrouillé sur Metasploitable 2 (passwd -u)"
                fi
            fi
        done
    fi
    sleep 1
done
