#!/bin/bash
TARGET_DIR="/tmp/ransomware_test"
mkdir -p $TARGET_DIR

# 1. Creează fișiere "victimă"
echo "[*] Generating dummy files..."
for i in {1..20}; do
    echo "This is critical data $i" > "$TARGET_DIR/data_$i.txt"
done

# 2. Simulează criptarea (Arhivare + Ștergere)
echo "[*] Simulating encryption loop..."
find $TARGET_DIR -name "*.txt" | while read file; do
    # "Criptează" (Arhivează)
    tar -czf "${file}.enc" "$file" 2>/dev/null
    
    # Șterge originalul (Comportament distructiv specific ransomware)
    rm -f "$file"
    
    # Lasă un mesaj de răscumpărare
    touch "$TARGET_DIR/READ_ME_TO_DECRYPT.txt"
done

echo "[*] Attack finished. Check your logs for 'tar', 'rm', and 'find' spikes."
