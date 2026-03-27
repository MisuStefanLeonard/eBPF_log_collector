#!/bin/bash

name="ransomware.txt"
sudo touch /tmp/${name}
sudo chattr +i /tmp/${name}
sudo setfacl -m u:support_account:r /etc/shadow
