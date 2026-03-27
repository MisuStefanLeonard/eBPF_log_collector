#!/bin/bash
mkdir -p /tmp/bin

# Create a fake 'ls' command
echo "#!/bin/bash" > /tmp/bin/ls
echo "echo '[!] YOU HAVE BEEN HACKED'" >> /tmp/bin/ls
echo "/bin/ls \$@" >> /tmp/bin/ls # Runs the real ls so you don't notice immediately
chmod +x /tmp/bin/ls

# Modify the PATH variable for the current session
export PATH="/tmp/bin:$PATH"

# Now run 'ls' to see the effect
ls -la
