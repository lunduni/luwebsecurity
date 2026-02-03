#!/bin/bash
# Minimalist Nmap Recon for Shark Jack

# 1. Start Up (Magenta LED)
LED SETUP
NETMODE DHCP

# 2. Wait for IP (Blinks Yellow until connected)
while [ -z "$(ip addr show eth0 | grep 'inet ')" ]; do
    LED Y SOLID; sleep 0.5; LED OFF; sleep 0.5
done

# 3. Target Discovery
# Grabs your IP, trims it to find the subnet (e.g., 192.168.1.0/24)
INTERNAL_IP=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
SUBNET=$(echo $INTERNAL_IP | cut -d"." -f1-3)".0/24"

# 4. The Scan (Yellow LED)
LED ATTACK
LOOT_FILE="/root/loot/scan_$(date +%s).txt"
mkdir -p /root/loot

# Performs a fast "Ping Scan" and saves to the file
nmap -sn "$SUBNET" > "$LOOT_FILE"

# 5. Done (Green LED)
LED FINISH