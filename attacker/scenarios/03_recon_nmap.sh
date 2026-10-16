#!/usr/bin/env bash
# Scenario 3: port/service recon against the victim (MITRE T1046).
# Generates connection noise; pair with the brute force to see the analyst
# correlate recon -> access attempts from the same source.
set -uo pipefail
TARGET="${1:-victim}"
echo "[*] Scanning ${TARGET}..."
nmap -sV -T4 -p 1-1024 "${TARGET}"
echo "[*] Done."
