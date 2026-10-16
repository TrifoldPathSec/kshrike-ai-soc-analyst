#!/usr/bin/env bash
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER must be set}"

# Point the agent at the manager (the agent registers under its hostname).
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|" /var/ossec/etc/ossec.conf

# Pre-create auth.log owned by the `syslog` user that rsyslog drops privileges
# to — otherwise a root-owned file is not writable by rsyslog and every SSH
# auth event is silently dropped. Creating it up front also avoids a
# logcollector "file not found" race on a fresh container.
install -o syslog -g adm -m 0640 /dev/null /var/log/auth.log 2>/dev/null \
    || { touch /var/log/auth.log; chmod 0666 /var/log/auth.log; }

# Start rsyslog before sshd so the /dev/log socket exists when sshd logs to it.
rm -f /run/rsyslogd.pid
service rsyslog start 2>/dev/null || /usr/sbin/rsyslogd
sleep 2

mkdir -p /run/sshd
/usr/sbin/sshd

# Start the Wazuh agent.
/var/ossec/bin/wazuh-control start

# Tail the agent log so the container stays up and `docker logs` is useful.
touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log /var/log/auth.log
