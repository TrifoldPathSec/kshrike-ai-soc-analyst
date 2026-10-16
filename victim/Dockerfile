# Deliberately weak Ubuntu endpoint, monitored by a Wazuh agent.
# It is only reachable on the lab's Docker network; no ports are published.
FROM ubuntu:24.04

ARG WAZUH_AGENT_VERSION=4.14.9-1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg openssh-server rsyslog sudo cron procps \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y "wazuh-agent=${WAZUH_AGENT_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

# rsyslog in a container can't read the kernel log, so disable imklog. The base
# config already routes auth/authpriv to /var/log/auth.log via imuxsock
# (/dev/log, the socket sshd logs through), so no extra rule is needed — the
# entrypoint just has to create auth.log owned by the `syslog` user rsyslog
# drops to, or rsyslog can't write it and the file stays empty.
RUN sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf

# Force the traditional syslog timestamp format so Wazuh can decode auth events
# (Ubuntu's default high-precision ISO8601 format is not parsed by Wazuh).
COPY rsyslog-traditional.conf /etc/rsyslog.d/01-traditional.conf

# Intentional weaknesses for the attack scenarios:
#   - password SSH logins allowed
#   - user "deploy" with a guessable password and passwordless sudo
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && useradd -m -s /bin/bash deploy \
    && echo 'deploy:Summer2024!' | chpasswd \
    && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy

COPY ossec-lab.conf /tmp/ossec-lab.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    # Extra agent config: auth.log collection and real-time file integrity monitoring.
    && cat /tmp/ossec-lab.conf >> /var/ossec/etc/ossec.conf \
    && rm /tmp/ossec-lab.conf

ENTRYPOINT ["/entrypoint.sh"]
