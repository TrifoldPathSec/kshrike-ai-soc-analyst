# Attack box. Runs the lab scenarios in /scenarios against the victim.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        sshpass openssh-client hydra nmap curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
