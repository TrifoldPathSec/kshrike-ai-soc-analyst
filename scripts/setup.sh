#!/usr/bin/env bash
# One-time setup: fetch Wazuh, generate its TLS certs, create .env.
set -euo pipefail
cd "$(dirname "$0")/.."

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.9}"

command -v docker >/dev/null || { echo "Docker is not installed. Install it first (Linux: https://docs.docker.com/engine/install/ubuntu/)."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running, or your user lacks access. Start the daemon / add yourself to the 'docker' group and re-run."; exit 1; }

# The Wazuh indexer (OpenSearch) needs a higher mmap limit. On a Linux host
# this must be set; Docker Desktop on macOS handles it inside its own VM.
if [ "$(uname -s)" = "Linux" ]; then
  current="$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)"
  if [ "$current" -lt 262144 ]; then
    echo "==> Raising vm.max_map_count to 262144 (needs sudo)"
    sudo sysctl -w vm.max_map_count=262144
    echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
  fi
fi

if [ ! -d wazuh-docker ]; then
  echo "==> Cloning wazuh-docker ${WAZUH_VERSION}"
  git clone --depth 1 --branch "${WAZUH_VERSION}" https://github.com/wazuh/wazuh-docker.git
fi

if [ ! -f wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  echo "==> Generating Wazuh indexer certificates"
  docker compose -f wazuh-docker/single-node/generate-indexer-certs.yml run --rm generator
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env: add your ANTHROPIC_API_KEY before starting the lab."
fi

mkdir -p reports
echo "==> Setup done. Next: edit .env, then run: docker compose up -d --build"
