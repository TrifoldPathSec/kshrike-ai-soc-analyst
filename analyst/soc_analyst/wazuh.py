"""Read alerts from the Wazuh indexer (OpenSearch) REST API."""
from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger("soc.wazuh")


class WazuhIndexer:
    def __init__(self, url: str, user: str, password: str, ca_cert: str = ""):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers["Content-Type"] = "application/json"
        # Verify against the Wazuh root CA when mounted; otherwise fall back to
        # unverified TLS (self-signed lab certs) and silence the warning.
        if ca_cert:
            self.session.verify = ca_cert
        else:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    def ping(self) -> bool:
        try:
            r = self.session.get(f"{self.url}/_cluster/health", timeout=10)
            return r.ok
        except requests.RequestException as e:
            log.warning("indexer not reachable yet: %s", e)
            return False

    def fetch_alerts(self, after_iso: str, min_level: int, size: int = 200) -> list[dict[str, Any]]:
        """Return alerts newer than `after_iso` at or above `min_level`,
        oldest first so we process them in order."""
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {"timestamp": {"gt": after_iso}}},
                    ]
                }
            },
        }
        r = self.session.get(
            f"{self.url}/wazuh-alerts-*/_search",
            json=query,
            timeout=30,
        )
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
