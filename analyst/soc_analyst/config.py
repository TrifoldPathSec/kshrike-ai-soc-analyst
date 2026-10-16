"""Configuration, read once from the environment at startup."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _list(name: str) -> list[str]:
    return [p.strip() for p in os.environ.get(name, "").split(",") if p.strip()]


@dataclass(frozen=True)
class Config:
    # Claude
    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    model: str = field(default_factory=lambda: os.environ.get("CLAUDE_MODEL", "claude-opus-5-5"))
    effort: str = field(default_factory=lambda: os.environ.get("CLAUDE_EFFORT", "medium"))

    # Wazuh indexer
    indexer_url: str = field(default_factory=lambda: os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200"))
    indexer_user: str = field(default_factory=lambda: os.environ.get("INDEXER_USER", "admin"))
    indexer_password: str = field(default_factory=lambda: os.environ.get("INDEXER_PASSWORD", "SecretPassword"))
    indexer_ca_cert: str = field(default_factory=lambda: os.environ.get("INDEXER_CA_CERT", ""))

    # Triage policy
    min_rule_level: int = field(default_factory=lambda: _int("MIN_RULE_LEVEL", 7))
    poll_interval: int = field(default_factory=lambda: _int("POLL_INTERVAL_SECONDS", 30))
    group_window_minutes: int = field(default_factory=lambda: _int("GROUP_WINDOW_MINUTES", 15))
    max_triages_per_hour: int = field(default_factory=lambda: _int("MAX_TRIAGES_PER_HOUR", 20))

    # Enrichment
    abuseipdb_key: str = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", ""))
    virustotal_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))

    # Notifications
    notify_webhook: str = field(default_factory=lambda: os.environ.get("NOTIFY_WEBHOOK_URL", ""))
    notify_severities: list[str] = field(default_factory=lambda: _list("NOTIFY_SEVERITIES") or ["critical", "high"])

    # Output
    reports_dir: str = field(default_factory=lambda: os.environ.get("REPORTS_DIR", "/app/reports"))

    def require(self) -> None:
        if not self.anthropic_api_key:
            raise SystemExit("ANTHROPIC_API_KEY is not set. Add it to .env.")
