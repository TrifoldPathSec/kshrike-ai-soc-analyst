"""AI SOC analyst main loop.

Poll the Wazuh indexer for new high-severity alerts, correlate them into
cases, enrich, have Claude triage each case, write a Markdown report, and
(optionally) notify. State is kept in memory; on restart it resumes from
`now` so a backlog of old alerts isn't replayed.
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from datetime import datetime, timezone

from . import enrich, notify
from .config import Config
from .correlate import group
from .report import write_case
from .triage import Analyst
from .wazuh import WazuhIndexer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("soc.main")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _case_fingerprint(case: dict) -> str:
    """Stable id for a case *state* so we don't re-triage an unchanged group,
    but do re-triage when it grows (new alerts => new fingerprint)."""
    raw = f"{case['case_id']}:{case['alert_count']}:{case['max_rule_level']}"
    return hashlib.sha1(raw.encode()).hexdigest()


class RateLimiter:
    """At most `per_hour` triages in any rolling 60-minute window."""

    def __init__(self, per_hour: int):
        self.per_hour = per_hour
        self.calls: deque[float] = deque()

    def allow(self) -> bool:
        now = time.time()
        while self.calls and now - self.calls[0] > 3600:
            self.calls.popleft()
        if len(self.calls) >= self.per_hour:
            return False
        self.calls.append(now)
        return True


def enrich_case(case: dict, cfg: Config) -> dict:
    intel = {}
    for ip in case.get("source_ips", []):
        intel[ip] = enrich.abuseipdb(ip, cfg.abuseipdb_key)
    if intel:
        case["threat_intel"] = intel
    return case


def main() -> None:
    cfg = Config()
    cfg.require()

    indexer = WazuhIndexer(cfg.indexer_url, cfg.indexer_user, cfg.indexer_password, cfg.indexer_ca_cert)
    analyst = Analyst(cfg.anthropic_api_key, cfg.model, cfg.effort)
    limiter = RateLimiter(cfg.max_triages_per_hour)

    log.info("waiting for the Wazuh indexer at %s ...", cfg.indexer_url)
    while not indexer.ping():
        time.sleep(10)
    log.info("indexer is up. model=%s effort=%s min_level=%s", cfg.model, cfg.effort, cfg.min_rule_level)

    last_seen = _now_iso()          # only triage alerts newer than startup
    triaged: set[str] = set()       # case fingerprints already handled

    while True:
        try:
            alerts = indexer.fetch_alerts(last_seen, cfg.min_rule_level)
            if alerts:
                last_seen = alerts[-1].get("timestamp", last_seen)
                cases = group(alerts)
                log.info("%d new alert(s) -> %d case(s)", len(alerts), len(cases))

                for case_id, case in cases.items():
                    fp = _case_fingerprint(case)
                    if fp in triaged:
                        continue
                    if not limiter.allow():
                        log.warning("hourly triage cap reached; deferring case %s", case_id)
                        continue

                    case = enrich_case(case, cfg)
                    log.info("triaging case %s (%d alerts, level %s)",
                             case_id, case["alert_count"], case["max_rule_level"])
                    verdict = analyst.triage(case)
                    triaged.add(fp)

                    path = write_case(cfg.reports_dir, case_id, case, verdict)
                    sev = verdict.get("severity", "medium")
                    log.info("  -> %s / %s  report: %s",
                             sev, verdict.get("verdict"), path)

                    if sev in cfg.notify_severities:
                        notify.send(
                            cfg.notify_webhook,
                            f"{sev.upper()} [{verdict.get('verdict')}] "
                            f"{verdict.get('title')}\n{verdict.get('summary')}",
                        )
        except Exception as e:  # keep the loop alive; log and move on
            log.exception("poll cycle failed: %s", e)

        time.sleep(cfg.poll_interval)


if __name__ == "__main__":
    main()
