"""Group raw Wazuh alerts into cases so the analyst triages an incident once,
not every repeated failed-login line separately."""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def _source_ip(alert: dict[str, Any]) -> str:
    data = alert.get("data", {})
    return data.get("srcip") or data.get("src_ip") or "n/a"


def group(alerts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return {case_id: case} keyed by (agent, rule group, source IP).

    A case bundles the matching alerts and pulls out the fields the analyst
    and report need up front."""
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for a in alerts:
        agent = a.get("agent", {}).get("name", "unknown")
        # Group by the rule's first ATT&CK-ish group when present, else rule id,
        # so related rules (e.g. the brute-force chain) land in one case.
        groups = a.get("rule", {}).get("groups", []) or [a.get("rule", {}).get("id", "?")]
        key = (agent, groups[0], _source_ip(a))
        buckets[key].append(a)

    cases: dict[str, dict[str, Any]] = {}
    for (agent, grp, srcip), items in buckets.items():
        case_id = f"{agent}-{grp}-{srcip}".replace("/", "_").replace(" ", "_")
        rules = sorted({str(i.get("rule", {}).get("id")) for i in items})
        descriptions = sorted({i.get("rule", {}).get("description", "") for i in items})
        max_level = max(i.get("rule", {}).get("level", 0) for i in items)
        cases[case_id] = {
            "case_id": case_id,
            "agents": [agent],
            "group": grp,
            "source_ips": [srcip] if srcip != "n/a" else [],
            "rules": rules,
            "rule_descriptions": descriptions,
            "max_rule_level": max_level,
            "alert_count": len(items),
            # Cap the raw alerts we send to the model to keep tokens bounded.
            "alerts": items[:25],
        }
    return cases
