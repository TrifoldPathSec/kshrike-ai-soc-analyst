"""Write each triaged case to a Markdown report on disk."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


def write_case(reports_dir: str, case_id: str, case: dict[str, Any], verdict: dict[str, Any]) -> str:
    os.makedirs(reports_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sev = verdict.get("severity", "medium")
    path = os.path.join(reports_dir, f"{ts}_{sev}_{case_id}.md")

    mitre_lines = "\n".join(
        f"- `{m.get('technique_id', '?')}` {m.get('technique', '')} "
        f"({m.get('tactic', '')})"
        for m in verdict.get("mitre", [])
    ) or "- (none mapped)"
    evidence = "\n".join(f"- {e}" for e in verdict.get("evidence", [])) or "- (none)"
    actions = "\n".join(f"{i}. {a}" for i, a in enumerate(verdict.get("recommended_actions", []), 1)) or "1. (none)"

    body = f"""# {_SEV_EMOJI.get(sev, '')} {verdict.get('title', 'Untitled case')}

**Case ID:** `{case_id}`
**Generated:** {datetime.now(timezone.utc).isoformat()}
**Severity:** {sev}  |  **Verdict:** {verdict.get('verdict')}  |  **Confidence:** {verdict.get('confidence')}

## Summary
{verdict.get('summary', '')}

## MITRE ATT&CK
{mitre_lines}

## Evidence
{evidence}

## Recommended actions
{actions}

## Case context
- **Host(s):** {', '.join(case.get('agents', [])) or 'unknown'}
- **Source IP(s):** {', '.join(case.get('source_ips', [])) or 'n/a'}
- **Alert count:** {case.get('alert_count')}
- **Rule(s):** {', '.join(case.get('rules', []))}

<details><summary>Raw alert group (JSON)</summary>

```json
{json.dumps(case, indent=2, default=str)}
```
</details>
"""
    with open(path, "w") as f:
        f.write(body)
    return path
