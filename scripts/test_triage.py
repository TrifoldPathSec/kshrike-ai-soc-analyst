#!/usr/bin/env python3
"""Offline test: run the analyst against a sample alert file, no Wazuh needed.

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python scripts/test_triage.py samples/bruteforce_alerts.json

With no API key it still exercises correlation and report rendering using a
canned verdict, so you can verify the pipeline before spending any tokens.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyst"))

from soc_analyst.correlate import group  # noqa: E402
from soc_analyst.report import write_case  # noqa: E402

CANNED = {
    "title": "SSH brute force with successful login",
    "severity": "high",
    "verdict": "true_positive",
    "confidence": 0.9,
    "mitre": [{"tactic": "Credential Access", "technique_id": "T1110.001", "technique": "Password Guessing"}],
    "summary": "(canned verdict - no ANTHROPIC_API_KEY set)",
    "evidence": ["rule 5712 brute force", "rule 5715 success from same srcip"],
    "recommended_actions": ["Reset the deploy account", "Block 203.0.113.47"],
}


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/bruteforce_alerts.json"
    alerts = json.load(open(path))
    cases = group(alerts)
    print(f"{len(alerts)} alerts -> {len(cases)} case(s)\n")

    use_claude = bool(os.environ.get("ANTHROPIC_API_KEY"))
    analyst = None
    if use_claude:
        from soc_analyst.triage import Analyst
        analyst = Analyst(
            os.environ["ANTHROPIC_API_KEY"],
            os.environ.get("CLAUDE_MODEL", "claude-opus-5-5"),
            os.environ.get("CLAUDE_EFFORT", "medium"),
        )

    for case_id, case in cases.items():
        verdict = analyst.triage(case) if analyst else CANNED
        out = write_case("reports", case_id, case, verdict)
        print(f"[{verdict['severity']}/{verdict['verdict']}] {verdict['title']}")
        print(f"  report: {out}\n")


if __name__ == "__main__":
    main()
