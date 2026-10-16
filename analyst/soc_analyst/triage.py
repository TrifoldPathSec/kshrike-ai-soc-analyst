"""The AI analyst: turn a group of Wazuh alerts + enrichment into a triage
verdict and an incident writeup, using Claude."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

import anthropic

log = logging.getLogger("soc.triage")

SYSTEM_PROMPT = """You are a Tier-1/Tier-2 SOC analyst working in a security \
homelab. You receive a group of related Wazuh alerts (already correlated by \
host, rule and source) plus any threat-intel enrichment, and you triage them.

Be concise, technical, and honest about uncertainty. Map behaviour to MITRE \
ATT&CK where you reasonably can. This is a controlled lab, so expect simulated \
attacks (SSH brute force, persistence, recon) as well as benign noise.

Respond with ONE JSON object and nothing else, matching exactly this shape:
{
  "title": "short incident title",
  "severity": "critical" | "high" | "medium" | "low" | "informational",
  "verdict": "true_positive" | "false_positive" | "benign" | "needs_review",
  "confidence": 0.0-1.0,
  "mitre": [{"tactic": "...", "technique_id": "T1110", "technique": "..."}],
  "summary": "2-4 sentences: what happened, on which host, from where",
  "evidence": ["concrete fields/values from the alerts that justify the verdict"],
  "recommended_actions": ["ordered, concrete next steps for a responder"]
}
Output valid JSON only. No markdown, no prose outside the object."""


def _extract_json(text: str) -> dict[str, Any]:
    """Claude is instructed to return bare JSON, but salvage a fenced or
    surrounded object just in case."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            return json.loads(text[start : end + 1])
        raise


class Analyst:
    def __init__(self, api_key: str, model: str, effort: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.effort = effort

    def triage(self, case: dict[str, Any]) -> dict[str, Any]:
        """`case` holds the grouped alerts and enrichment. Returns the parsed
        verdict dict, or a needs_review stub if the model's output won't parse."""
        user_content = (
            "Triage this alert group.\n\n```json\n"
            + json.dumps(case, indent=2, default=str)
            + "\n```"
        )
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )

        if response.stop_reason == "refusal":
            cat = getattr(response.stop_details, "category", None)
            log.warning("triage refused (category=%s)", cat)
            return _stub(f"Model declined to triage (category: {cat}).")

        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            verdict = _extract_json(text)
        except (json.JSONDecodeError, ValueError):
            log.warning("could not parse model output as JSON")
            return _stub("Model output was not valid JSON; raw text in evidence.", raw=text)

        verdict.setdefault("severity", "medium")
        verdict.setdefault("verdict", "needs_review")
        return verdict


def _stub(reason: str, raw: str = "") -> dict[str, Any]:
    return {
        "title": "Triage incomplete",
        "severity": "medium",
        "verdict": "needs_review",
        "confidence": 0.0,
        "mitre": [],
        "summary": reason,
        "evidence": [raw] if raw else [],
        "recommended_actions": ["Review the raw alerts manually."],
    }
