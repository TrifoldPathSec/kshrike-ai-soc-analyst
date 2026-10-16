"""Post a short case summary to a Slack or Discord incoming webhook.

Both accept a JSON body with a top-level `text` / `content` field; we send
both keys so one URL works for either service."""
from __future__ import annotations

import logging

import requests

log = logging.getLogger("soc.notify")


def send(webhook_url: str, text: str) -> None:
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"text": text, "content": text}, timeout=10)
    except requests.RequestException as e:
        log.warning("notification failed: %s", e)
