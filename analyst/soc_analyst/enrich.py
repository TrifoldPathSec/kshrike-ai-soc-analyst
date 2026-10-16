"""Optional threat-intel enrichment. Each lookup degrades gracefully: a
missing key or a failed request returns a note instead of raising, so the
analyst always gets *something* to reason about."""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

import requests

log = logging.getLogger("soc.enrich")


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"skipped": "no ABUSEIPDB_API_KEY"}
    if not _is_public_ip(ip):
        return {"note": f"{ip} is private/loopback; not checked"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def virustotal_hash(file_hash: str, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"skipped": "no VIRUSTOTAL_API_KEY"}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if r.status_code == 404:
            return {"note": "hash not found in VirusTotal"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"last_analysis_stats": stats}
    except (requests.RequestException, KeyError) as e:
        return {"error": str(e)}
