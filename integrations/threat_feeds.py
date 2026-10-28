"""AbuseIPDB + GreyNoise IP reputation lookups with in-process TTL cache."""
from __future__ import annotations

import time

import httpx

from config import settings
from logger import get_logger

logger = get_logger("threat_feeds")


_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_GREYNOISE_URL_TMPL = "https://api.greynoise.io/v3/community/{ip}"

_cache: dict[str, tuple[float, dict]] = {}


def _cache_get(key: str) -> dict | None:
    entry = _cache.get(key)
    if not entry:
        return None
    ts, val = entry
    if time.time() - ts > settings.threat_feed_cache_ttl_seconds:
        _cache.pop(key, None)
        return None
    return val


def _cache_set(key: str, val: dict) -> None:
    _cache[key] = (time.time(), val)


async def check_ip_abuseipdb(ip: str) -> dict:
    key = settings.abuseipdb_api_key
    if not key:
        return {"skipped": True, "reason": "abuseipdb_api_key_not_set"}
    if settings.mock_mode:
        return {"skipped": True, "reason": "mock_mode"}
    ck = f"abuseipdb:{ip}"
    if (c := _cache_get(ck)) is not None:
        return c
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                _ABUSEIPDB_URL,
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            data = (resp.json() or {}).get("data", {})
        out = {
            "abuse_confidence": int(data.get("abuseConfidenceScore", 0) or 0),
            "is_public": bool(data.get("isPublic", False)),
            "country_code": data.get("countryCode") or "",
            "usage_type": data.get("usageType") or "",
            "reports": int(data.get("totalReports", 0) or 0),
        }
        _cache_set(ck, out)
        return out
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {"skipped": True, "reason": f"error: {e}"}


async def check_ip_greynoise(ip: str) -> dict:
    key = settings.greynoise_api_key
    if not key:
        return {"skipped": True, "reason": "greynoise_api_key_not_set"}
    if settings.mock_mode:
        return {"skipped": True, "reason": "mock_mode"}
    ck = f"greynoise:{ip}"
    if (c := _cache_get(ck)) is not None:
        return c
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                _GREYNOISE_URL_TMPL.format(ip=ip),
                headers={"key": key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json() or {}
        out = {
            "classification": data.get("classification") or "",
            "name": data.get("name") or "",
            "noise": bool(data.get("noise", False)),
            "riot": bool(data.get("riot", False)),
            "last_seen": data.get("last_seen") or "",
        }
        _cache_set(ck, out)
        return out
    except Exception as e:
        logger.warning(f"GreyNoise lookup failed for {ip}: {e}")
        return {"skipped": True, "reason": f"error: {e}"}


def _risk_score(abuse: dict, gn: dict) -> int:
    score = 0
    if not abuse.get("skipped"):
        score += min(int(abuse.get("abuse_confidence", 0)), 100)
        if abuse.get("reports", 0) > 10:
            score += 10
    if not gn.get("skipped"):
        cls = (gn.get("classification") or "").lower()
        if cls == "malicious":
            score += 60
        elif cls == "suspicious":
            score += 30
        elif cls == "benign":
            score -= 20
        if gn.get("noise"):
            score += 5
    return max(0, min(100, score))


async def lookup_ip(ip: str) -> dict:
    """Combine AbuseIPDB + GreyNoise into a merged reputation record."""
    abuse = await check_ip_abuseipdb(ip)
    gn = await check_ip_greynoise(ip)
    return {
        "ip": ip,
        "abuseipdb": abuse,
        "greynoise": gn,
        "risk_score": _risk_score(abuse, gn),
    }
