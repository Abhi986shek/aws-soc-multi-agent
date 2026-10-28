"""
Threat Feed Lookup Tool
Checks events against threat intelligence feeds and known attack patterns.
"""

import asyncio
import re

from strands import tool
from datetime import datetime, timezone

from logger import get_logger

logger = get_logger("threat_feed_lookup")

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _collect_ips(indicators) -> list[str]:
    """Best-effort scrape of IPv4 strings from `indicators`."""
    found: set[str] = set()
    def walk(obj):
        if isinstance(obj, str):
            for tok in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", obj):
                found.add(tok)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                walk(v)
    walk(indicators)
    return sorted(found)


def _run_feeds(ips: list[str]) -> list[dict]:
    if not ips:
        return []
    try:
        from integrations.threat_feeds import lookup_ip
    except Exception as e:
        logger.warning(f"threat_feeds module unavailable: {e}")
        return []

    async def _gather():
        return await asyncio.gather(*(lookup_ip(ip) for ip in ips), return_exceptions=True)

    try:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't await here; skip external calls in a running loop
                return []
        except RuntimeError:
            pass
        results = asyncio.run(_gather())
    except Exception as e:
        logger.warning(f"threat feed lookup failed: {e}")
        return []
    return [r for r in results if isinstance(r, dict)]


@tool
def lookup_threat_intelligence(indicators: dict, event_metadata: dict) -> dict:
    """Look up indicators against threat intelligence feeds and databases."""
    threat_database = {
        "known_insider_patterns": [
            {
                "pattern_id": "INS-001",
                "name": "Insider Exfiltration Pattern",
                "indicators": ["large_data_transfer", "off_hours", "log_tampering"],
                "confidence": 0.85,
                "description": "Classic insider threat exfiltration sequence",
            },
            {
                "pattern_id": "INS-002",
                "name": "Privilege Escalation + Data Access",
                "indicators": ["permission_change", "new_resource_access", "bulk_download"],
                "confidence": 0.78,
                "description": "Unauthorized privilege escalation followed by data access",
            },
        ],
        "suspicious_behaviors": {
            "off_hours_access": {"risk_score": 0.6, "category": "temporal_anomaly"},
            "new_device": {"risk_score": 0.5, "category": "access_anomaly"},
            "log_tampering": {"risk_score": 0.9, "category": "anti_forensics"},
            "bulk_download": {"risk_score": 0.8, "category": "data_exfiltration"},
            "policy_modification": {"risk_score": 0.7, "category": "persistence"},
        },
    }

    matches = []
    total_risk_score = 0.0
    matched_categories = set()

    for pattern in threat_database["known_insider_patterns"]:
        pattern_match_count = sum(
            1 for indicator in pattern["indicators"] if indicator in str(indicators)
        )
        if pattern_match_count >= 2:
            matches.append({
                "pattern_id": pattern["pattern_id"],
                "pattern_name": pattern["name"],
                "confidence": pattern["confidence"],
                "matched_indicators": pattern_match_count,
                "description": pattern["description"],
            })

    behavior_scores = []
    for behavior, details in threat_database["suspicious_behaviors"].items():
        if behavior in str(indicators):
            behavior_scores.append({
                "behavior": behavior,
                "risk_score": details["risk_score"],
                "category": details["category"],
            })
            total_risk_score += details["risk_score"]
            matched_categories.add(details["category"])

    ti_confidence = _calculate_ti_confidence(matches, behavior_scores)

    # Enrich with real threat feeds for any IPv4 indicators
    ips = _collect_ips(indicators) + _collect_ips(event_metadata)
    feed_results = _run_feeds(sorted(set(ips)))
    if feed_results:
        max_ip_risk = max((f.get("risk_score", 0) or 0) for f in feed_results)
        total_risk_score += max_ip_risk / 100.0
        ti_confidence = min(1.0, ti_confidence + (max_ip_risk / 200.0))

    return {
        "matched_patterns": matches,
        "suspicious_behaviors": behavior_scores,
        "threat_categories": list(matched_categories),
        "total_risk_score": min(total_risk_score, 1.0),
        "ti_confidence": ti_confidence,
        "threat_level": _determine_threat_level(ti_confidence),
        "ip_reputation": feed_results,
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


def _calculate_ti_confidence(patterns: list, behaviors: list) -> float:
    if not patterns and not behaviors:
        return 0.0
    pattern_confidence = max([p["confidence"] for p in patterns], default=0.0)
    behavior_confidence = (
        sum([b["risk_score"] for b in behaviors]) / len(behaviors) if behaviors else 0.0
    )
    if patterns:
        return (pattern_confidence * 0.7) + (behavior_confidence * 0.3)
    return behavior_confidence * 0.8


def _determine_threat_level(confidence: float) -> str:
    if confidence >= 0.8:
        return "Critical"
    if confidence >= 0.6:
        return "High"
    if confidence >= 0.4:
        return "Medium"
    return "Low"
