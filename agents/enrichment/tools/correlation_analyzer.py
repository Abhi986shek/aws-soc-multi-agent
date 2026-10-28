"""
Correlation Analysis Tool
Analyzes CloudTrail events for correlated threat patterns.
"""

from datetime import datetime, time
from typing import Dict, Any
from strands import tool
from logger import get_logger
from integrations.redis_store import get_recent_by_principal_sync

logger = get_logger("correlation_analyzer")

OFF_HOURS_START = time(0, 0)
OFF_HOURS_END = time(8, 0)


@tool
def is_off_hours_access(event_time_iso: str) -> bool:
    """
    Check if event occurred during off-hours (midnight to 8 AM).

    Args:
        event_time_iso: ISO format timestamp string

    Returns:
        True if event is during off-hours, False otherwise
    """
    try:
        dt = datetime.fromisoformat(event_time_iso.replace("Z", "+00:00"))
        t = dt.time()
        result = OFF_HOURS_START <= t < OFF_HOURS_END
        logger.debug(f"Time {t} is {'OFF-HOURS' if result else 'NORMAL-HOURS'}")
        return result
    except Exception as e:
        logger.error(f"Error parsing time {event_time_iso}: {e}")
        return False


@tool
def parse_event_signals(event: dict) -> dict:
    """
    Parse a CloudTrail event and extract threat signals.

    Detects:
    1. large_s3_download
    2. off_hours_access
    3. log_tampering_attempt
    4. new_s3_policy_edits
    """
    signals = {
        "large_s3_download": {"present": False, "details": ""},
        "off_hours_access": {"present": False, "details": ""},
        "log_tampering_attempt": {"present": False, "details": ""},
        "new_s3_policy_edits": {"present": False, "details": ""},
        "history": {"present": False, "details": "", "count": 0},
    }

    # Pull rolling-window history for this principal (last hour) so we can see
    # activity beyond the current 5-event batch.
    principal_arn = (event.get("userIdentity") or {}).get("arn", "")
    history = get_recent_by_principal_sync(principal_arn) if principal_arn else []
    history_count = len(history)

    event_source = event.get("eventSource", event.get("event_source", ""))
    event_name = event.get("eventName", event.get("event_name", event.get("action", "")))
    event_time = event.get("eventTime", event.get("event_time", event.get("timestamp", "")))

    is_get_object = (
        (event_source == "s3.amazonaws.com" and event_name == "GetObject")
        or event_name in ("s3:GetObject", "GetObject")
    )
    if is_get_object:
        # Count how many S3 GetObject calls the same principal has made in the
        # rolling window - a burst is much stronger evidence than a single call.
        prior_downloads = sum(
            1 for h in history
            if h.get("eventName") in ("GetObject", "s3:GetObject")
        )
        signals["large_s3_download"] = {
            "present": True,
            "details": (
                f"S3 GetObject detected: {event_name}; "
                f"{prior_downloads} prior downloads by same principal in window"
            ),
        }

    if event_time and is_off_hours_access(event_time):
        # Compare against principal's history: off-hours access is more
        # suspicious if the principal usually operates in business hours.
        prior_off_hours = sum(
            1 for h in history
            if is_off_hours_access(h.get("eventTime") or h.get("timestamp") or "")
        )
        prior_normal = history_count - prior_off_hours
        signals["off_hours_access"] = {
            "present": True,
            "details": (
                f"Off-hours activity at {event_time}; "
                f"principal history: {prior_off_hours} off-hours vs "
                f"{prior_normal} normal-hours events"
            ),
        }

    tampering_actions = [
        "DeleteTrailEvent", "DeleteTrail", "StopLogging", "DeleteEventDataStore",
        "cloudtrail:DeleteTrailEvent", "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging", "cloudtrail:DeleteEventDataStore",
    ]
    if (event_source == "cloudtrail.amazonaws.com" and event_name in tampering_actions) or \
       (event_name in tampering_actions):
        signals["log_tampering_attempt"] = {
            "present": True,
            "details": f"CloudTrail tampering: {event_name}",
        }

    policy_actions = [
        "PutBucketPolicy", "PutBucketAcl",
        "s3:PutBucketPolicy", "s3:PutBucketAcl",
    ]
    if (event_source == "s3.amazonaws.com" and event_name in policy_actions) or \
       (event_name in policy_actions):
        signals["new_s3_policy_edits"] = {
            "present": True,
            "details": f"S3 policy change: {event_name}",
        }

    if history_count > 0:
        signals["history"] = {
            "present": history_count >= 10,
            "details": (
                f"{history_count} recent events by {principal_arn} in rolling window"
            ),
            "count": history_count,
        }

    return signals


@tool
def calculate_correlation_confidence(signals: dict) -> float:
    """Weighted correlation confidence with multi-signal bonus."""
    weights = {
        "large_s3_download": 0.30,
        "off_hours_access": 0.20,
        "log_tampering_attempt": 0.30,
        "new_s3_policy_edits": 0.20,
    }
    score = 0.0
    for signal_name, weight in weights.items():
        if signals.get(signal_name, {}).get("present", False):
            score += weight

    indicators_count = sum(1 for k in signals if signals[k].get("present", False))
    if indicators_count >= 3:
        score += 0.10

    return max(0.0, min(score, 1.0))
