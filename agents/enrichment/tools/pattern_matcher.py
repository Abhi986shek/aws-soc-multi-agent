"""
Pattern Matcher Tool
Matches event sequences to known attack patterns and behavioral signatures.
"""

from strands import tool
from typing import List


@tool
def match_attack_patterns(event_sequence: List[dict], time_window_minutes: int = 60) -> dict:
    """Match event sequences to known attack patterns."""
    attack_patterns = {
        "insider_exfiltration_sequence": {
            "pattern": ["unusual_access", "large_download", "log_tampering"],
            "severity": "critical",
            "description": "Classic insider threat exfiltration sequence",
            "min_confidence": 0.85,
        },
        "reconnaissance_then_exfil": {
            "pattern": ["account_discovery", "permission_check", "data_access", "bulk_download"],
            "severity": "high",
            "description": "Reconnaissance followed by data exfiltration",
            "min_confidence": 0.75,
        },
        "anti_forensics_sequence": {
            "pattern": ["log_tampering", "cloudtrail_disable", "event_deletion"],
            "severity": "critical",
            "description": "Deliberate anti-forensics activity",
            "min_confidence": 0.90,
        },
        "privilege_escalation_abuse": {
            "pattern": ["permission_change", "policy_modification", "new_resource_access"],
            "severity": "high",
            "description": "Privilege escalation followed by resource abuse",
            "min_confidence": 0.70,
        },
    }

    matched_patterns = []
    sequence_analysis = _analyze_event_sequence(event_sequence)

    for pattern_name, pattern_data in attack_patterns.items():
        match_result = _check_pattern_match(
            event_sequence, pattern_data["pattern"], time_window_minutes
        )
        if match_result["matched"]:
            matched_patterns.append({
                "pattern_name": pattern_name,
                "severity": pattern_data["severity"],
                "description": pattern_data["description"],
                "confidence": match_result["confidence"],
                "matched_events": match_result["matched_events"],
                "time_span_minutes": match_result["time_span"],
            })

    overall_confidence = _calculate_pattern_confidence(matched_patterns, sequence_analysis)

    return {
        "matched_patterns": matched_patterns,
        "sequence_analysis": sequence_analysis,
        "overall_confidence": overall_confidence,
        "attack_stage": _determine_attack_stage(sequence_analysis),
        "is_active_attack": _is_active_attack(event_sequence),
        "pattern_count": len(matched_patterns),
    }


def _analyze_event_sequence(events: List[dict]) -> dict:
    if not events:
        return {"event_count": 0, "behaviors": []}
    behaviors = []
    event_types = set()
    for event in events:
        event_type = event.get("type", "unknown")
        event_types.add(event_type)
        if "download" in event_type or "transfer" in event_type:
            behaviors.append("data_exfiltration")
        elif "log" in event_type or "trail" in event_type:
            behaviors.append("log_tampering")
        elif "policy" in event_type or "permission" in event_type:
            behaviors.append("privilege_modification")
        elif "access" in event_type:
            behaviors.append("unusual_access")
    return {
        "event_count": len(events),
        "unique_event_types": len(event_types),
        "behaviors": list(set(behaviors)),
        "behavior_diversity": len(set(behaviors)),
    }


def _check_pattern_match(events: List[dict], pattern: List[str], time_window: int) -> dict:
    matched_events = []
    pattern_index = 0
    for event in events:
        event_type = event.get("type", "")
        if pattern_index < len(pattern) and pattern[pattern_index] in event_type:
            matched_events.append(event)
            pattern_index += 1
    match_ratio = len(matched_events) / len(pattern) if pattern else 0
    matched = match_ratio >= 0.6
    time_span = len(matched_events) * 5 if len(matched_events) >= 2 else 0
    return {
        "matched": matched,
        "confidence": match_ratio,
        "matched_events": len(matched_events),
        "time_span": time_span,
    }


def _calculate_pattern_confidence(patterns: List[dict], sequence: dict) -> float:
    if not patterns:
        return 0.0
    max_confidence = max([p["confidence"] for p in patterns])
    pattern_boost = min(len(patterns) * 0.05, 0.15)
    diversity_boost = min(sequence.get("behavior_diversity", 0) * 0.03, 0.10)
    return min(max_confidence + pattern_boost + diversity_boost, 1.0)


def _determine_attack_stage(sequence: dict) -> str:
    behaviors = sequence.get("behaviors", [])
    if "data_exfiltration" in behaviors and "log_tampering" in behaviors:
        return "Active Exfiltration with Cover-up"
    if "data_exfiltration" in behaviors:
        return "Data Exfiltration"
    if "privilege_modification" in behaviors:
        return "Privilege Escalation"
    if "unusual_access" in behaviors:
        return "Initial Access / Reconnaissance"
    return "Unknown"


def _is_active_attack(events: List[dict]) -> bool:
    if not events:
        return False
    recent_event_count = len([e for e in events[-5:] if e])
    return recent_event_count >= 3
