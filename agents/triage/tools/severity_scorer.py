"""
Severity Scorer Tool
Scores threat severity based on behavior, timing, and context.
"""

from strands import tool


@tool
def score_threat_severity(
    behaviors: list[str],
    timing_context: dict,
    user_context: dict,
    attack_stage: str,
) -> dict:
    """Scores threat severity based on multiple contextual factors."""
    severity_score = 0.0
    contributing_factors = []

    behavior_score = _score_behaviors(behaviors)
    severity_score += behavior_score
    if behavior_score > 0.2:
        contributing_factors.append({
            "factor": "High-risk behaviors detected",
            "score": behavior_score,
            "details": behaviors,
        })

    timing_score = _score_timing(timing_context)
    severity_score += timing_score
    if timing_score > 0.15:
        contributing_factors.append({
            "factor": "Suspicious timing patterns",
            "score": timing_score,
            "details": timing_context,
        })

    user_score = _score_user_risk(user_context)
    severity_score += user_score
    if user_score > 0.1:
        contributing_factors.append({
            "factor": "User risk indicators",
            "score": user_score,
            "details": user_context,
        })

    stage_score = _score_attack_stage(attack_stage)
    severity_score += stage_score
    if stage_score > 0.1:
        contributing_factors.append({
            "factor": f"Attack stage: {attack_stage}",
            "score": stage_score,
            "details": {"stage": attack_stage},
        })

    severity_score = min(max(severity_score, 0.0), 1.0)
    severity_level = _get_severity_level(severity_score)
    urgency = _calculate_urgency(severity_score, attack_stage, behaviors)

    return {
        "severity_score": round(severity_score, 3),
        "severity_level": severity_level,
        "contributing_factors": contributing_factors,
        "urgency": urgency,
        "response_time_required": _get_response_time(severity_level),
        "escalation_required": severity_score >= 0.75,
    }


def _score_behaviors(behaviors: list[str]) -> float:
    behavior_weights = {
        "data_exfiltration": 0.35,
        "log_tampering": 0.30,
        "privilege_modification": 0.25,
        "unusual_access": 0.15,
        "reconnaissance": 0.10,
        "policy_change": 0.20,
    }
    score = 0.0
    for behavior in behaviors:
        for key, weight in behavior_weights.items():
            if key in behavior.lower():
                score += weight
    return min(score, 0.35)


def _score_timing(timing_context: dict) -> float:
    score = 0.0
    if timing_context.get("is_off_hours", False):
        score += 0.10
    velocity = timing_context.get("action_velocity", 0)
    if velocity > 20:
        score += 0.10
    elif velocity > 10:
        score += 0.05
    if timing_context.get("unusual_time_pattern", False):
        score += 0.05
    return min(score, 0.25)


def _score_user_risk(user_context: dict) -> float:
    score = 0.0
    if user_context.get("is_new_device", False):
        score += 0.08
    if user_context.get("unusual_location", False):
        score += 0.07
    if user_context.get("role") == "unauthorized":
        score += 0.10
    incident_count = user_context.get("previous_incidents", 0)
    if incident_count > 0:
        score += min(incident_count * 0.03, 0.10)
    return min(score, 0.20)


def _score_attack_stage(stage: str) -> float:
    stage_scores = {
        "Active Exfiltration with Cover-up": 0.20,
        "Data Exfiltration": 0.18,
        "Privilege Escalation": 0.15,
        "Initial Access / Reconnaissance": 0.10,
        "Unknown": 0.05,
    }
    return stage_scores.get(stage, 0.10)


def _get_severity_level(score: float) -> str:
    if score >= 0.85:
        return "Critical"
    if score >= 0.65:
        return "High"
    if score >= 0.40:
        return "Medium"
    return "Low"


def _calculate_urgency(score: float, stage: str, behaviors: list[str]) -> str:
    if score >= 0.85:
        return "Immediate - Respond within minutes"
    if "exfiltration" in stage.lower() and score >= 0.70:
        return "Immediate - Active data theft in progress"
    if any("log_tampering" in b or "cover" in b for b in behaviors):
        return "Urgent - Evidence destruction in progress"
    if score >= 0.65:
        return "Urgent - Respond within 1 hour"
    if score >= 0.40:
        return "Moderate - Respond within 4 hours"
    return "Standard - Respond within 24 hours"


def _get_response_time(level: str) -> str:
    return {
        "Critical": "< 15 minutes",
        "High": "< 1 hour",
        "Medium": "< 4 hours",
        "Low": "< 24 hours",
    }.get(level, "< 24 hours")
