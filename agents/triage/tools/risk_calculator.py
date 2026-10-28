"""
Risk Calculator Tool
Calculates overall threat risk score based on multiple factors.
"""

from strands import tool


@tool
def calculate_threat_risk(
    ti_confidence: float,
    mitre_severity: str,
    data_sensitivity: str,
    user_role: str,
    event_count: int,
) -> dict:
    """Calculates comprehensive threat risk score."""
    risk_score = 0.0
    risk_factors: dict = {}

    ti_score = ti_confidence * 0.30
    risk_factors["threat_intelligence"] = {"score": ti_confidence, "weight": 0.30, "contribution": ti_score}
    risk_score += ti_score

    severity_map = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
    severity_score = severity_map.get(mitre_severity, 0.5) * 0.25
    risk_factors["mitre_severity"] = {"level": mitre_severity, "weight": 0.25, "contribution": severity_score}
    risk_score += severity_score

    sensitivity_map = {"PII": 1.0, "Confidential": 0.85, "Internal": 0.5, "Public": 0.2}
    data_score = sensitivity_map.get(data_sensitivity, 0.5) * 0.25
    risk_factors["data_sensitivity"] = {"classification": data_sensitivity, "weight": 0.25, "contribution": data_score}
    risk_score += data_score

    auth_map = {"unauthorized": 1.0, "limited_access": 0.7, "standard_user": 0.5, "authorized": 0.3}
    auth_score = auth_map.get(user_role, 0.5) * 0.10
    risk_factors["user_authorization"] = {"role": user_role, "weight": 0.10, "contribution": auth_score}
    risk_score += auth_score

    volume_score = min(event_count / 10, 1.0) * 0.10
    risk_factors["event_volume"] = {"count": event_count, "weight": 0.10, "contribution": volume_score}
    risk_score += volume_score

    risk_score = min(max(risk_score, 0.0), 1.0)

    return {
        "risk_score": round(risk_score, 3),
        "risk_factors": risk_factors,
        "risk_level": _get_risk_level(risk_score),
        "calculation_method": "weighted_multi_factor",
        "total_weight": 1.0,
    }


def _get_risk_level(score: float) -> str:
    if score >= 0.85:
        return "Critical"
    if score >= 0.65:
        return "High"
    if score >= 0.40:
        return "Medium"
    return "Low"
