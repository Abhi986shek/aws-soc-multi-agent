"""
IOC (Indicator of Compromise) Analyzer Tool
Analyzes and extracts indicators of compromise from security events.
"""

from strands import tool
from typing import List


@tool
def analyze_iocs(event_data: dict, context: dict) -> dict:
    """Analyze events to extract and evaluate Indicators of Compromise."""
    iocs = {
        "network_iocs": [],
        "user_iocs": [],
        "resource_iocs": [],
        "behavioral_iocs": [],
    }
    risk_scores: dict = {}

    if "source_ip" in context:
        ip_analysis = _analyze_ip(context["source_ip"], context.get("user_location"))
        iocs["network_iocs"].append(ip_analysis)
        risk_scores["ip_risk"] = ip_analysis["risk_score"]

    if "user_id" in event_data:
        user_analysis = _analyze_user_behavior(
            event_data["user_id"],
            event_data.get("actions", []),
            context.get("normal_behavior", {}),
        )
        iocs["user_iocs"].append(user_analysis)
        risk_scores["user_risk"] = user_analysis["risk_score"]

    if "resources_accessed" in event_data:
        resource_analysis = _analyze_resources(
            event_data["resources_accessed"], event_data.get("data_volume", 0)
        )
        iocs["resource_iocs"].append(resource_analysis)
        risk_scores["resource_risk"] = resource_analysis["risk_score"]

    behavioral_analysis = _analyze_behavioral_indicators(event_data, context)
    iocs["behavioral_iocs"] = behavioral_analysis["indicators"]
    risk_scores["behavioral_risk"] = behavioral_analysis["risk_score"]

    overall_severity = _calculate_ioc_severity(risk_scores)

    return {
        "iocs": iocs,
        "risk_scores": risk_scores,
        "overall_severity": overall_severity,
        "critical_iocs": _identify_critical_iocs(iocs, risk_scores),
        "ioc_count": _count_total_iocs(iocs),
        "recommendations": _generate_ioc_recommendations(overall_severity, iocs),
    }


def _analyze_ip(ip_address: str, location: dict = None) -> dict:
    risk_factors = []
    risk_score = 0.0
    if location and location.get("is_vpn", False):
        risk_factors.append("VPN/Proxy detected")
        risk_score += 0.3
    if location and location.get("is_unusual_location", False):
        risk_factors.append("Unusual geographic location")
        risk_score += 0.4
    if _is_suspicious_ip(ip_address):
        risk_factors.append("IP in threat database")
        risk_score += 0.5
    return {
        "type": "network",
        "indicator": ip_address,
        "risk_factors": risk_factors,
        "risk_score": min(risk_score, 1.0),
        "location": location,
    }


def _analyze_user_behavior(user_id: str, actions: List[str], normal_behavior: dict) -> dict:
    risk_factors = []
    risk_score = 0.0
    action_count = len(actions)
    normal_count = normal_behavior.get("avg_daily_actions", 50)
    if action_count > normal_count * 3:
        risk_factors.append(f"Action volume {action_count} vs normal {normal_count}")
        risk_score += 0.4
    unusual_actions = [a for a in actions if a not in normal_behavior.get("typical_actions", [])]
    if len(unusual_actions) > 5:
        risk_factors.append(f"{len(unusual_actions)} unusual action types")
        risk_score += 0.3
    if any("permission" in a or "policy" in a for a in actions):
        risk_factors.append("Privilege modification detected")
        risk_score += 0.4
    return {
        "type": "user",
        "indicator": user_id,
        "risk_factors": risk_factors,
        "risk_score": min(risk_score, 1.0),
        "unusual_actions": len(unusual_actions),
    }


def _analyze_resources(resources: List[str], data_volume: int) -> dict:
    risk_factors = []
    risk_score = 0.0
    sensitive_keywords = ["prod", "production", "sensitive", "confidential", "pii"]
    sensitive_resources = [r for r in resources if any(k in r.lower() for k in sensitive_keywords)]
    if sensitive_resources:
        risk_factors.append(f"{len(sensitive_resources)} sensitive resources accessed")
        risk_score += 0.5
    if data_volume > 1_000_000_000:
        risk_factors.append(f"Large data volume: {data_volume / 1_000_000_000:.2f}GB")
        risk_score += 0.4
    if len(resources) > 10:
        risk_factors.append(f"{len(resources)} different resources accessed")
        risk_score += 0.2
    return {
        "type": "resource",
        "indicator": f"{len(resources)} resources",
        "risk_factors": risk_factors,
        "risk_score": min(risk_score, 1.0),
        "sensitive_count": len(sensitive_resources),
    }


def _analyze_behavioral_indicators(event_data: dict, context: dict) -> dict:
    indicators = []
    risk_score = 0.0
    if context.get("is_off_hours", False):
        indicators.append({"type": "temporal", "description": "Off-hours access", "severity": "medium"})
        risk_score += 0.3
    if context.get("is_new_device", False):
        indicators.append({"type": "access", "description": "New device fingerprint", "severity": "medium"})
        risk_score += 0.3
    if any("log" in str(a).lower() for a in event_data.get("actions", [])):
        indicators.append({"type": "anti_forensics", "description": "Log tampering attempt", "severity": "high"})
        risk_score += 0.5
    if event_data.get("action_velocity", 0) > 10:
        indicators.append({"type": "velocity", "description": "Rapid action succession", "severity": "medium"})
        risk_score += 0.2
    return {"indicators": indicators, "risk_score": min(risk_score, 1.0)}


def _calculate_ioc_severity(risk_scores: dict) -> str:
    if not risk_scores:
        return "Low"
    avg_risk = sum(risk_scores.values()) / len(risk_scores)
    if avg_risk >= 0.75:
        return "Critical"
    if avg_risk >= 0.5:
        return "High"
    if avg_risk >= 0.3:
        return "Medium"
    return "Low"


def _identify_critical_iocs(iocs: dict, risk_scores: dict) -> List[str]:
    return [f"{c}: {s:.2f}" for c, s in risk_scores.items() if s >= 0.7]


def _count_total_iocs(iocs: dict) -> int:
    return sum(len(v) if isinstance(v, list) else 1 for v in iocs.values())


def _generate_ioc_recommendations(severity: str, iocs: dict) -> List[str]:
    recommendations = []
    if severity in ["Critical", "High"]:
        recommendations.append("Immediate account suspension recommended")
        recommendations.append("Block source IP addresses")
        recommendations.append("Initiate forensic investigation")
    if iocs.get("behavioral_iocs"):
        recommendations.append("Review user activity logs in detail")
    if iocs.get("network_iocs"):
        recommendations.append("Analyze network traffic patterns")
    recommendations.append("Preserve all logs for investigation")
    return recommendations


def _is_suspicious_ip(ip: str) -> bool:
    suspicious_ranges = ["10.0.0.", "192.168."]
    return any(ip.startswith(r) for r in suspicious_ranges)
