"""
Data Classifier Tool
Classifies data sensitivity and determines impact of potential breach.
"""

from strands import tool


@tool
def classify_data_sensitivity(
    resources_accessed: list[str],
    data_volume: int,
    resource_metadata: dict,
) -> dict:
    """Classifies data sensitivity and calculates potential impact."""
    sensitivity_keywords = {
        "PII": ["pii", "personal", "customer", "ssn", "credit", "payment", "identity"],
        "Confidential": ["confidential", "secret", "private", "sensitive", "prod", "production"],
        "Internal": ["internal", "employee", "staff", "company"],
        "Public": ["public", "marketing", "blog", "website"],
    }

    classifications = []
    highest_sensitivity = "Public"
    sensitivity_order = ["PII", "Confidential", "Internal", "Public"]

    for resource in resources_accessed:
        resource_lower = str(resource).lower()
        for sensitivity, keywords in sensitivity_keywords.items():
            if any(keyword in resource_lower for keyword in keywords):
                classifications.append({"resource": resource, "classification": sensitivity})
                if sensitivity_order.index(sensitivity) < sensitivity_order.index(highest_sensitivity):
                    highest_sensitivity = sensitivity
                break
        else:
            classifications.append({"resource": resource, "classification": "Internal"})

    impact_score = _calculate_impact_score(highest_sensitivity, data_volume, len(resources_accessed))
    breach_impact = _assess_breach_impact(highest_sensitivity, data_volume)

    return {
        "overall_classification": highest_sensitivity,
        "resource_classifications": classifications,
        "data_volume_gb": round(data_volume / (1024 ** 3), 2) if data_volume else 0.0,
        "resource_count": len(resources_accessed),
        "impact_score": impact_score,
        "breach_impact": breach_impact,
        "compliance_risk": _get_compliance_risk(highest_sensitivity),
    }


def _calculate_impact_score(sensitivity: str, volume: int, resource_count: int) -> float:
    sensitivity_scores = {"PII": 1.0, "Confidential": 0.8, "Internal": 0.5, "Public": 0.2}
    base_score = sensitivity_scores.get(sensitivity, 0.5)
    volume_gb = (volume or 0) / (1024 ** 3)
    if volume_gb > 10:
        volume_multiplier = 1.3
    elif volume_gb > 1:
        volume_multiplier = 1.2
    elif volume_gb > 0.1:
        volume_multiplier = 1.1
    else:
        volume_multiplier = 1.0
    if resource_count > 10:
        resource_multiplier = 1.2
    elif resource_count > 5:
        resource_multiplier = 1.1
    else:
        resource_multiplier = 1.0
    return min(base_score * volume_multiplier * resource_multiplier, 1.0)


def _assess_breach_impact(sensitivity: str, volume: int) -> dict:
    volume_gb = (volume or 0) / (1024 ** 3)
    impact_levels = {
        "PII": {
            "financial": "High - Potential fines, lawsuits",
            "reputational": "Severe - Customer trust loss",
            "regulatory": "Critical - GDPR, CCPA violations",
            "estimated_cost": f"${volume_gb * 150:.0f}K - ${volume_gb * 300:.0f}K",
        },
        "Confidential": {
            "financial": "Medium-High - Business loss",
            "reputational": "High - Competitive disadvantage",
            "regulatory": "Medium - Industry compliance",
            "estimated_cost": f"${volume_gb * 50:.0f}K - ${volume_gb * 150:.0f}K",
        },
        "Internal": {
            "financial": "Low-Medium - Operational impact",
            "reputational": "Medium - Internal trust",
            "regulatory": "Low - Minimal compliance risk",
            "estimated_cost": f"${volume_gb * 10:.0f}K - ${volume_gb * 50:.0f}K",
        },
        "Public": {
            "financial": "Low - Minimal impact",
            "reputational": "Low - Public data",
            "regulatory": "None",
            "estimated_cost": "Minimal",
        },
    }
    return impact_levels.get(sensitivity, impact_levels["Internal"])


def _get_compliance_risk(sensitivity: str) -> list[str]:
    compliance_map = {
        "PII": ["GDPR", "CCPA", "HIPAA", "PCI-DSS"],
        "Confidential": ["SOC 2", "ISO 27001", "Industry-specific"],
        "Internal": ["Internal policies", "SOC 2"],
        "Public": [],
    }
    return compliance_map.get(sensitivity, [])
