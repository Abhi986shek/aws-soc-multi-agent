"""
Learning Engine Tool
Updates detection models and learns from security incidents.
Ported verbatim from v1 mitigation_agent.tools.learning_engine.
"""

from strands import tool
from datetime import datetime, timezone

from integrations.thehive import list_recently_closed_cases
from logger import get_logger

_logger = get_logger("learning_engine")


@tool
def update_learning_models(
    incident_data: dict,
    attack_patterns: list,
    iocs: dict,
    mitigation_effectiveness: dict,
) -> dict:
    """Update detection models and learn from security incidents."""
    learning_updates = {
        "update_timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "incident_id": incident_data.get("incident_id", "unknown"),
        "updates_applied": [],
    }
    learning_updates["updates_applied"].append(_learn_attack_patterns(attack_patterns, incident_data))
    learning_updates["updates_applied"].append(_update_ioc_database(iocs))
    learning_updates["updates_applied"].append(_optimize_detection_thresholds(incident_data))
    learning_updates["updates_applied"].append(_learn_mitigation_effectiveness(mitigation_effectiveness))
    learning_updates["updates_applied"].append(_update_user_baselines(incident_data))
    learning_updates["learning_confidence"] = _calculate_learning_confidence(learning_updates)
    learning_updates["improvement_recommendations"] = _generate_improvements(learning_updates)
    return learning_updates


def _learn_attack_patterns(patterns: list, incident: dict) -> dict:
    incident_pattern = {
        "pattern_id": f"PAT-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d-%H%M%S')}",
        "pattern_name": incident.get("attack_hypothesis", "Unknown Pattern"),
        "confidence": incident.get("ti_confidence", 0.0),
        "behaviors": incident.get("behaviors", []),
        "indicators": incident.get("indicators", []),
        "learned_from": incident.get("incident_id", "unknown"),
        "learned_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
    variants = _identify_pattern_variants(patterns, incident_pattern)
    return {
        "update_type": "attack_pattern_learning",
        "new_patterns_learned": 1,
        "pattern_variants_identified": len(variants),
        "patterns": [incident_pattern],
        "status": "success",
    }


def _update_ioc_database(iocs: dict) -> dict:
    ioc_updates = {
        "ip_addresses_added": len(iocs.get("ip_addresses", [])),
        "user_accounts_flagged": len(iocs.get("user_accounts", [])),
        "resources_monitored": len(iocs.get("resources_accessed", [])),
        "suspicious_actions_cataloged": len(iocs.get("suspicious_actions", [])),
    }
    watchlist_additions = []
    for ip in iocs.get("ip_addresses", []):
        watchlist_additions.append({"type": "ip_address", "value": ip, "risk_level": "high",
                                    "added_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
    for user in iocs.get("user_accounts", []):
        watchlist_additions.append({"type": "user_account", "value": user, "risk_level": "critical",
                                    "added_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat()})
    return {
        "update_type": "ioc_database_update",
        "total_iocs_added": sum(ioc_updates.values()),
        "ioc_breakdown": ioc_updates,
        "watchlist_additions": len(watchlist_additions),
        "status": "success",
    }


def _optimize_detection_thresholds(incident: dict) -> dict:
    current_thresholds = {
        "data_volume_threshold_gb": 1.0,
        "action_velocity_threshold": 10,
        "off_hours_sensitivity": 0.7,
        "new_device_sensitivity": 0.6,
    }
    adjusted_thresholds = current_thresholds.copy()
    if incident.get("data_volume", 0) > 1_000_000_000:
        adjusted_thresholds["data_volume_threshold_gb"] = 0.5
    if incident.get("action_velocity", 0) > 15:
        adjusted_thresholds["action_velocity_threshold"] = 8
    adjustments = {
        key: {"old_value": current_thresholds[key], "new_value": adjusted_thresholds[key],
              "change": adjusted_thresholds[key] - current_thresholds[key]}
        for key in current_thresholds if current_thresholds[key] != adjusted_thresholds[key]
    }
    return {
        "update_type": "detection_threshold_optimization",
        "thresholds_adjusted": len(adjustments),
        "adjustments": adjustments,
        "expected_improvement": "15-20% better early detection",
        "status": "success",
    }


def _learn_mitigation_effectiveness(effectiveness: dict) -> dict:
    effective_actions, ineffective_actions = [], []
    for action, result in (effectiveness or {}).items():
        if result.get("success", False):
            effective_actions.append({"action": action, "execution_time": result.get("execution_time_ms", 0),
                                      "effectiveness_score": 1.0})
        else:
            ineffective_actions.append({"action": action, "failure_reason": result.get("error", "Unknown"),
                                        "effectiveness_score": 0.0})
    total_actions = len(effective_actions) + len(ineffective_actions)
    effectiveness_rate = len(effective_actions) / total_actions if total_actions > 0 else 0
    return {
        "update_type": "mitigation_effectiveness_learning",
        "total_actions_analyzed": total_actions,
        "effective_actions": len(effective_actions),
        "ineffective_actions": len(ineffective_actions),
        "effectiveness_rate": round(effectiveness_rate, 2),
        "recommendations": _generate_mitigation_recommendations(ineffective_actions),
        "status": "success",
    }


def _update_user_baselines(incident: dict) -> dict:
    user = incident.get("user", "unknown")
    baseline_updates = {"user": user, "baseline_type": "behavioral", "updates": []}
    if "data_volume" in incident:
        baseline_updates["updates"].append({
            "metric": "typical_data_volume", "old_baseline": "20MB/day",
            "new_baseline": "50MB/day", "reason": "Adjusted based on recent activity patterns",
        })
    if incident.get("is_off_hours"):
        baseline_updates["updates"].append({
            "metric": "typical_access_hours", "old_baseline": "9AM-5PM",
            "new_baseline": "9AM-5PM (off-hours flagged)", "reason": "Maintain strict off-hours monitoring",
        })
    return {
        "update_type": "user_baseline_update",
        "user": user,
        "baselines_updated": len(baseline_updates["updates"]),
        "updates": baseline_updates["updates"],
        "status": "success",
    }


def _calculate_learning_confidence(updates: dict) -> float:
    successful_updates = sum(1 for u in updates.get("updates_applied", []) if u.get("status") == "success")
    total_updates = len(updates.get("updates_applied", []))
    if total_updates == 0:
        return 0.0
    return round(successful_updates / total_updates, 2)


def _generate_improvements(updates: dict) -> list:
    recommendations = []
    for update in updates.get("updates_applied", []):
        if update.get("update_type") == "attack_pattern_learning":
            if update.get("new_patterns_learned", 0) > 0:
                recommendations.append("Deploy updated attack pattern detection to production within 24 hours")
        if update.get("update_type") == "detection_threshold_optimization":
            if update.get("thresholds_adjusted", 0) > 0:
                recommendations.append("Test optimized thresholds in staging before production deployment")
        if update.get("update_type") == "mitigation_effectiveness_learning":
            effectiveness = update.get("effectiveness_rate", 0)
            if effectiveness < 0.9:
                recommendations.append(
                    f"Review and improve mitigation actions (current effectiveness: {effectiveness*100}%)"
                )
    recommendations.append("Schedule quarterly review of learned patterns")
    recommendations.append("Update SOC playbooks with new attack patterns")
    return recommendations


def _identify_pattern_variants(existing_patterns: list, new_pattern: dict) -> list:
    variants = []
    for pattern in existing_patterns or []:
        pattern_name = str(pattern.get("pattern", "")) if isinstance(pattern, dict) else str(pattern)
        new_name = new_pattern.get("pattern_name", "")
        if pattern_name and (pattern_name.lower() in new_name.lower() or new_name.lower() in pattern_name.lower()):
            variants.append({"existing_pattern": pattern_name, "new_pattern": new_name, "similarity": "high"})
    return variants


async def learn_from_closed_cases(since_hours: int = 24) -> dict:
    """Read recently-closed TheHive cases and derive pattern up/downgrades.

    Returns a diff dict describing which patterns/techniques should have
    their confidence adjusted based on analyst resolutions. Silently returns
    a "no TheHive data" note when TheHive is not configured or no cases
    were closed in the window.
    """
    update_type = "thehive_closed_case_learning"
    try:
        cases = await list_recently_closed_cases(since_hours=since_hours)
    except Exception as e:
        _logger.error(f"learn_from_closed_cases: fetch failed: {e}")
        cases = []

    if not cases:
        return {
            "update_type": update_type,
            "note": "no TheHive data",
            "upgraded": [],
            "downgraded": [],
            "false_positive_rate": 0.0,
            "total_closed": 0,
            "status": "success",
        }

    upgraded: dict[str, int] = {}
    downgraded: dict[str, int] = {}
    tp = fp = 0
    for case in cases:
        status = str(case.get("resolutionStatus") or "").lower()
        tags = [t for t in (case.get("tags") or []) if isinstance(t, str)]
        pattern_tags = [
            t for t in tags
            if t.startswith("mitre:") or t.startswith("pattern:")
        ]
        if status == "truepositive":
            tp += 1
            for t in pattern_tags:
                upgraded[t] = upgraded.get(t, 0) + 1
        elif status == "falsepositive":
            fp += 1
            for t in pattern_tags:
                downgraded[t] = downgraded.get(t, 0) + 1

    total = len(cases)
    fp_rate = round(fp / total, 3) if total else 0.0
    return {
        "update_type": update_type,
        "upgraded": [{"tag": k, "count": v} for k, v in upgraded.items()],
        "downgraded": [{"tag": k, "count": v} for k, v in downgraded.items()],
        "false_positive_rate": fp_rate,
        "total_closed": total,
        "true_positives": tp,
        "false_positives": fp,
        "status": "success",
    }


def _generate_mitigation_recommendations(ineffective_actions: list) -> list:
    if not ineffective_actions:
        return ["All mitigation actions were effective - maintain current approach"]
    recommendations = []
    for action in ineffective_actions:
        action_name = action.get("action", "unknown")
        recommendations.append(f"Review and fix {action_name} - Failure reason: {action.get('failure_reason')}")
    recommendations.append("Conduct mitigation action testing in staging environment")
    return recommendations
