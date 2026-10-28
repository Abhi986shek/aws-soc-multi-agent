"""
Forensic Investigator Tool
Reconstructs incident timeline and creates forensic reports.
Ported verbatim from v1 mitigation_agent.tools.forensic_investigator.
"""

from strands import tool
from datetime import datetime, timezone


@tool
def conduct_forensic_investigation(
    event_list: list[dict],
    event_details: dict,
    mitigation_actions: list[str],
    attack_hypothesis: str,
) -> dict:
    """Conduct forensic investigation and create comprehensive report."""
    timeline = _reconstruct_timeline(event_list, event_details, mitigation_actions)
    evidence = _collect_evidence(event_details)
    iocs = _extract_iocs(event_details)
    narrative = _generate_incident_narrative(timeline, attack_hypothesis)
    metrics = _calculate_incident_metrics(timeline, event_list)

    return {
        "report_id": f"FR-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d-%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        "incident_type": attack_hypothesis,
        "timeline": timeline,
        "evidence_collected": evidence,
        "indicators_of_compromise": iocs,
        "incident_narrative": narrative,
        "metrics": metrics,
        "severity": _determine_forensic_severity(timeline, evidence),
        "recommendations": _generate_forensic_recommendations(timeline, iocs),
    }


def _reconstruct_timeline(events: list, details: dict, actions: list) -> list:
    timeline = []
    for event in events:
        event_id = event.get("event_id")
        event_detail = details.get(event_id, {})
        timeline.append({
            "timestamp": event.get("timestamp"),
            "type": "security_event",
            "event_id": event_id,
            "action": event_detail.get("action", "Unknown"),
            "user": event_detail.get("user", "Unknown"),
            "resource": event_detail.get("resource", "Unknown"),
            "severity": event.get("score", 0),
            "description": _describe_event(event, event_detail),
        })
    current_time = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    for action in actions:
        timeline.append({
            "timestamp": current_time,
            "type": "mitigation_action",
            "action": action,
            "description": f"Automated mitigation: {action.replace('_', ' ').title()}",
            "executed_by": "SOC Mitigation Agent",
        })
    timeline.sort(key=lambda x: x.get("timestamp", ""))
    return timeline


def _describe_event(event: dict, details: dict) -> str:
    event_type = event.get("type", "unknown")
    user = details.get("user", "Unknown user")
    action = details.get("action", "unknown action")
    resource = details.get("resource", "unknown resource")
    descriptions = {
        "unusual_access": f"{user} accessed {resource} from unusual location/device",
        "large_s3_download": f"{user} downloaded large volume of data from {resource}",
        "cloudtrail_disabled": f"{user} disabled CloudTrail logging",
        "log_deletion_attempt": f"{user} attempted to delete CloudTrail events",
        "bucket_policy_modification": f"{user} modified bucket policy on {resource}",
        "off_hours_access": f"{user} accessed resources during off-hours",
    }
    return descriptions.get(event_type, f"{user} performed {action} on {resource}")


def _collect_evidence(details: dict) -> dict:
    evidence = {
        "cloudtrail_logs": [],
        "s3_access_logs": [],
        "iam_changes": [],
        "network_logs": [],
        "user_activity": [],
    }
    for event_id, event_detail in details.items():
        if "action" in event_detail:
            evidence["cloudtrail_logs"].append({
                "event_id": event_id,
                "action": event_detail["action"],
                "user": event_detail.get("user"),
                "resource": event_detail.get("resource"),
            })
        if "s3" in str(event_detail.get("resource", "")).lower():
            evidence["s3_access_logs"].append({
                "event_id": event_id,
                "bucket": event_detail.get("resource"),
                "data_volume": event_detail.get("data_volume", 0),
                "file_count": event_detail.get("file_count", 0),
            })
        if "iam" in str(event_detail.get("action", "")).lower() or \
           "policy" in str(event_detail.get("action", "")).lower():
            evidence["iam_changes"].append({
                "event_id": event_id,
                "action": event_detail.get("action"),
                "user": event_detail.get("user"),
            })
        if "source_ip" in event_detail:
            evidence["network_logs"].append({
                "event_id": event_id,
                "source_ip": event_detail.get("source_ip"),
                "user_agent": event_detail.get("user_agent"),
            })
        evidence["user_activity"].append({
            "event_id": event_id,
            "user": event_detail.get("user"),
            "action": event_detail.get("action"),
            "is_new_device": event_detail.get("is_new_device", False),
            "is_off_hours": event_detail.get("is_off_hours", False),
        })
    return evidence


def _extract_iocs(details: dict) -> dict:
    iocs = {
        "ip_addresses": set(),
        "user_accounts": set(),
        "resources_accessed": set(),
        "user_agents": set(),
        "suspicious_actions": [],
    }
    for event_detail in details.values():
        if "source_ip" in event_detail:
            iocs["ip_addresses"].add(event_detail["source_ip"])
        if "user" in event_detail:
            iocs["user_accounts"].add(event_detail["user"])
        if "resource" in event_detail:
            v = event_detail["resource"]
            iocs["resources_accessed"].add(str(v))
        if "user_agent" in event_detail:
            iocs["user_agents"].add(event_detail["user_agent"])
        action = event_detail.get("action", "")
        if any(keyword in action.lower() for keyword in ["delete", "stop", "disable", "modify"]):
            iocs["suspicious_actions"].append(action)
    return {
        "ip_addresses": list(iocs["ip_addresses"]),
        "user_accounts": list(iocs["user_accounts"]),
        "resources_accessed": list(iocs["resources_accessed"]),
        "user_agents": list(iocs["user_agents"]),
        "suspicious_actions": iocs["suspicious_actions"],
    }


def _generate_incident_narrative(timeline: list, attack_type: str) -> str:
    if not timeline:
        return "No timeline data available for narrative generation."
    narrative = f"INCIDENT NARRATIVE - {attack_type}\n\nINCIDENT PROGRESSION:\n"
    for i, event in enumerate(timeline, 1):
        narrative += f"\n{i}. [{event.get('timestamp', 'Unknown time')}] {event.get('description', 'Unknown event')}"
    narrative += "\n\nRESPONSE ACTIONS: Automated mitigation executed within seconds.\nCURRENT STATUS: Threat contained. Forensic evidence preserved.\n"
    return narrative


def _calculate_incident_metrics(timeline: list, events: list) -> dict:
    if not timeline:
        return {}
    first_event = min(timeline, key=lambda x: x.get("timestamp", ""))
    last_event = max(timeline, key=lambda x: x.get("timestamp", ""))
    mitigation_count = sum(1 for t in timeline if t.get("type") == "mitigation_action")
    return {
        "total_events": len(events),
        "timeline_entries": len(timeline),
        "first_event_time": first_event.get("timestamp"),
        "last_event_time": last_event.get("timestamp"),
        "mitigation_actions_taken": mitigation_count,
        "incident_duration": "< 5 minutes",
        "response_time": "< 2 seconds",
        "containment_achieved": True,
    }


def _determine_forensic_severity(timeline: list, evidence: dict) -> str:
    severity_indicators = 0
    if len(evidence.get("iam_changes", [])) > 0:
        severity_indicators += 1
    if len(evidence.get("s3_access_logs", [])) > 2:
        severity_indicators += 1
    if any("delete" in str(t).lower() or "disable" in str(t).lower() for t in timeline):
        severity_indicators += 1
    if severity_indicators >= 3:
        return "Critical"
    if severity_indicators >= 2:
        return "High"
    if severity_indicators >= 1:
        return "Medium"
    return "Low"


def _generate_forensic_recommendations(timeline: list, iocs: dict) -> list:
    recommendations = [
        "Preserve all logs and evidence for minimum 90 days",
        "Review access logs for all affected resources",
        "Conduct user interview to determine if account was compromised",
        "Review and update IAM policies to prevent similar incidents",
    ]
    if len(iocs.get("ip_addresses", [])) > 0:
        recommendations.append("Block identified IP addresses at network perimeter")
    if len(iocs.get("resources_accessed", [])) > 5:
        recommendations.append("Conduct data classification review for accessed resources")
    recommendations.append("Update detection rules based on this incident pattern")
    return recommendations
