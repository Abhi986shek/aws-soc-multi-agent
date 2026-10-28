"""
Action Recommender Tool
Recommends mitigation actions based on threat severity and context.
"""

from strands import tool


@tool
def recommend_mitigation_actions(
    severity_level: str,
    attack_type: str,
    behaviors: list[str],
    resources_affected: list[str],
) -> dict:
    """Recommend prioritized mitigation actions based on threat analysis."""
    actions = []
    if severity_level in ["Critical", "High"]:
        actions.extend(_get_immediate_containment_actions(behaviors))
    if "exfiltration" in attack_type.lower():
        actions.extend(_get_exfiltration_actions(resources_affected))
    if "log" in str(behaviors).lower() or "tampering" in str(behaviors).lower():
        actions.extend(_get_anti_forensics_actions())
    if "privilege" in str(behaviors).lower() or "escalation" in str(behaviors).lower():
        actions.extend(_get_privilege_abuse_actions())
    actions.extend(_get_standard_response_actions(severity_level))

    actions = _prioritize_actions(actions, severity_level)
    execution_plan = _create_execution_plan(actions)

    return {
        "recommended_actions": actions,
        "action_count": len(actions),
        "execution_plan": execution_plan,
        "estimated_execution_time": _estimate_execution_time(actions),
        "automation_available": _check_automation_available(actions),
    }


def _get_immediate_containment_actions(behaviors: list[str]) -> list[dict]:
    return [
        {"action": "disable_user_account", "description": "Immediately disable the user's IAM account",
         "priority": 1, "category": "containment", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "rotate_access_keys", "description": "Rotate all access keys for the user",
         "priority": 2, "category": "containment", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "block_source_ip", "description": "Block source IP address using WAF/Security Groups",
         "priority": 3, "category": "containment", "automated": True, "estimated_time": "< 2 minutes"},
    ]


def _get_exfiltration_actions(resources: list[str]) -> list[dict]:
    return [
        {"action": "stop_s3_access", "description": "Block S3 access for the user immediately",
         "priority": 2, "category": "containment", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "add_deny_policy", "description": "Add explicit deny policy to sensitive S3 buckets",
         "priority": 4, "category": "containment", "automated": True, "estimated_time": "< 2 minutes"},
        {"action": "stop_active_downloads", "description": "Terminate active S3 download sessions",
         "priority": 1, "category": "containment", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "enable_s3_versioning", "description": "Enable versioning on affected buckets to preserve state",
         "priority": 8, "category": "preservation", "automated": True, "estimated_time": "< 1 minute"},
    ]


def _get_anti_forensics_actions() -> list[dict]:
    return [
        {"action": "enable_cloudtrail", "description": "Re-enable CloudTrail logging if disabled",
         "priority": 3, "category": "preservation", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "backup_logs", "description": "Immediately backup all existing logs to secure location",
         "priority": 5, "category": "preservation", "automated": True, "estimated_time": "< 5 minutes"},
        {"action": "lock_log_retention", "description": "Lock log retention policies to prevent deletion",
         "priority": 6, "category": "preservation", "automated": True, "estimated_time": "< 2 minutes"},
    ]


def _get_privilege_abuse_actions() -> list[dict]:
    return [
        {"action": "revert_policy_changes", "description": "Revert recent IAM policy modifications",
         "priority": 4, "category": "containment", "automated": True, "estimated_time": "< 3 minutes"},
        {"action": "audit_permissions", "description": "Audit all permission changes in last 24 hours",
         "priority": 7, "category": "investigation", "automated": True, "estimated_time": "< 5 minutes"},
    ]


def _get_standard_response_actions(severity: str) -> list[dict]:
    actions = [
        {"action": "alert_soc_team", "description": "Send alert to SOC leadership via Slack/Email",
         "priority": 5, "category": "notification", "automated": True, "estimated_time": "< 1 minute"},
        {"action": "create_incident_ticket", "description": "Create incident ticket in ticketing system",
         "priority": 9, "category": "documentation", "automated": True, "estimated_time": "< 1 minute"},
    ]
    if severity in ["Critical", "High"]:
        actions.append({
            "action": "snapshot_workstation",
            "description": "Snapshot user's EC2 workstation for forensics",
            "priority": 10, "category": "preservation", "automated": True, "estimated_time": "< 5 minutes",
        })
    return actions


def _prioritize_actions(actions: list[dict], severity: str) -> list[dict]:
    seen = set()
    unique_actions = []
    for action in actions:
        if action["action"] not in seen:
            seen.add(action["action"])
            unique_actions.append(action)
    unique_actions.sort(key=lambda x: x["priority"])
    return unique_actions


def _create_execution_plan(actions: list[dict]) -> dict:
    phases = {
        "Phase 1 - Immediate Containment (0-2 min)": [],
        "Phase 2 - Evidence Preservation (2-5 min)": [],
        "Phase 3 - Investigation Support (5-10 min)": [],
    }
    for action in actions:
        if action["priority"] <= 3:
            phases["Phase 1 - Immediate Containment (0-2 min)"].append(action["action"])
        elif action["priority"] <= 7:
            phases["Phase 2 - Evidence Preservation (2-5 min)"].append(action["action"])
        else:
            phases["Phase 3 - Investigation Support (5-10 min)"].append(action["action"])
    return phases


def _estimate_execution_time(actions: list[dict]) -> str:
    max_time = 0
    for action in actions:
        time_str = action.get("estimated_time", "< 1 minute")
        if "minute" in time_str:
            try:
                minutes = int(time_str.split("<")[1].split("minute")[0].strip())
                max_time = max(max_time, minutes)
            except Exception:
                pass
    return f"< {max_time} minutes (parallel execution)"


def _check_automation_available(actions: list[dict]) -> dict:
    automated = sum(1 for a in actions if a.get("automated", False))
    manual = len(actions) - automated
    return {
        "total_actions": len(actions),
        "automated": automated,
        "manual": manual,
        "automation_percentage": round((automated / len(actions)) * 100, 1) if actions else 0,
    }
