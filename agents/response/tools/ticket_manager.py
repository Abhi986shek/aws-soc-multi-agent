"""
Ticket Manager Tool
Creates resolved tickets for automated actions and priority tickets for manual intervention.
Ported verbatim from v1 mitigation_agent.tools.ticket_manager.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from strands import tool
from .dynamodb_client import get_dynamodb_client
from logger import get_logger
from integrations.email import send_email
from integrations.splunk import send_event
from integrations.pagerduty import trigger_incident
from integrations.thehive import create_case as thehive_create_case
import config

logger = get_logger("ticket_manager")


def _fire_and_forget(coro) -> None:
    """Run an async coro from sync context without blocking the LLM tool call."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
        return
    except RuntimeError:
        pass
    try:
        asyncio.run(coro)
    except Exception as e:
        logger.error(f"Async task failed: {e}")


def _priority_email_body(ticket: dict) -> str:
    severity = ticket.get("priority_level", "Unknown")
    techniques = []
    for m in (config.mitre_mappings or []):
        if isinstance(m, dict):
            tid = m.get("technique_id")
            if tid:
                techniques.append(tid)
    actions = ticket.get("automated_actions_taken", []) or []
    return (
        f"SOC PRIORITY incident {ticket.get('ticket_id')}\n"
        f"Severity: {severity}\n"
        f"Top MITRE techniques: {', '.join(techniques[:5]) or 'n/a'}\n"
        f"Actions attempted: {', '.join(actions) or 'none'}\n"
        f"DynamoDB ticket id: {ticket.get('ticket_id')} "
        f"(table={config.settings.dynamodb_table if hasattr(config, 'settings') else 'soc_tickets'})\n"
    )


@tool
def manage_incident_tickets(
    mitigation_results: dict,
    incident_summary: dict,
    priority_level: str,
    actions_taken: list[str],
) -> dict:
    """Create tickets for SOC record keeping and manual intervention."""
    tickets_created = []
    automated_successful = mitigation_results.get("successful_actions", [])
    failed_actions = mitigation_results.get("failed_actions", [])
    db_client = get_dynamodb_client()

    if automated_successful:
        resolved_ticket = _create_resolved_ticket(automated_successful, incident_summary, priority_level)
        tickets_created.append(resolved_ticket)
        if db_client:
            if db_client.create_ticket(resolved_ticket):
                logger.info(f"RESOLVED ticket written: {resolved_ticket['ticket_id']}")
            else:
                logger.error(f"Failed to write RESOLVED ticket: {resolved_ticket['ticket_id']}")
        _fire_and_forget(send_event(resolved_ticket))
        _fire_and_forget(thehive_create_case(resolved_ticket, pre_closed=True))

    if failed_actions or _requires_manual_intervention(incident_summary, priority_level):
        priority_ticket = _create_priority_ticket(failed_actions, incident_summary, priority_level, actions_taken)
        tickets_created.append(priority_ticket)
        if db_client:
            if db_client.create_ticket(priority_ticket):
                logger.info(f"PRIORITY ticket written: {priority_ticket['ticket_id']}")
            else:
                logger.error(f"Failed to write PRIORITY ticket: {priority_ticket['ticket_id']}")
        _fire_and_forget(send_event(priority_ticket))
        _fire_and_forget(send_email(
            subject=f"[SOC] Priority incident {priority_ticket['ticket_id']}",
            body_text=_priority_email_body(priority_ticket),
        ))
        if not getattr(config.settings, "dry_run", False):
            _fire_and_forget(trigger_incident(priority_ticket))
        _fire_and_forget(thehive_create_case(priority_ticket, pre_closed=False))

    return {
        "total_tickets_created": len(tickets_created),
        "resolved_tickets": sum(1 for t in tickets_created if t["ticket_type"] == "RESOLVED"),
        "priority_tickets": sum(1 for t in tickets_created if t["ticket_type"] == "PRIORITY"),
        "tickets": tickets_created,
        "notification_sent": True,
        "created_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }


def _create_resolved_ticket(successful_actions: list, incident: dict, priority: str) -> dict:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ticket_id = f"SOC-RESOLVED-{now.strftime('%Y%m%d%H%M%S')}"
    timestamp = now.isoformat() + "Z"
    return {
        "ticket_id": ticket_id,
        "created_timestamp": timestamp,
        "priority_level": priority,
        "ticket_type": "RESOLVED",
        "affected_user": _extract_affected_user(),
        "assigned_to": "SOC Mitigation Agent",
        "automated_actions_taken": successful_actions,
        "escalated": False,
        "incident_detected_time": _get_incident_detected_time(),
        "manual_actions_required": [],
    }


def _create_priority_ticket(failed_actions: list, incident: dict, priority: str, all_actions: list) -> dict:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ticket_id = f"SOC-PRIORITY-{now.strftime('%Y%m%d%H%M%S')}"
    timestamp = now.isoformat() + "Z"
    manual_actions_needed = _determine_manual_actions(incident, failed_actions, priority)
    return {
        "ticket_id": ticket_id,
        "created_timestamp": timestamp,
        "priority_level": priority,
        "ticket_type": "PRIORITY",
        "affected_user": _extract_affected_user(),
        "assigned_to": "SOC Team",
        "automated_actions_taken": [a for a in all_actions if a not in [f.get("action") for f in failed_actions]],
        "escalated": priority in ["Critical", "High"],
        "incident_detected_time": _get_incident_detected_time(),
        "manual_actions_required": manual_actions_needed,
        "response_deadline": _calculate_response_deadline(priority),
        "urgency": _calculate_urgency(priority, failed_actions),
    }


def _requires_manual_intervention(incident: dict, priority: str) -> bool:
    if priority == "Critical":
        return True
    high_risk_attacks = ["exfiltration", "ransomware", "privilege escalation"]
    attack_type = str(incident.get("attack_hypothesis", "")).lower()
    if any(risk in attack_type for risk in high_risk_attacks):
        return True
    if incident.get("data_classification") == "PII":
        return True
    return False


def _calculate_urgency(priority: str, failed_actions: list) -> str:
    if priority == "Critical":
        return "IMMEDIATE - Respond within 15 minutes"
    if priority == "High":
        return "URGENT - Respond within 1 hour"
    if failed_actions:
        return "HIGH - Respond within 2 hours"
    if priority == "Medium":
        return "MODERATE - Respond within 4 hours"
    return "STANDARD - Respond within 24 hours"


def _determine_manual_actions(incident: dict, failed_actions: list, priority: str) -> list:
    manual_actions = []
    for failed in failed_actions:
        action = failed.get("action", "")
        manual_actions.append(f"Manually execute: {action.replace('_', ' ').title()}")
    if priority in ["Critical", "High"]:
        manual_actions.extend([
            "Conduct user interview to determine if account was compromised",
            "Review all user activity for past 30 days",
            "Assess data breach scope and notify stakeholders if required",
            "Contact legal/compliance team if PII or regulated data involved",
        ])
    attack_type = str(incident.get("attack_hypothesis", "")).lower()
    if "exfiltration" in attack_type:
        manual_actions.extend([
            "Determine exact data exfiltrated and assess impact",
            "Check for data in external locations",
            "Prepare breach notification if required by regulations",
        ])
    if "log" in attack_type or "tampering" in attack_type:
        manual_actions.extend([
            "Verify log integrity and identify gaps",
            "Restore logs from backup if available",
            "Implement additional log protection measures",
        ])
    manual_actions.extend([
        "Review and approve permanent account suspension",
        "Update incident response playbook based on findings",
        "Schedule post-incident review meeting",
    ])
    return manual_actions


def _calculate_response_deadline(priority: str) -> str:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    deadlines = {
        "Critical": timedelta(minutes=15),
        "High": timedelta(hours=1),
        "Medium": timedelta(hours=4),
        "Low": timedelta(hours=24),
    }
    return (now + deadlines.get(priority, timedelta(hours=24))).isoformat()


def _extract_affected_user() -> str:
    if not config.event_details:
        return "Unknown"
    for event_detail in config.event_details.values():
        if "user" in event_detail:
            return event_detail["user"]
    return "Unknown"


def _get_incident_detected_time() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
