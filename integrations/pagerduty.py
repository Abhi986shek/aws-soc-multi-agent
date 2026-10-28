"""PagerDuty Events API v2 - triggers on-call for priority incidents."""
from __future__ import annotations

import httpx
from config import settings
from logger import get_step_logger

step = get_step_logger("pagerduty")

_API_URL = "https://events.pagerduty.com/v2/enqueue"


async def trigger_incident(ticket: dict) -> None:
    """Trigger a PagerDuty incident from a SOC ticket."""
    if settings.mock_mode:
        step.info("trigger_incident", mock=True, ticket_id=ticket.get("ticket_id"))
        return
    if not settings.pagerduty_routing_key:
        step.info("trigger_incident", skipped=True, reason="routing_key_not_configured")
        return

    severity = _map_severity(ticket.get("priority_level") or ticket.get("severity") or "medium")
    step.start("trigger_incident",
               ticket_id=ticket.get("ticket_id"), severity=severity)
    payload = {
        "routing_key": settings.pagerduty_routing_key,
        "event_action": "trigger",
        "dedup_key": ticket.get("ticket_id"),
        "payload": {
            "summary": f"[SOC] {ticket.get('priority_level', 'Priority')} incident: "
                       f"{ticket.get('ticket_id')}",
            "severity": severity,
            "source": "soc_agent",
            "component": "cloudtrail",
            "group": ticket.get("aws_region", "unknown"),
            "class": ticket.get("attack_hypothesis", "unknown"),
            "custom_details": {
                "ticket_id": ticket.get("ticket_id"),
                "threat_score": ticket.get("threat_score"),
                "mitre_techniques": ticket.get("mitre_mappings", [])[:10],
                "actions_attempted": ticket.get("mitigation_actions_taken", []),
            },
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(_API_URL, json=payload)
            if r.status_code >= 300:
                step.error("PagerDuty non-2xx",
                           status_code=r.status_code, body=r.text[:200])
                return
        step.done("trigger_incident", status_code=r.status_code)
    except Exception as e:
        step.error("PagerDuty trigger failed", exc=e)


def _map_severity(level: str) -> str:
    level = (level or "").lower()
    if level in ("critical", "high"):
        return "critical" if level == "critical" else "error"
    if level == "medium":
        return "warning"
    return "info"
