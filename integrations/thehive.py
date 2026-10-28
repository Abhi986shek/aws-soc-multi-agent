"""TheHive case management integration.

Every priority incident becomes an open case; every resolved incident becomes
a pre-closed case for audit trail. Closed cases are read back nightly by the
Learning sidecar to update detection patterns.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from config import settings
from logger import get_step_logger

logger = get_step_logger("thehive")
step = logger

_SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_disabled_logged = False
_mock_logged = False


def _enabled() -> bool:
    """Return True if TheHive is configured. Log once on the first no-op."""
    global _disabled_logged
    if not settings.thehive_url or not settings.thehive_api_key:
        if not _disabled_logged:
            logger.info("TheHive not configured (THEHIVE_URL/API_KEY empty); integration disabled")
            _disabled_logged = True
        return False
    return True


def _mock_log(msg: str) -> None:
    global _mock_logged
    logger.info(f"[mock] thehive: {msg}")
    _mock_logged = True


def _headers() -> dict[str, str]:
    h = {
        "Authorization": f"Bearer {settings.thehive_api_key}",
        "Content-Type": "application/json",
    }
    if settings.thehive_organisation:
        h["X-Organisation"] = settings.thehive_organisation
    return h


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=15.0, verify=settings.thehive_verify_tls)


def _severity(priority_level: str | None) -> int:
    return _SEVERITY_MAP.get(str(priority_level or "").lower(), 2)


def _unique(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _extract_mitre_ids(ticket: dict) -> list[str]:
    ids: list[str] = []
    for m in (ticket.get("mitre_mappings") or []):
        if isinstance(m, dict):
            tid = m.get("technique_id")
            if tid:
                ids.append(str(tid))
        elif isinstance(m, str):
            ids.append(m)
    return _unique(ids)


def _extract_source_ips(ticket: dict) -> list[str]:
    ips: list[str] = []
    for key in ("source_ips", "ip_addresses"):
        for ip in (ticket.get(key) or []):
            if isinstance(ip, str):
                ips.append(ip)
    for ev in (ticket.get("events") or []):
        if isinstance(ev, dict):
            ip = ev.get("source_ip") or ev.get("sourceIPAddress")
            if isinstance(ip, str):
                ips.append(ip)
    return _unique(ips)


def _extract_principals(ticket: dict) -> list[str]:
    arns: list[str] = []
    for key in ("principals", "user_arns", "affected_principals"):
        for a in (ticket.get(key) or []):
            if isinstance(a, str):
                arns.append(a)
    au = ticket.get("affected_user")
    if isinstance(au, str) and au and au != "Unknown":
        arns.append(au)
    return _unique(arns)


def _build_description(ticket: dict) -> str:
    lines: list[str] = []
    lines.append(f"# SOC incident {ticket.get('ticket_id', 'unknown')}")
    lines.append("")
    lines.append(f"- **Severity / Priority**: {ticket.get('priority_level', 'Unknown')}")
    lines.append(f"- **Threat score**: {ticket.get('threat_score', 'n/a')}")
    lines.append(f"- **Attack hypothesis**: {ticket.get('attack_hypothesis', 'n/a')}")
    lines.append(f"- **AWS region**: {ticket.get('aws_region', 'n/a')}")
    lines.append(f"- **Affected user**: {ticket.get('affected_user', 'n/a')}")
    lines.append("")
    mitre = _extract_mitre_ids(ticket)
    if mitre:
        lines.append("## MITRE techniques")
        for tid in mitre:
            lines.append(f"- {tid}")
        lines.append("")
    events = ticket.get("events") or ticket.get("timeline") or []
    if events:
        lines.append("## Timeline")
        for ev in events[:25]:
            if isinstance(ev, dict):
                ts = ev.get("time") or ev.get("timestamp") or ""
                name = ev.get("type") or ev.get("event_name") or ev.get("eventName") or "event"
                lines.append(f"- {ts} {name}")
            else:
                lines.append(f"- {ev}")
        lines.append("")
    actions = ticket.get("automated_actions_taken") or []
    if actions:
        lines.append("## Actions attempted")
        for a in actions:
            lines.append(f"- {a}")
        lines.append("")
    manual = ticket.get("manual_actions_required") or []
    if manual:
        lines.append("## Manual actions required")
        for a in manual:
            lines.append(f"- {a}")
    return "\n".join(lines)


def _build_tags(ticket: dict) -> list[str]:
    tags = [
        "soc_agent",
        f"trace:{ticket.get('trace_id', 'unknown')}",
        f"aws_region:{ticket.get('aws_region', '')}",
    ]
    for tid in _extract_mitre_ids(ticket):
        tags.append(f"mitre:{tid}")
    return tags


def _build_payload(ticket: dict, pre_closed: bool) -> dict[str, Any]:
    return {
        "title": f"[SOC] {ticket.get('priority_level', 'Unknown')} incident: {ticket.get('ticket_id', 'unknown')}",
        "description": _build_description(ticket),
        "severity": _severity(ticket.get("priority_level")),
        "tlp": settings.thehive_tlp,
        "pap": settings.thehive_pap,
        "tags": _build_tags(ticket),
        "status": "Resolved" if pre_closed else "InProgress",
        "customFields": {
            "threat_score": {"float": ticket.get("threat_score")},
            "attack_hypothesis": {"string": ticket.get("attack_hypothesis", "") or ""},
        },
    }


async def _post_task(client: httpx.AsyncClient, base: str, case_id: str, title: str) -> None:
    try:
        r = await client.post(
            f"{base}/api/v1/case/{case_id}/task",
            headers=_headers(),
            json={"title": title, "status": "Waiting"},
        )
        if r.status_code // 100 != 2:
            logger.error(f"TheHive task create non-2xx: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.error(f"TheHive task create failed: {e}")


async def _post_observable(
    client: httpx.AsyncClient, base: str, case_id: str, data_type: str, data: str
) -> None:
    try:
        r = await client.post(
            f"{base}/api/v1/case/{case_id}/observable",
            headers=_headers(),
            json={
                "dataType": data_type,
                "data": data,
                "tags": ["from_soc_agent"],
                "tlp": settings.thehive_tlp,
                "pap": settings.thehive_pap,
                "ioc": False,
            },
        )
        if r.status_code // 100 != 2:
            logger.error(f"TheHive observable create non-2xx: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.error(f"TheHive observable create failed: {e}")


async def create_case(ticket: dict, pre_closed: bool = False) -> str | None:
    """Create a TheHive case (open or pre-closed) for a SOC ticket.

    Returns the case id on success, or None on no-op / error.
    """
    if settings.mock_mode:
        _mock_log(f"create_case ticket={ticket.get('ticket_id')} pre_closed={pre_closed}")
        return None
    if not _enabled():
        step.info("create_case", skipped=True, reason="thehive_not_configured")
        return None

    step.start("create_case",
               ticket_id=ticket.get("ticket_id"), pre_closed=pre_closed)
    base = settings.thehive_url.rstrip("/")
    payload = _build_payload(ticket, pre_closed)
    try:
        async with _client() as client:
            r = await client.post(f"{base}/api/v1/case", headers=_headers(), json=payload)
            if r.status_code // 100 != 2:
                logger.error(f"TheHive case create non-2xx: {r.status_code} {r.text[:200]}")
                return None
            try:
                data = r.json()
            except Exception:
                logger.error("TheHive case create: could not parse JSON body")
                return None
            case_id = str(data.get("_id") or data.get("id") or "")
            if not case_id:
                logger.error(f"TheHive case create: no id in response: {str(data)[:200]}")
                return None

            actions = ticket.get("automated_actions_taken") or []
            manual = ticket.get("manual_actions_required") or []
            for name in _unique([*actions, *manual]):
                await _post_task(client, base, case_id, str(name))

            for ip in _extract_source_ips(ticket):
                await _post_observable(client, base, case_id, "ip", ip)
            for arn in _extract_principals(ticket):
                await _post_observable(client, base, case_id, "other", arn)

            step.done("create_case", case_id=case_id, pre_closed=pre_closed,
                      status_code=r.status_code)
            return case_id
    except Exception as e:
        logger.error(f"TheHive case create failed: {e}")
        return None


async def list_recently_closed_cases(since_hours: int = 24) -> list[dict]:
    """Return cases resolved within the last `since_hours` hours."""
    if settings.mock_mode:
        _mock_log(f"list_recently_closed_cases since_hours={since_hours}")
        return []
    if not _enabled():
        return []

    base = settings.thehive_url.rstrip("/")
    since_ms = int(
        (datetime.now(timezone.utc) - timedelta(hours=since_hours)).timestamp() * 1000
    )
    query = {
        "query": [
            {"_name": "listCase"},
            {
                "_name": "filter",
                "_and": [
                    {"_field": "status", "_value": "Resolved"},
                    {"_gte": {"_field": "endDate", "_value": since_ms}},
                ],
            },
        ]
    }
    try:
        async with _client() as client:
            r = await client.post(
                f"{base}/api/v1/query", headers=_headers(), json=query
            )
            if r.status_code // 100 != 2:
                logger.error(f"TheHive query non-2xx: {r.status_code} {r.text[:200]}")
                return []
            try:
                data = r.json()
            except Exception:
                logger.error("TheHive query: could not parse JSON body")
                return []
            if not isinstance(data, list):
                logger.error("TheHive query: unexpected response shape")
                return []
            out: list[dict] = []
            for c in data:
                if not isinstance(c, dict):
                    continue
                out.append(
                    {
                        "id": c.get("_id") or c.get("id"),
                        "title": c.get("title"),
                        "status": c.get("status"),
                        "resolutionStatus": c.get("resolutionStatus"),
                        "summary": c.get("summary"),
                        "tags": c.get("tags", []) or [],
                        "customFields": c.get("customFields", {}) or {},
                    }
                )
            return out
    except Exception as e:
        logger.error(f"TheHive list_recently_closed_cases failed: {e}")
        return []


async def get_case_resolution(case_id: str) -> dict | None:
    """Fetch a single case and return its resolution fields."""
    if settings.mock_mode:
        _mock_log(f"get_case_resolution case_id={case_id}")
        return None
    if not _enabled():
        return None

    base = settings.thehive_url.rstrip("/")
    try:
        async with _client() as client:
            r = await client.get(f"{base}/api/v1/case/{case_id}", headers=_headers())
            if r.status_code // 100 != 2:
                logger.error(f"TheHive get case non-2xx: {r.status_code} {r.text[:200]}")
                return None
            try:
                c = r.json()
            except Exception:
                logger.error("TheHive get case: could not parse JSON body")
                return None
            if not isinstance(c, dict):
                return None
            return {
                "resolutionStatus": c.get("resolutionStatus"),
                "summary": c.get("summary"),
                "tags": c.get("tags", []) or [],
                "customFields": c.get("customFields", {}) or {},
            }
    except Exception as e:
        logger.error(f"TheHive get_case_resolution failed: {e}")
        return None
