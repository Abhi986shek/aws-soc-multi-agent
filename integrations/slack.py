"""Slack alerts + approval gate."""
from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from config import settings
from logger import get_step_logger

step = get_step_logger("slack")


async def send_alert(text: str) -> None:
    """Post `text` to the configured Slack incoming webhook."""
    url = settings.slack_webhook_url
    if not url:
        step.info("send_alert skipped", skipped=True, reason="webhook_not_configured")
        return
    step.start("send_alert", bytes=len(text))
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={"text": text})
        step.done("send_alert", status_code=resp.status_code)
    except Exception as e:
        step.error("Slack alert failed", exc=e)


async def request_approval(trace_id: str, triage: dict, action: str) -> bool:
    """Request human approval for a destructive action.

    Modes: auto_approve | deny | manual (see settings.slack_approval_mode).
    """
    alert_text = (
        f":rotating_light: SOC approval requested\n"
        f"trace_id: {trace_id}\n"
        f"action: {action}\n"
        f"triage: {triage}"
    )
    await send_alert(alert_text)

    mode = (settings.slack_approval_mode or "deny").lower()
    step.start("request_approval", action=action, mode=mode, trace=trace_id)

    if mode == "auto_approve":
        step.done("granted", reason="auto_approve", action=action)
        return True
    if mode == "deny":
        step.done("denied", reason="deny_mode", action=action)
        return False
    if mode == "manual":
        approvals_dir = Path.cwd() / "approvals"
        approvals_dir.mkdir(parents=True, exist_ok=True)
        decision_path = approvals_dir / f"{trace_id}_{action}.decision"
        step.info("awaiting manual approval", path=str(decision_path))
        deadline = asyncio.get_event_loop().time() + settings.slack_approval_timeout_seconds
        while asyncio.get_event_loop().time() < deadline:
            if decision_path.exists():
                try:
                    decision = decision_path.read_text(encoding="utf-8").strip().lower()
                except Exception:
                    decision = ""
                if decision == "approve":
                    step.done("granted", reason="manual_approve", action=action)
                    return True
                if decision == "deny":
                    step.done("denied", reason="manual_deny", action=action)
                    return False
            await asyncio.sleep(2.0)
        step.warn("manual approval timed out",
                  seconds=settings.slack_approval_timeout_seconds, action=action)
        return False

    step.warn("unknown slack_approval_mode; failing closed", mode=mode)
    return False
