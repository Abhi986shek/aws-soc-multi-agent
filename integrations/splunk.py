"""Splunk HEC integration. No-op when SPLUNK_HEC_URL empty or MOCK_MODE."""
from __future__ import annotations

import time

import httpx

from config import settings
from logger import get_step_logger

step = get_step_logger("splunk")


async def send_event(event: dict, sourcetype: str = "soc_agent:incident") -> dict:
    url = settings.splunk_hec_url
    token = settings.splunk_hec_token
    if not url or not token:
        step.info("send_event", skipped=True, reason="splunk_not_configured")
        return {"status": "skipped", "reason": "splunk_not_configured"}

    step.start("send_event", sourcetype=sourcetype)

    if settings.mock_mode:
        step.done("send_event", mock=True, sourcetype=sourcetype)
        return {"status": "mock"}

    payload = {
        "event": event,
        "sourcetype": sourcetype,
        "source": "soc_agent",
        "index": settings.splunk_index or "main",
        "time": int(time.time()),
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=settings.splunk_verify_tls) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Splunk {token}"},
                json=payload,
            )
            if resp.status_code // 100 != 2:
                step.error("Splunk HEC non-2xx",
                           status_code=resp.status_code, body=resp.text[:200])
                return {"status": "error", "code": resp.status_code}
        step.done("send_event", status_code=resp.status_code)
        return {"status": "sent"}
    except Exception as e:
        step.error("Splunk HEC send failed", exc=e)
        return {"status": "error", "error": str(e)}
