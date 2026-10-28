"""SES email integration. Graceful no-op when EMAIL_FROM / EMAIL_TO are empty."""
from __future__ import annotations

import asyncio

from config import settings
from logger import get_step_logger

step = get_step_logger("email")


async def send_email(subject: str, body_text: str, body_html: str | None = None) -> dict:
    """Send an email via AWS SES. No-op if config is missing or MOCK_MODE."""
    email_from = settings.email_from or ""
    email_to = settings.email_to or ""
    if not email_from or not email_to:
        step.info("send_email", skipped=True, reason="email_not_configured")
        return {"status": "skipped", "reason": "email_not_configured"}

    to_addrs = [a.strip() for a in email_to.split(",") if a.strip()]
    if not to_addrs:
        step.info("send_email", skipped=True, reason="no_recipients")
        return {"status": "skipped", "reason": "no_recipients"}

    step.start("send_email", subject=subject, recipients=len(to_addrs))

    if settings.mock_mode:
        step.done("send_email", mock=True, subject=subject)
        return {"status": "mock", "subject": subject, "to": to_addrs}

    def _send() -> dict:
        import boto3
        client = boto3.client("ses", region_name=settings.aws_region)
        message: dict = {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
        }
        if body_html:
            message["Body"]["Html"] = {"Data": body_html, "Charset": "UTF-8"}
        return client.send_email(
            Source=email_from,
            Destination={"ToAddresses": to_addrs},
            Message=message,
        )

    try:
        resp = await asyncio.to_thread(_send)
        msg_id = resp.get("MessageId") if isinstance(resp, dict) else None
        step.done("send_email", message_id=msg_id)
        return {"status": "sent", "message_id": msg_id}
    except Exception as e:
        step.error("SES send_email failed", exc=e)
        return {"status": "error", "error": str(e)}
