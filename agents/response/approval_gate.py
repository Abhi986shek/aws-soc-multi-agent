"""Human-in-the-loop approval via Slack for destructive actions."""
from __future__ import annotations

from uuid import uuid4

from config import settings
from integrations.slack import request_approval


DESTRUCTIVE = {
    "disable_user_account",
    "rotate_access_keys",
    "revoke_access_key",
    "quarantine_principal",
    "isolate_account",
    "detach_policy",
    "disable_user",
    "block_source_ip",
    "terminate_instance",
    "delete_credentials",
}


class ApprovalGate:
    async def request(self, trace_id: str | None, triage: dict, action: str) -> bool:
        if action not in DESTRUCTIVE:
            return True
        if not settings.slack_approval_channel:
            return False  # fail closed: no channel = no approval
        return await request_approval(trace_id or str(uuid4()), triage, action)
