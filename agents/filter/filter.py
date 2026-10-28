"""Stage 0 - deterministic pre-filter.

No LLM. Drops known-benign events (reads, allowlisted principals, etc.) so
the expensive LLM stages only see ambiguous events.
"""
from __future__ import annotations

from logger import get_step_logger

from .rules.benign_events import is_benign_read
from .rules.allowlist_check import is_allowlisted


class Stage0Filter:
    async def run(self, events: list[dict]) -> tuple[list[dict], dict]:
        """Return (kept_events, summary_dict)."""
        step = get_step_logger("stage0")
        kept = []
        dropped_benign = 0
        dropped_allowlist = 0
        for event in events:
            eid = event.get("event_id")
            if is_benign_read(event):
                step.info("dropped", event_id=eid, reason="benign_read")
                dropped_benign += 1
                continue
            if is_allowlisted(event):
                step.info("dropped", event_id=eid, reason="allowlisted")
                dropped_allowlist += 1
                continue
            kept.append(event)

        summary = {
            "in": len(events),
            "kept": len(kept),
            "dropped": len(events) - len(kept),
            "dropped_benign": dropped_benign,
            "dropped_allowlist": dropped_allowlist,
        }
        return kept, summary
