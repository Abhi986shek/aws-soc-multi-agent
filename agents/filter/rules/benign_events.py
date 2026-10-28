"""Read-only CloudTrail events are almost always benign at scale — drop them
here so the LLM pipeline never sees them.
"""
from __future__ import annotations

BENIGN_PREFIXES = ("Describe", "List", "Get", "Head", "Lookup", "BatchGet")

# High-value reads we DO want to inspect even though they start with Get.
SENSITIVE_READS = {
    "GetSecretValue",
    "GetParameter",
    "GetPasswordData",
    "GetFederationToken",
}


def is_benign_read(event: dict) -> bool:
    name = event.get("eventName", "")
    if name in SENSITIVE_READS:
        return False
    return name.startswith(BENIGN_PREFIXES)
