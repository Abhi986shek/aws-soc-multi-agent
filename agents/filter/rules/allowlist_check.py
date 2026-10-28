"""Allowlist check against config/rules/allowlist.yaml."""
from __future__ import annotations

import fnmatch
from functools import lru_cache
import yaml

from config import settings


@lru_cache
def _allowlist() -> dict:
    with open(settings.rules_dir / "allowlist.yaml") as f:
        return yaml.safe_load(f) or {}


def is_allowlisted(event: dict) -> bool:
    al = _allowlist()
    arn = (event.get("userIdentity") or {}).get("arn", "")
    for pattern in al.get("principals", []) or []:
        if fnmatch.fnmatch(arn, pattern):
            return True
    ip = event.get("sourceIPAddress", "")
    if ip and ip in (al.get("source_ips") or []):
        return True
    ua = event.get("userAgent", "")
    for pattern in al.get("user_agents", []) or []:
        if fnmatch.fnmatch(ua, pattern):
            return True
    return False
