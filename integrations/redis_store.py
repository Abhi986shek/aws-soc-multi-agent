"""Redis-backed rolling window for correlation.

In MOCK_MODE, backed by an in-process dict instead of a real Redis instance.
Exposes both async (used by the orchestrator) and sync (used inside Strands
tool functions) helpers.
"""
from __future__ import annotations

import json
from collections import deque

from config import settings

_client = None
_sync_client = None
_mock_store: dict[str, deque] = {}


def _r():
    global _client
    if settings.mock_mode:
        return None
    if _client is None:
        import redis.asyncio as redis
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


def _r_sync():
    global _sync_client
    if settings.mock_mode:
        return None
    if _sync_client is None:
        import redis
        _sync_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _sync_client


async def record_event(event: dict) -> None:
    arn = (event.get("userIdentity") or {}).get("arn")
    if not arn:
        return
    if settings.mock_mode:
        _mock_store.setdefault(arn, deque(maxlen=1000)).appendleft(event)
        return
    client = _r()
    key = f"soc:events:{arn}"
    await client.lpush(key, json.dumps(event))
    await client.ltrim(key, 0, 999)
    await client.expire(key, settings.correlation_window_seconds)


async def get_recent_by_principal(arn: str) -> list[dict]:
    if settings.mock_mode:
        return list(_mock_store.get(arn, []))
    raw = await _r().lrange(f"soc:events:{arn}", 0, -1)
    return [json.loads(r) for r in raw]


def get_recent_by_principal_sync(arn: str) -> list[dict]:
    """Sync variant for use inside sync Strands tool functions."""
    if not arn:
        return []
    if settings.mock_mode:
        return list(_mock_store.get(arn, []))
    try:
        raw = _r_sync().lrange(f"soc:events:{arn}", 0, -1)
        return [json.loads(r) for r in raw]
    except Exception:
        return []
