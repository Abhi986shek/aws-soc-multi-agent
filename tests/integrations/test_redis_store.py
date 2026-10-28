"""Integration tests for the Redis-backed correlation-window store."""
from __future__ import annotations

import pytest

from integrations import redis_store


@pytest.mark.asyncio
async def test_record_and_get_roundtrip_mock(mock_settings):
    # Reset in-process store to avoid cross-test contamination.
    redis_store._mock_store.clear()
    arn = "arn:aws:iam::1:user/roundtrip"
    ev = {"eventName": "GetObject", "userIdentity": {"arn": arn}}
    await redis_store.record_event(ev)
    got = await redis_store.get_recent_by_principal(arn)
    assert len(got) == 1
    assert got[0]["eventName"] == "GetObject"


@pytest.mark.asyncio
async def test_sync_and_async_agree_mock(mock_settings):
    redis_store._mock_store.clear()
    arn = "arn:aws:iam::1:user/sync"
    ev = {"eventName": "StopLogging", "userIdentity": {"arn": arn}}
    await redis_store.record_event(ev)
    async_val = await redis_store.get_recent_by_principal(arn)
    sync_val = redis_store.get_recent_by_principal_sync(arn)
    assert async_val == sync_val
