"""Integration tests for the PagerDuty Events API integration."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from integrations import pagerduty


@pytest.mark.asyncio
async def test_trigger_incident_noop_no_routing_key(mock_settings):
    mock_settings.mock_mode = False
    mock_settings.pagerduty_routing_key = ""
    with patch("integrations.pagerduty.httpx.AsyncClient") as m:
        await pagerduty.trigger_incident({"ticket_id": "T-1"})
        m.assert_not_called()


@pytest.mark.asyncio
async def test_trigger_incident_mock_mode(mock_settings):
    mock_settings.mock_mode = True
    mock_settings.pagerduty_routing_key = "rk-1"
    with patch("integrations.pagerduty.httpx.AsyncClient") as m:
        await pagerduty.trigger_incident({"ticket_id": "T-1"})
        m.assert_not_called()


@pytest.mark.asyncio
async def test_trigger_incident_posts_shape(mock_settings, patched_httpx, sample_ticket):
    mock_settings.mock_mode = False
    mock_settings.pagerduty_routing_key = "rk-abc"
    await pagerduty.trigger_incident(sample_ticket)
    assert len(patched_httpx.calls) == 1
    call = patched_httpx.calls[0]
    assert call["url"] == "https://events.pagerduty.com/v2/enqueue"
    body = call["json"]
    assert body["routing_key"] == "rk-abc"
    assert body["event_action"] == "trigger"
    assert body["dedup_key"] == sample_ticket["ticket_id"]
    assert body["payload"]["severity"] == "critical"
    assert "custom_details" in body["payload"]


@pytest.mark.parametrize("level,expected", [
    ("Critical", "critical"),
    ("High", "error"),
    ("Medium", "warning"),
    ("Low", "info"),
    ("weird", "info"),
])
def test_severity_mapping(level, expected):
    assert pagerduty._map_severity(level) == expected
