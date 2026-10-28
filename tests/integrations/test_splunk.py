"""Integration tests for the Splunk HEC integration."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from integrations import splunk


@pytest.mark.asyncio
async def test_send_event_noop_when_url_empty(mock_settings):
    mock_settings.splunk_hec_url = ""
    with patch("integrations.splunk.httpx.AsyncClient") as m:
        r = await splunk.send_event({"a": 1})
        m.assert_not_called()
    assert r["status"] == "skipped"


@pytest.mark.asyncio
async def test_send_event_noop_in_mock_mode(mock_settings):
    mock_settings.splunk_hec_url = "https://splunk.example/hec"
    mock_settings.splunk_hec_token = "tok"
    mock_settings.mock_mode = True
    with patch("integrations.splunk.httpx.AsyncClient") as m:
        r = await splunk.send_event({"a": 1})
        m.assert_not_called()
    assert r["status"] == "mock"


@pytest.mark.asyncio
async def test_send_event_posts_when_configured(mock_settings, patched_httpx):
    mock_settings.splunk_hec_url = "https://splunk.example/hec"
    mock_settings.splunk_hec_token = "sekret"
    mock_settings.splunk_index = "soc"
    mock_settings.mock_mode = False
    r = await splunk.send_event({"ticket_id": "T-1"}, sourcetype="soc:test")
    assert r["status"] == "sent"
    assert len(patched_httpx.calls) == 1
    call = patched_httpx.calls[0]
    body = call["json"]
    assert body["event"] == {"ticket_id": "T-1"}
    assert body["sourcetype"] == "soc:test"
    assert body["source"] == "soc_agent"
    assert body["index"] == "soc"
    assert call["headers"]["Authorization"] == "Splunk sekret"
