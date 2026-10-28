"""Integration tests for the TheHive case-management integration."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from integrations import thehive


@pytest.mark.asyncio
async def test_create_case_noop_when_unconfigured(mock_settings):
    mock_settings.mock_mode = False
    mock_settings.thehive_url = ""
    mock_settings.thehive_api_key = ""
    with patch("integrations.thehive.httpx.AsyncClient") as m:
        result = await thehive.create_case({"ticket_id": "T-1"})
        m.assert_not_called()
    assert result is None


@pytest.mark.asyncio
async def test_create_case_mock_mode(mock_settings):
    mock_settings.mock_mode = True
    with patch("integrations.thehive.httpx.AsyncClient") as m:
        result = await thehive.create_case({"ticket_id": "T-1"})
        m.assert_not_called()
    assert result is None


@pytest.mark.asyncio
async def test_create_case_posts_all(mock_settings, sample_ticket, monkeypatch):
    mock_settings.mock_mode = False
    mock_settings.thehive_url = "https://hive.example"
    mock_settings.thehive_api_key = "key"

    calls = []

    class FakeClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            calls.append({"url": url, **kw})
            resp = MagicMock()
            resp.status_code = 201
            resp.json = MagicMock(return_value={"_id": "case-1"})
            resp.text = ""
            return resp

    monkeypatch.setattr(thehive.httpx, "AsyncClient", FakeClient)
    case_id = await thehive.create_case(sample_ticket)
    assert case_id == "case-1"
    assert len(calls) >= 3
    first = calls[0]
    assert first["url"].endswith("/api/v1/case")
    assert first["headers"]["Authorization"].startswith("Bearer ")
    payload = first["json"]
    assert payload["severity"] == 4  # Critical


@pytest.mark.asyncio
async def test_list_recently_closed_noop_when_unconfigured(mock_settings):
    mock_settings.mock_mode = False
    mock_settings.thehive_url = ""
    with patch("integrations.thehive.httpx.AsyncClient") as m:
        result = await thehive.list_recently_closed_cases()
        m.assert_not_called()
    assert result == []


def test_severity_map_critical():
    assert thehive._severity("Critical") == 4
    assert thehive._severity("High") == 3
    assert thehive._severity("low") == 1
