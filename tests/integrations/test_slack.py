"""Integration tests for the Slack alert / approval integration."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from integrations import slack


@pytest.mark.asyncio
async def test_send_alert_noop_when_no_webhook(mock_settings):
    mock_settings.slack_webhook_url = ""
    with patch("integrations.slack.httpx.AsyncClient") as mock_client:
        await slack.send_alert("hello")
        mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_send_alert_posts_when_configured(mock_settings, patched_httpx):
    mock_settings.slack_webhook_url = "https://hooks.slack.example/xyz"
    await slack.send_alert("hello world")
    assert len(patched_httpx.calls) == 1
    call = patched_httpx.calls[0]
    assert call["url"] == "https://hooks.slack.example/xyz"
    assert call["json"]["text"] == "hello world"


@pytest.mark.asyncio
async def test_request_approval_auto_approve(mock_settings, patched_httpx):
    mock_settings.slack_approval_mode = "auto_approve"
    ok = await slack.request_approval("trace-1", {"threat_score": 0.9}, "disable_user_account")
    assert ok is True


@pytest.mark.asyncio
async def test_request_approval_deny(mock_settings, patched_httpx):
    mock_settings.slack_approval_mode = "deny"
    ok = await slack.request_approval("trace-1", {"threat_score": 0.9}, "disable_user_account")
    assert ok is False


@pytest.mark.asyncio
async def test_request_approval_manual_approve(mock_settings, patched_httpx, tmp_path, monkeypatch):
    mock_settings.slack_approval_mode = "manual"
    mock_settings.slack_approval_timeout_seconds = 5
    monkeypatch.chdir(tmp_path)
    approvals = tmp_path / "approvals"
    approvals.mkdir()
    decision = approvals / "trace-m_disable_user_account.decision"
    decision.write_text("approve")
    ok = await slack.request_approval("trace-m", {}, "disable_user_account")
    assert ok is True


@pytest.mark.asyncio
async def test_request_approval_manual_timeout(mock_settings, patched_httpx, tmp_path, monkeypatch):
    mock_settings.slack_approval_mode = "manual"
    mock_settings.slack_approval_timeout_seconds = 0  # immediate timeout
    monkeypatch.chdir(tmp_path)
    ok = await slack.request_approval("trace-t", {}, "disable_user_account")
    assert ok is False
