"""Unit tests for the destructive-action approval gate."""
from __future__ import annotations

import pytest

from agents.response.approval_gate import ApprovalGate


@pytest.mark.asyncio
async def test_non_destructive_action_bypasses_slack(mock_settings):
    gate = ApprovalGate()
    approved = await gate.request("trace-1", {}, "enable_cloudtrail")
    assert approved is True


@pytest.mark.asyncio
async def test_destructive_auto_approve(mock_settings, monkeypatch):
    mock_settings.slack_approval_channel = "#soc"
    mock_settings.slack_approval_mode = "auto_approve"
    gate = ApprovalGate()
    approved = await gate.request("trace-1", {"threat_score": 0.9}, "disable_user_account")
    assert approved is True


@pytest.mark.asyncio
async def test_destructive_deny(mock_settings, monkeypatch):
    mock_settings.slack_approval_channel = "#soc"
    mock_settings.slack_approval_mode = "deny"
    gate = ApprovalGate()
    approved = await gate.request("trace-1", {"threat_score": 0.9}, "disable_user_account")
    assert approved is False
