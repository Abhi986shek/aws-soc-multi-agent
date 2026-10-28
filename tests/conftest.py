"""Shared pytest fixtures for the SOC agent test suite."""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set MOCK_MODE + mock model ids BEFORE any project module imports config.
os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("MODEL_FAST", "mock-fast")
os.environ.setdefault("MODEL_SMART", "mock-smart")
# Neutralize external service creds.
for _k in (
    "ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "SLACK_APPROVAL_CHANNEL",
    "EMAIL_FROM", "EMAIL_TO", "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN",
    "PAGERDUTY_ROUTING_KEY", "THEHIVE_URL", "THEHIVE_API_KEY",
    "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY",
):
    os.environ.setdefault(_k, "")


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def mock_settings(monkeypatch):
    """Force MOCK_MODE + empty external creds via monkeypatching config.settings."""
    from config import settings
    monkeypatch.setattr(settings, "mock_mode", True)
    monkeypatch.setattr(settings, "dry_run", False)
    monkeypatch.setattr(settings, "auto_mitigation_enabled", False)
    monkeypatch.setattr(settings, "slack_webhook_url", "")
    monkeypatch.setattr(settings, "slack_approval_channel", "")
    monkeypatch.setattr(settings, "email_from", "")
    monkeypatch.setattr(settings, "email_to", "")
    monkeypatch.setattr(settings, "splunk_hec_url", "")
    monkeypatch.setattr(settings, "splunk_hec_token", "")
    monkeypatch.setattr(settings, "pagerduty_routing_key", "")
    monkeypatch.setattr(settings, "thehive_url", "")
    monkeypatch.setattr(settings, "thehive_api_key", "")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "greynoise_api_key", "")
    return settings


@pytest.fixture
def sample_cloudtrail_event():
    """Load the first canned CloudTrail event from batch01.json."""
    data = json.loads((FIXTURES / "cloudtrail_events" / "batch01.json").read_text())
    return data[0]


@pytest.fixture
def sample_ticket():
    """A canonical PRIORITY ticket dict for integration tests."""
    return {
        "ticket_id": "SOC-PRIORITY-20250723024600",
        "priority_level": "Critical",
        "severity": "Critical",
        "threat_score": 0.93,
        "attack_hypothesis": "Insider Data Exfiltration with Anti-Forensics",
        "aws_region": "us-east-1",
        "affected_user": "arn:aws:iam::123456789012:user/jsmith",
        "trace_id": "trace-abc-123",
        "mitre_mappings": ["T1537", "T1562.008"],
        "source_ips": ["203.0.113.45"],
        "principals": ["arn:aws:iam::123456789012:user/jsmith"],
        "automated_actions_taken": ["disable_user_account", "rotate_access_keys"],
        "manual_actions_required": [],
        "events": [
            {"time": "2025-07-23T02:41:12Z", "type": "GetObject"},
            {"time": "2025-07-23T02:42:03Z", "type": "StopLogging"},
        ],
    }


class _RecordingPost:
    def __init__(self):
        self.calls = []

    async def __call__(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.json = MagicMock(return_value={})
        return resp


@pytest.fixture
def patched_httpx(monkeypatch):
    """Patch httpx.AsyncClient so tests can record POST/GET calls."""
    import httpx

    recorder = _RecordingPost()

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            self.calls = recorder.calls
            self.post = recorder
            self.get = recorder

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    return recorder
