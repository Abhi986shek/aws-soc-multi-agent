"""Unit tests for Stage 1 (Threat Detection) tools."""
from __future__ import annotations

from agents.detection.tools.threat_scorer import get_threat_patterns
from agents.detection.tools.fetch_cloudtrail import fetch_cloudtrail_events


def test_get_threat_patterns_non_empty():
    text = get_threat_patterns()
    assert isinstance(text, str)
    assert len(text) > 0
    # At least one known threat name from threats.yaml should appear.
    assert any(name in text for name in (
        "iam_privilege_escalation", "credential_exfiltration", "defense_evasion"
    ))


def test_fetch_cloudtrail_events_mock_mode(mock_settings):
    events = fetch_cloudtrail_events(lookback_seconds=30)
    assert isinstance(events, list)
    assert len(events) >= 5
    ids = {e.get("event_id") for e in events}
    assert "evt-0001-getobject" in ids
    assert "evt-0002-stoplogging" in ids
