"""Unit tests for Stage 2 (Enrichment) tools."""
from __future__ import annotations

from agents.enrichment.tools.correlation_analyzer import (
    parse_event_signals,
    is_off_hours_access,
)
from agents.enrichment.tools.mitre_mapper import map_to_mitre_attack
from agents.enrichment.tools.pattern_matcher import match_attack_patterns


def test_parse_event_signals_flags_large_s3_download(mock_settings):
    ev = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventTime": "2025-07-23T02:41:12Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/jsmith"},
    }
    signals = parse_event_signals(ev)
    assert signals["large_s3_download"]["present"] is True


def test_parse_event_signals_flags_log_tampering(mock_settings):
    ev = {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "eventTime": "2025-07-23T02:42:03Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/jsmith"},
    }
    signals = parse_event_signals(ev)
    assert signals["log_tampering_attempt"]["present"] is True


def test_is_off_hours_access():
    assert is_off_hours_access("2025-07-23T02:40:00Z") is True
    assert is_off_hours_access("2025-07-23T14:00:00Z") is False


def test_map_to_mitre_attack_returns_tactics(mock_settings):
    result = map_to_mitre_attack(["large_s3_download"], {})
    assert result["total_techniques"] >= 1
    assert result["tactics"]


def test_match_attack_patterns_insider_exfiltration():
    seq = [
        {"type": "unusual_access"},
        {"type": "large_download"},
        {"type": "log_tampering"},
    ]
    result = match_attack_patterns(seq, time_window_minutes=60)
    names = {p["pattern_name"] for p in result["matched_patterns"]}
    assert "insider_exfiltration_sequence" in names
