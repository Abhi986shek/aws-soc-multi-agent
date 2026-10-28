"""Unit tests for the forensic-investigator sidecar tool."""
from __future__ import annotations

from agents.sidecars.forensics.tools.forensic_investigator import (
    conduct_forensic_investigation,
)


def test_conduct_forensic_investigation_shape():
    event_list = [
        {"event_id": "e1", "timestamp": "2025-07-23T02:41:12Z", "type": "large_s3_download", "score": 0.9},
        {"event_id": "e2", "timestamp": "2025-07-23T02:42:03Z", "type": "log_tampering", "score": 0.95},
        {"event_id": "e3", "timestamp": "2025-07-23T02:43:41Z", "type": "policy_change", "score": 0.85},
    ]
    details = {
        "e1": {"action": "GetObject", "user": "jsmith", "resource": "arn:aws:s3:::pii", "source_ip": "1.2.3.4"},
        "e2": {"action": "StopLogging", "user": "jsmith", "resource": "trail", "source_ip": "1.2.3.4"},
        "e3": {"action": "PutBucketPolicy", "user": "jsmith", "resource": "arn:aws:s3:::pii", "source_ip": "1.2.3.4"},
    }
    report = conduct_forensic_investigation(
        event_list=event_list,
        event_details=details,
        mitigation_actions=["disable_user_account"],
        attack_hypothesis="Insider Data Exfiltration",
    )
    for key in ("report_id", "timeline", "indicators_of_compromise", "severity"):
        assert key in report
    # evidence key present (aliased as evidence_collected in code)
    assert "evidence_collected" in report
    # Timeline is sorted ascending by timestamp.
    ts = [entry.get("timestamp", "") for entry in report["timeline"]]
    assert ts == sorted(ts)
