"""Unit tests for Stage 3 (Triage) tools."""
from __future__ import annotations

from agents.triage.tools.risk_calculator import calculate_threat_risk
from agents.triage.tools.data_classifier import classify_data_sensitivity
from agents.triage.tools.severity_scorer import score_threat_severity
from agents.triage.tools.action_recommender import recommend_mitigation_actions


def test_calculate_threat_risk_weights():
    result = calculate_threat_risk(
        ti_confidence=0.9,
        mitre_severity="Critical",
        data_sensitivity="PII",
        user_role="standard_user",
        event_count=5,
    )
    assert 0.0 <= result["risk_score"] <= 1.0
    assert set(result["risk_factors"].keys()) == {
        "threat_intelligence", "mitre_severity", "data_sensitivity",
        "user_authorization", "event_volume",
    }
    assert result["total_weight"] == 1.0


def test_classify_data_sensitivity_pii():
    result = classify_data_sensitivity(
        resources_accessed=["arn:aws:s3:::acme-customer-pii-prod/x.csv"],
        data_volume=5_000_000_000,
        resource_metadata={},
    )
    assert result["overall_classification"] == "PII"


def test_score_threat_severity_exfiltration_higher_than_unusual_access():
    exf = score_threat_severity(
        behaviors=["data_exfiltration", "log_tampering"],
        timing_context={"is_off_hours": True, "action_velocity": 15},
        user_context={"role": "unauthorized"},
        attack_stage="Data Exfiltration",
    )
    ua = score_threat_severity(
        behaviors=["unusual_access"],
        timing_context={},
        user_context={},
        attack_stage="Initial Access / Reconnaissance",
    )
    assert exf["severity_score"] > ua["severity_score"]


def test_recommend_mitigation_actions_known_vocabulary():
    result = recommend_mitigation_actions(
        severity_level="Critical",
        attack_type="data_exfiltration",
        behaviors=["log_tampering"],
        resources_affected=["arn:aws:s3:::pii"],
    )
    names = {a["action"] for a in result["recommended_actions"]}
    assert "disable_user_account" in names
    assert "rotate_access_keys" in names
    assert "enable_cloudtrail" in names
