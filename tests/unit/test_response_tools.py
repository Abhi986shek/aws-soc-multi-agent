"""Unit tests for Stage 4 (Response) tools."""
from __future__ import annotations

from agents.response.tools.aws_mitigation import execute_aws_mitigation
from agents.response.tools.dynamodb_client import DynamoDBTicketClient


def _statuses(result: dict) -> list[str]:
    return [r.get("details", {}).get("status") for r in result.get("execution_results", [])]


def test_execute_aws_mitigation_mock(mock_settings):
    mock_settings.auto_mitigation_enabled = True
    mock_settings.mock_mode = True
    result = execute_aws_mitigation(["enable_cloudtrail"], "jsmith", [])
    assert "mock" in _statuses(result)


def test_execute_aws_mitigation_dry_run(mock_settings):
    mock_settings.auto_mitigation_enabled = True
    mock_settings.mock_mode = False
    mock_settings.dry_run = True
    result = execute_aws_mitigation(["enable_cloudtrail"], "jsmith", [])
    assert "dry_run" in _statuses(result)


def test_execute_aws_mitigation_disabled(mock_settings):
    mock_settings.auto_mitigation_enabled = False
    result = execute_aws_mitigation(["enable_cloudtrail"], "jsmith", [])
    assert "disabled_by_setting" in _statuses(result)


def test_execute_aws_mitigation_unknown_action(mock_settings):
    mock_settings.auto_mitigation_enabled = True
    result = execute_aws_mitigation(["definitely_not_a_real_action"], "jsmith", [])
    r0 = result["execution_results"][0]
    assert r0["success"] is False
    assert "Unknown action" in (r0.get("error") or "")


def test_dynamodb_client_mock_no_boto3(mock_settings, monkeypatch):
    # If boto3 were touched in mock_mode, importing it in the client would fail
    # loudly; we assert it isn't called by never letting boto3 be imported.
    called = {"n": 0}

    def _fail(*a, **kw):
        called["n"] += 1
        raise RuntimeError("boto3 should not be called in mock_mode")

    import sys
    if "boto3" in sys.modules:
        monkeypatch.setattr(sys.modules["boto3"], "resource", _fail, raising=False)

    client = DynamoDBTicketClient()
    ok = client.create_ticket({"ticket_id": "T-1", "priority_level": "Critical"})
    assert ok is True
    assert called["n"] == 0
