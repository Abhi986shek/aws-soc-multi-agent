"""End-to-end smoke test for the SOC agent orchestrator in MOCK_MODE."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.mark.asyncio
async def test_full_pipeline_mock_mode(mock_settings):
    # Ensure strands.Agent is mocked so no LLM network call happens.
    from mock_llm import install as install_mock_llm
    install_mock_llm()

    from agents.orchestrator import run_soc_workflow_once

    batch = json.loads((FIXTURES / "cloudtrail_events" / "batch01.json").read_text())
    result = await run_soc_workflow_once(initial_batch=batch)

    assert result["status"] == "success"

    executed = {a["agent"] for a in result["agents_executed"]}
    for name in ("Threat Detection", "Enrichment", "Triage", "Response",
                 "Forensics", "Learning"):
        assert name in executed, f"missing stage: {name}"

    detection = next(a for a in result["agents_executed"] if a["agent"] == "Threat Detection")
    assert detection["result"].get("flagged_count", 0) > 0

    triage = next(a for a in result["agents_executed"] if a["agent"] == "Triage")
    assert triage["result"]["priority_level"] in {"Critical", "High", "Medium", "Low"}

    response = next(a for a in result["agents_executed"] if a["agent"] == "Response")
    assert response["result"]["tickets_created"] >= 1
