"""Unit tests for the learning-engine sidecar tool."""
from __future__ import annotations

import pytest

from agents.sidecars.learning.tools.learning_engine import (
    update_learning_models,
    learn_from_closed_cases,
)


def test_update_learning_models_returns_updates_applied():
    result = update_learning_models(
        incident_data={"incident_id": "INC-1", "attack_hypothesis": "Insider Exfil"},
        attack_patterns=[{"pattern": "insider"}],
        iocs={"ip_addresses": ["1.2.3.4"], "user_accounts": ["jsmith"]},
        mitigation_effectiveness={"disable_user_account": {"success": True}},
    )
    assert isinstance(result.get("updates_applied"), list)
    assert len(result["updates_applied"]) > 0


@pytest.mark.asyncio
async def test_learn_from_closed_cases_no_thehive(mock_settings):
    result = await learn_from_closed_cases(since_hours=24)
    assert result["note"] == "no TheHive data"
    assert result["total_closed"] == 0
