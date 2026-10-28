"""Integration tests for the MITRE ATT&CK loader / mapper."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from integrations import mitre


def test_load_mitre_bundle_uses_cache(mock_settings, tmp_path):
    cache = tmp_path / "mitre.json"
    bundle = {"objects": [
        {"type": "attack-pattern",
         "name": "Data Exfiltration to Cloud",
         "description": "Transfer data to cloud storage",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1537"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "exfiltration"}]}
    ]}
    cache.write_text(json.dumps(bundle))
    mock_settings.mock_mode = False
    mock_settings.mitre_stix_cache_path = cache
    mitre.techniques_by_external_id.cache_clear()
    with patch("integrations.mitre.httpx.Client") as http:
        loaded = mitre.load_mitre_bundle()
        http.assert_not_called()
    assert loaded == bundle


def test_map_behaviors_returns_matches(mock_settings, tmp_path):
    cache = tmp_path / "mitre.json"
    bundle = {"objects": [
        {"type": "attack-pattern",
         "name": "Transfer Data to Cloud Account",
         "description": "Adversaries may exfiltrate data to cloud storage they control.",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1537"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "exfiltration"}]}
    ]}
    cache.write_text(json.dumps(bundle))
    mock_settings.mock_mode = False
    mock_settings.mitre_stix_cache_path = cache
    mitre.techniques_by_external_id.cache_clear()
    results = mitre.map_behaviors(["data exfiltration"])
    assert len(results) >= 1
    assert results[0]["technique_id"] == "T1537"


def test_load_mitre_bundle_handles_fetch_failure(mock_settings, tmp_path):
    cache = tmp_path / "does-not-exist.json"
    mock_settings.mock_mode = False
    mock_settings.mitre_stix_cache_path = cache
    mitre.techniques_by_external_id.cache_clear()

    class BoomClient:
        def __init__(self, *a, **kw): ...
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, *a, **kw):
            raise RuntimeError("network down")

    with patch("integrations.mitre.httpx.Client", BoomClient):
        assert mitre.load_mitre_bundle() is None
        assert mitre.map_behaviors(["anything"]) == []
