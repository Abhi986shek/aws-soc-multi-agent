"""Integration tests for AbuseIPDB / GreyNoise threat-feed integration."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from integrations import threat_feeds


@pytest.mark.asyncio
async def test_abuseipdb_skipped_when_no_key(mock_settings):
    mock_settings.abuseipdb_api_key = ""
    r = await threat_feeds.check_ip_abuseipdb("1.2.3.4")
    assert r["skipped"] is True


@pytest.mark.asyncio
async def test_greynoise_skipped_when_no_key(mock_settings):
    mock_settings.greynoise_api_key = ""
    r = await threat_feeds.check_ip_greynoise("1.2.3.4")
    assert r["skipped"] is True


@pytest.mark.asyncio
async def test_lookup_ip_merges_results(mock_settings, monkeypatch):
    mock_settings.abuseipdb_api_key = "ak"
    mock_settings.greynoise_api_key = "gk"
    mock_settings.mock_mode = False
    threat_feeds._cache.clear()

    abuse_json = {"data": {"abuseConfidenceScore": 80, "isPublic": True,
                            "countryCode": "US", "usageType": "hosting", "totalReports": 20}}
    gn_json = {"classification": "malicious", "name": "known-bad", "noise": True,
               "riot": False, "last_seen": "2025-07-22"}

    class FakeResp:
        def __init__(self, payload):
            self._p = payload
            self.status_code = 200
        def raise_for_status(self): return None
        def json(self): return self._p

    class FakeClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, **kw):
            if "abuseipdb" in url:
                return FakeResp(abuse_json)
            return FakeResp(gn_json)

    monkeypatch.setattr(threat_feeds.httpx, "AsyncClient", FakeClient)
    result = await threat_feeds.lookup_ip("1.2.3.4")
    assert result["ip"] == "1.2.3.4"
    assert result["abuseipdb"]["abuse_confidence"] == 80
    assert result["greynoise"]["classification"] == "malicious"
    assert result["risk_score"] > 0
