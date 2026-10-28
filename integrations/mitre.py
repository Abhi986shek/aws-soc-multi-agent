"""MITRE ATT&CK STIX bundle loader + keyword-based behavior mapping.

Downloads the enterprise-attack STIX bundle once and caches to disk.
On MOCK_MODE or fetch failure, callers should fall back to the yaml/inline dict.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import httpx

from config import settings
from logger import get_logger

logger = get_logger("mitre")


def load_mitre_bundle() -> dict | None:
    """Return parsed STIX bundle. Downloads once and caches to disk. None on error."""
    if settings.mock_mode:
        return None
    cache_path = Path(settings.mitre_stix_cache_path)
    if cache_path.exists():
        try:
            with cache_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Cached MITRE bundle unreadable ({e}); refetching")

    url = settings.mitre_stix_url
    if not url:
        return None
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info(f"MITRE STIX bundle cached to {cache_path}")
        return data
    except Exception as e:
        logger.warning(f"Failed to fetch MITRE STIX bundle: {e}")
        return None


@lru_cache(maxsize=1)
def techniques_by_external_id() -> dict[str, dict]:
    """Return {"T1078": {"name":..., "tactics":[...], "description":...}}."""
    bundle = load_mitre_bundle()
    out: dict[str, dict] = {}
    if not bundle:
        return out
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        external_id = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                break
        if not external_id:
            continue
        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", []) or []
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        out[external_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "description": obj.get("description", ""),
        }
    logger.info(f"Loaded {len(out)} MITRE techniques from STIX bundle")
    return out


def map_behaviors(behaviors: list[str]) -> list[dict]:
    """Keyword-match each behavior into technique names/descriptions."""
    techs = techniques_by_external_id()
    results: list[dict] = []
    if not techs:
        return results
    for behavior in behaviors:
        key = str(behavior).lower().replace("_", " ")
        tokens = [t for t in key.split() if len(t) > 3]
        if not tokens:
            continue
        best: tuple[int, str, dict] | None = None
        for tid, info in techs.items():
            haystack = (info["name"] + " " + info["description"]).lower()
            score = sum(1 for t in tokens if t in haystack)
            if score > 0 and (best is None or score > best[0]):
                best = (score, tid, info)
        if best:
            _, tid, info = best
            results.append({
                "behavior": behavior,
                "technique_id": tid,
                "technique_name": info["name"],
                "tactics": info["tactics"],
            })
    return results
