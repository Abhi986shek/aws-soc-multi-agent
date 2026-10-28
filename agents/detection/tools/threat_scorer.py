"""
Threat Scoring Tool
Scores CloudTrail events against known threat patterns using LLM analysis.
"""

import json
from functools import lru_cache
from typing import Dict, Any

import yaml
from strands import tool

from config import settings
from logger import get_logger

logger = get_logger("threat_scorer")


@lru_cache(maxsize=1)
def _load_threats_yaml() -> dict:
    """Load config/rules/threats.yaml once."""
    path = settings.rules_dir / "threats.yaml"
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        logger.info(f"Loaded threat patterns from {path}")
        return data
    except Exception as e:
        logger.error(f"Error loading threats.yaml: {e}")
        return {}


@lru_cache(maxsize=1)
def _format_threats_text() -> str:
    """Format the yaml threat list as a bullet list the LLM can reason over."""
    data = _load_threats_yaml()
    threats = data.get("threats", []) if isinstance(data, dict) else []
    if not threats:
        return ""

    lines: list[str] = ["Known AWS threat patterns:"]
    for t in threats:
        name = t.get("name", "unnamed")
        desc = t.get("description", "")
        events = ", ".join(t.get("cloudtrail_events", []) or [])
        sev = t.get("severity_hint", "")
        lines.append(f"- {name} (severity_hint={sev}): {desc}")
        if events:
            lines.append(f"    example CloudTrail events: {events}")
    return "\n".join(lines)


@tool
def get_threat_patterns() -> str:
    """
    Get the complete AWS threat patterns list.
    Returns:
        A human-readable bullet list of threat patterns loaded from
        config/rules/threats.yaml.
    """
    return _format_threats_text()


@tool
def analyze_event_with_llm(event_summary: str, threat_patterns: str) -> Dict[str, Any]:
    """
    Analyze a CloudTrail event against threat patterns using LLM reasoning.

    Args:
        event_summary: JSON string of the CloudTrail event
        threat_patterns: The threat patterns to compare against

    Returns:
        Dictionary with threat analysis results (LLM populates fields)
    """
    try:
        event = json.loads(event_summary)
    except Exception:
        event = {"event_name": "Unknown", "event_id": "unknown"}

    return {
        "event_id": event.get("event_id", "unknown"),
        "event_name": event.get("event_name", "Unknown"),
        "threat_score": 0.0,
        "matched_threats": [],
        "threat_categories": [],
        "reasoning": "",
        "is_suspicious": False,
    }
