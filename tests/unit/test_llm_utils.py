"""Unit tests for agents._llm_utils.extract_json."""
from __future__ import annotations

from agents._llm_utils import extract_json


def test_extract_json_from_code_fence():
    text = 'Sure, here is the result:\n```json\n{"a": 1, "b": [1,2,3]}\n```\nthanks!'
    assert extract_json(text) == {"a": 1, "b": [1, 2, 3]}


def test_extract_json_plain_prose():
    text = 'The verdict is {"threat_score": 0.9, "priority_level": "Critical"} — act now.'
    parsed = extract_json(text)
    assert parsed == {"threat_score": 0.9, "priority_level": "Critical"}


def test_extract_json_returns_none_for_garbage():
    assert extract_json("no json here at all!!!") is None
    assert extract_json("") is None
    assert extract_json(None) is None


def test_extract_json_handles_nested_braces():
    text = 'result: {"outer": {"inner": {"x": 1}}, "arr": [1,{"n":2}]} done'
    parsed = extract_json(text)
    assert parsed == {"outer": {"inner": {"x": 1}}, "arr": [1, {"n": 2}]}
