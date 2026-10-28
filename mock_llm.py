"""Offline LLM stub used by MOCK_MODE.

Monkey-patches `strands.Agent.__call__` so no network calls are made.
Returns canned per-stage fixture responses from tests/fixtures/llm_responses/.
"""
from __future__ import annotations

from pathlib import Path

from logger import get_step_logger

step = get_step_logger("mock_llm")

_FIXTURE_DIR = Path(__file__).resolve().parent / "tests" / "fixtures" / "llm_responses"


def _load(name: str) -> str:
    path = _FIXTURE_DIR / f"{name}.json"
    if path.exists():
        try:
            return path.read_text()
        except Exception:
            pass
    # Fallback empty JSON array so the stage-1 parser is happy.
    return "[]"


def _pick_fixture(system_prompt: str) -> tuple[str, str]:
    p = (system_prompt or "").lower()
    if "threat detection specialist" in p:
        return "detection", _load("detection")
    if "correlation" in p or "threat intelligence specialist" in p:
        return "enrichment", _load("enrichment")
    if "triage specialist" in p:
        return "triage", _load("triage")
    if "automated incident response" in p:
        return "response", _load("response")
    if "forensic investigator" in p:
        return "forensics", _load("forensics")
    if "learning engine" in p:
        return "learning", _load("learning")
    return "unknown", "[]"


def install() -> None:
    """Monkey-patch strands.Agent so agent(...) returns a canned string."""
    try:
        import strands
    except Exception as e:
        step.error("strands not importable", exc=e)
        return

    def _mock_call(self, *args, **kwargs):  # type: ignore[no-redef]
        system = getattr(self, "system_prompt", "") or ""
        stage, response = _pick_fixture(system)
        step.info("returning fixture", stage=stage, bytes=len(response))
        return response

    strands.Agent.__call__ = _mock_call
    step.info("strands.Agent.__call__ patched")
