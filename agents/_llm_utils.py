"""Shared helpers for parsing structured JSON out of LLM responses."""
from __future__ import annotations

import json
import re
from typing import Any

from logger import get_logger

logger = get_logger("llm_utils")

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _response_text(response: Any) -> str:
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    for attr in ("content", "text", "output_text", "message"):
        val = getattr(response, attr, None)
        if isinstance(val, str) and val:
            return val
    try:
        return str(response)
    except Exception:
        return ""


def _try_load(candidate: str) -> dict | None:
    try:
        val = json.loads(candidate)
        return val if isinstance(val, dict) else None
    except Exception:
        return None


def extract_json(response: Any) -> dict | None:
    """Extract the FIRST valid JSON object from an LLM response.

    Handles ```json fences, plain JSON, and text-with-embedded-JSON. Returns
    None if no valid JSON object is found.
    """
    text = _response_text(response)
    if not text:
        return None

    # 1) fenced blocks
    for m in _FENCE_RE.finditer(text):
        parsed = _try_load(m.group(1))
        if parsed is not None:
            return parsed

    # 2) balanced brace scan
    for start in range(len(text)):
        if text[start] != "{":
            continue
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    parsed = _try_load(candidate)
                    if parsed is not None:
                        return parsed
                    break

    logger.debug("extract_json: no JSON object found in response")
    return None
