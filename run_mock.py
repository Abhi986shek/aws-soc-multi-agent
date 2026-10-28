"""End-to-end offline entry point.

Enables MOCK_MODE, patches strands.Agent, and runs the orchestrator once
against the canned CloudTrail batch under tests/fixtures/cloudtrail_events/.
"""
import asyncio
import json
import os
import sys

os.environ["MOCK_MODE"] = "true"
# Also set safe defaults for LLM model ids so Strands never tries to construct
# a real client. In mock_mode strands.Agent.__call__ is patched anyway.
os.environ.setdefault("MODEL_FAST", "mock-fast")
os.environ.setdefault("MODEL_SMART", "mock-smart")

from mock_llm import install as install_mock_llm  # noqa: E402
install_mock_llm()

from logger import get_step_logger  # noqa: E402
from agents.orchestrator import run_soc_workflow_once  # noqa: E402
from agents.detection.tools.fetch_cloudtrail import fetch_cloudtrail_events  # noqa: E402

step = get_step_logger("run_mock")


async def main() -> None:
    batch = fetch_cloudtrail_events(lookback_seconds=30)
    step.info("loaded canned CloudTrail events", count=len(batch))
    result = await run_soc_workflow_once(initial_batch=batch)
    # Final JSON summary emitted to stdout for downstream tooling / humans.
    sys.stdout.write(json.dumps(result, indent=2, default=str) + "\n")


if __name__ == "__main__":
    asyncio.run(main())
