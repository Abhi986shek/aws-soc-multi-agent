"""
SOC Multi-Agent System - Main Entry Point (v2 layout).

If MOCK_MODE=true, we patch strands.Agent for offline runs and execute a
single workflow pass over canned fixtures. Otherwise we run the continuous
integrated workflow with 30s CloudTrail polling.
"""
import asyncio
import os
import uuid

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from config import settings  # noqa: E402
from logger import get_step_logger, log_context  # noqa: E402

step = get_step_logger("main")


async def main():
    trace_id = uuid.uuid4().hex[:12]
    with log_context(trace_id=trace_id):
        if settings.mock_mode:
            step.start("mock run", mock_mode=True)
            from mock_llm import install as install_mock_llm
            install_mock_llm()
            from agents.orchestrator import run_soc_workflow_once
            from agents.detection.tools.fetch_cloudtrail import fetch_cloudtrail_events
            batch = fetch_cloudtrail_events(lookback_seconds=30)
            result = await run_soc_workflow_once(initial_batch=batch)
            step.done("mock run complete", status=result.get("status"))
            return result

        from agents.orchestrator import run_soc_workflow_integrated

        step.start("continuous monitoring", queue_target=5)
        results = await run_soc_workflow_integrated()
        step.done("service stopped", status=results.get("status"))
        return results


if __name__ == "__main__":
    asyncio.run(main())
