"""
SOC Multi-Agent Workflow Orchestrator (v2 layout).

Runs the pipeline stages in order. Every stage boundary is logged via a
`StepLogger` so a full workflow trace is greppable end-to-end:

    >>> [stage0] START filter | trace=... batch_size=5
    <<< [stage0] DONE filtered | trace=... kept=3 dropped=2

Stage numbering:
  Stage 0: deterministic pre-filter
  Stage 1: Threat Detection
  Stage 2: Enrichment  (correlation + intelligence)
  Stage 3: Triage
  Stage 4: Response    (mitigation + tickets)
  Sidecars: Forensics + Learning
"""

import asyncio
import uuid
from datetime import datetime, timezone

import config
from logger import get_logger, get_step_logger, log_context

from agents.filter.filter import Stage0Filter
from agents.detection import create_agent as create_detection_agent
from agents.detection.queue_monitor import EventQueue
from agents.detection.tools.fetch_cloudtrail import fetch_cloudtrail_events
from agents.enrichment import create_agent as create_enrichment_agent
from agents.triage import create_agent as create_triage_agent
from agents.response import create_agent as create_response_agent
from agents.response.approval_gate import ApprovalGate, DESTRUCTIVE
from agents.sidecars.forensics import create_agent as create_forensics_agent
from agents.sidecars.learning import create_agent as create_learning_agent
from integrations.redis_store import record_event

logger = get_logger("workflow")


class SOCWorkflowOrchestrator:
    """Orchestrates the complete SOC multi-agent workflow."""

    def __init__(self):
        self.agents = {}
        self.stage0 = Stage0Filter()
        self.approval = ApprovalGate()
        self._initialize_agents()

    def _initialize_agents(self):
        step = get_step_logger("orchestrator")
        step.start("loading agents")
        self.agents["detection"] = create_detection_agent()
        self.agents["enrichment"] = create_enrichment_agent()
        self.agents["triage"] = create_triage_agent()
        self.agents["response"] = create_response_agent()
        self.agents["forensics"] = create_forensics_agent()
        self.agents["learning"] = create_learning_agent()
        step.done("agents ready", count=len(self.agents))

    async def _apply_stage0(self, batch: list) -> list:
        step = get_step_logger("stage0")
        step.start("filter", batch_size=len(batch))
        try:
            kept, info = await self.stage0.run(list(batch))
            for event in kept:
                try:
                    await record_event(event)
                except Exception as e:
                    step.warn("record_event failed (non-fatal)", error=str(e))
            step.done("filtered", **{
                "in": info.get("in"),
                "kept": info.get("kept"),
                "dropped": info.get("dropped"),
            })
            return kept
        except Exception as e:
            step.error("filter failed, passing batch through", exc=e)
            return list(batch)

    async def _approval_gate(self) -> bool:
        """Approval gate between stage 3 and stage 4 for destructive actions."""
        step = get_step_logger("approval")
        actions = list(config.recommended_actions or [])
        has_destructive = any(a in DESTRUCTIVE for a in actions)
        if not has_destructive:
            step.info("no destructive actions", actions=actions)
            return True

        confidence = float(config.ti_confidence or 0.0)
        threshold = config.settings.triage_confidence_threshold
        step.start("gate", confidence=confidence, threshold=threshold, actions=actions)

        if confidence >= threshold:
            step.done("granted (high confidence)")
            return True

        if config.settings.dry_run or config.settings.mock_mode:
            step.done("granted (dry_run/mock_mode)")
            return True

        try:
            triage = {
                "threat_score": config.threat_score,
                "priority_level": config.priority_level,
                "confidence": confidence,
                "actions": actions,
            }
            for action in actions:
                if action in DESTRUCTIVE:
                    approved = await self.approval.request(None, triage, action)
                    if not approved:
                        step.warn("denied", action=action)
                        return False
            step.done("granted")
            return True
        except Exception as e:
            step.error("gate error, failing closed", exc=e)
            return False


def create_workflow() -> "SOCWorkflowOrchestrator":
    return SOCWorkflowOrchestrator()


# ============================================================================
# INTEGRATED WORKFLOW WITH QUEUE MONITORING
# ============================================================================

async def run_soc_workflow_integrated() -> dict:
    """Continuous monitoring workflow."""
    orch = create_workflow()
    queue = EventQueue()
    monitor = get_step_logger("monitor")
    monitor.start("queue monitoring", target=5, poll_seconds=30)

    workflow_count = 0

    try:
        while True:
            trace_id = uuid.uuid4().hex[:12]
            with log_context(trace_id=trace_id):
                workflow_start = datetime.now(timezone.utc)
                results = {
                    "workflow_id": f"WF-{workflow_start.strftime('%Y%m%d-%H%M%S')}",
                    "trace_id": trace_id,
                    "start_time": workflow_start.isoformat(),
                    "agents_executed": [],
                    "status": "in_progress",
                }
                wf_step = get_step_logger("workflow")

                try:
                    while not queue.is_full():
                        events = fetch_cloudtrail_events(lookback_seconds=30)
                        for event in events:
                            queue.add_event(event)
                        monitor.info("queue status", size=queue.size(), target=5)
                        if not queue.is_full():
                            await asyncio.sleep(30)

                    workflow_count += 1
                    wf_step.start("triggered", workflow_num=workflow_count)

                    batch = queue.get_batch()
                    batch = await orch._apply_stage0(batch)
                    if not batch:
                        wf_step.done("all events filtered", status="filtered_out")
                        results["status"] = "filtered_out"
                        continue

                    s1 = get_step_logger("stage1")
                    s1.start("detection", events=len(batch))
                    detection_result = await orch.agents["detection"].analyze(batch)
                    s1.done("detection", flagged=detection_result.get("flagged_count", 0),
                            status=detection_result.get("status"))
                    results["agents_executed"].append({
                        "agent": "Threat Detection", "status": "success",
                        "result": detection_result,
                    })

                    if detection_result.get("flagged_count", 0) == 0:
                        wf_step.done("no threats", status="no_threats")
                        results["status"] = "no_threats"
                        continue

                    s2 = get_step_logger("stage2")
                    s2.start("enrichment")
                    enrichment_result = orch.agents["enrichment"].analyze()
                    s2.done("enrichment",
                            mitre=len(config.mitre_mappings or []),
                            hypothesis=(config.attack_hypothesis or "")[:60])
                    results["agents_executed"].append({
                        "agent": "Enrichment", "status": "success",
                        "result": enrichment_result,
                    })

                    s3 = get_step_logger("stage3")
                    s3.start("triage")
                    triage_result = orch.agents["triage"].analyze()
                    s3.done("triage", priority=config.priority_level,
                            score=config.threat_score,
                            confidence=config.ti_confidence)
                    results["agents_executed"].append({
                        "agent": "Triage", "status": "success",
                        "result": triage_result,
                    })

                    approved = await orch._approval_gate()
                    if not approved:
                        wf_step.warn("awaiting approval", status="awaiting_approval")
                        results["status"] = "awaiting_approval"
                        continue

                    s4 = get_step_logger("stage4")
                    s4.start("response")
                    response_result = orch.agents["response"].respond()
                    s4.done("response",
                            actions=len(config.recommended_actions or []))
                    results["agents_executed"].append({
                        "agent": "Response", "status": "success",
                        "result": response_result,
                    })

                    sc = get_step_logger("sidecars")
                    sc.start("fire-and-forget")
                    asyncio.create_task(orch.agents["forensics"].run())
                    asyncio.create_task(orch.agents["learning"].run())
                    sc.done("dispatched")

                    workflow_end = datetime.now(timezone.utc)
                    execution_time = (workflow_end - workflow_start).total_seconds()
                    results["status"] = "success"
                    results["end_time"] = workflow_end.isoformat()
                    results["total_execution_time_seconds"] = round(execution_time, 2)
                    wf_step.done("complete",
                                 workflow_num=workflow_count,
                                 seconds=round(execution_time, 2),
                                 priority=config.priority_level,
                                 score=config.threat_score)

                except Exception as e:
                    results["status"] = "failed"
                    results["error"] = str(e)
                    wf_step.error("workflow failed", exc=e, workflow_num=workflow_count)
                    await asyncio.sleep(5)

    except KeyboardInterrupt:
        monitor.done("stopped by user", workflows_processed=workflow_count)
        return {
            "status": "stopped",
            "workflows_processed": workflow_count,
            "message": "Monitoring stopped by user",
        }
    except Exception as e:
        monitor.error("fatal error in monitoring loop", exc=e)
        return {"status": "failed", "error": str(e), "workflows_processed": workflow_count}


async def run_soc_workflow_once(initial_batch: list | None = None) -> dict:
    """One-shot workflow: all stages against a provided (or fetched) batch."""
    trace_id = uuid.uuid4().hex[:12]
    with log_context(trace_id=trace_id):
        orch = create_workflow()

        if initial_batch is None:
            initial_batch = fetch_cloudtrail_events(lookback_seconds=30)

        started = datetime.now(timezone.utc)
        results = {"trace_id": trace_id, "start_time": started.isoformat(), "agents_executed": []}
        wf_step = get_step_logger("workflow")
        wf_step.start("one-shot", batch_size=len(initial_batch))

        batch = await orch._apply_stage0(initial_batch)
        if not batch:
            wf_step.done("filtered out", status="filtered_out")
            results["status"] = "filtered_out"
            return results

        s1 = get_step_logger("stage1")
        s1.start("detection", events=len(batch))
        detection_result = await orch.agents["detection"].analyze(batch)
        s1.done("detection", flagged=detection_result.get("flagged_count", 0),
                status=detection_result.get("status"))
        results["agents_executed"].append({"agent": "Threat Detection", "result": detection_result})

        if detection_result.get("flagged_count", 0) == 0:
            wf_step.done("no threats", status="no_threats")
            results["status"] = "no_threats"
            return results

        s2 = get_step_logger("stage2")
        s2.start("enrichment")
        enrichment_result = orch.agents["enrichment"].analyze()
        s2.done("enrichment",
                mitre=len(config.mitre_mappings or []),
                hypothesis=(config.attack_hypothesis or "")[:60])
        results["agents_executed"].append({"agent": "Enrichment", "result": enrichment_result})

        s3 = get_step_logger("stage3")
        s3.start("triage")
        triage_result = orch.agents["triage"].analyze()
        s3.done("triage", priority=config.priority_level,
                score=config.threat_score, confidence=config.ti_confidence)
        results["agents_executed"].append({"agent": "Triage", "result": triage_result})

        approved = await orch._approval_gate()
        if not approved:
            wf_step.warn("awaiting approval", status="awaiting_approval")
            results["status"] = "awaiting_approval"
            return results

        s4 = get_step_logger("stage4")
        s4.start("response")
        response_result = orch.agents["response"].respond()
        s4.done("response", actions=len(config.recommended_actions or []))
        results["agents_executed"].append({"agent": "Response", "result": response_result})

        forensics = get_step_logger("forensics")
        forensics.start("timeline reconstruction")
        forensics_result = await orch.agents["forensics"].run()
        forensics.done("forensics", status=(forensics_result or {}).get("status"))
        learning = get_step_logger("learning")
        learning.start("nightly tuning")
        learning_result = await orch.agents["learning"].run()
        learning.done("learning", status=(learning_result or {}).get("status"))
        results["agents_executed"].append({"agent": "Forensics", "result": forensics_result})
        results["agents_executed"].append({"agent": "Learning", "result": learning_result})

        results["status"] = "success"
        results["end_time"] = datetime.now(timezone.utc).isoformat()
        wf_step.done("one-shot complete", status="success")
        return results


# --- v1-compat class alias ---
Orchestrator = SOCWorkflowOrchestrator
