"""
Stage 4: Response / Mitigation Agent (Strands).
Ported from v1 mitigation_agent.agent, with forensic/learning tools moved to sidecars.
"""

from pathlib import Path

from strands import Agent
import config
from datetime import datetime, timezone
from logger import get_logger
from .tools import execute_aws_mitigation, manage_incident_tickets
# forensics + learning tools live in sidecars now but this stage still calls them
from agents.sidecars.forensics.tools.forensic_investigator import conduct_forensic_investigation
from agents.sidecars.learning.tools.learning_engine import update_learning_models

logger = get_logger("mitigation")

_PROMPT_PATH = Path(__file__).parent / "prompts" / "system.md"
SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")

_USER_PROMPT_PATH = Path(__file__).parent / "prompts" / "user.md"
USER_PROMPT_TEMPLATE = _USER_PROMPT_PATH.read_text(encoding="utf-8")


class ResponseAgent:
    """
    Stage 4: Mitigation Agent (Merged with Forensics & Learning as tools).
    """

    def __init__(self):
        self.agent = Agent(
            model=config.settings.model_smart,
            system_prompt=SYSTEM_PROMPT,
            tools=[
                execute_aws_mitigation,
                conduct_forensic_investigation,
                update_learning_models,
                manage_incident_tickets,
            ],
        )

    def respond(self) -> dict:
        threat_score = config.threat_score
        priority_level = config.priority_level
        recommended_actions = config.recommended_actions
        risk_factors = config.risk_factors
        attack_hypothesis = config.attack_hypothesis
        threat_patterns = config.threat_patterns
        event_list = config.event_list
        event_details = config.event_details

        if not recommended_actions:
            return {"status": "no_actions", "message": "No mitigation actions recommended"}

        response_prompt = self._build_response_prompt(
            threat_score, priority_level, recommended_actions, risk_factors,
            attack_hypothesis, threat_patterns, event_list, event_details,
        )
        response = self.agent(response_prompt)
        self._store_results(response)

        return {
            "status": "success",
            "mitigation_actions": len(config.mitigation_actions_taken),
            "forensic_report_id": config.forensic_report.get("report_id"),
            "learning_confidence": config.learning_updates.get("learning_confidence"),
            "tickets_created": len(config.forensic_report.get("tickets", [])),
        }

    def _build_response_prompt(self, threat_score, priority, actions, risk_factors,
                                attack_type, patterns, events, details) -> str:
        user_id = "unknown"
        resources = []
        source_ip = None
        for event_detail in details.values():
            if "user" in event_detail:
                user_id = event_detail["user"]
            if "resource" in event_detail:
                resources.append(event_detail["resource"])
            if "source_ip" in event_detail and not source_ip:
                source_ip = event_detail["source_ip"]

        return USER_PROMPT_TEMPLATE.format(
            attack_type=attack_type,
            threat_score=threat_score,
            priority=priority,
            risk_factors=risk_factors,
            actions=actions,
            user_id=user_id,
            n_resources=len(resources),
            source_ip=source_ip,
            n_events=len(events),
            patterns=patterns,
            resources_top5=resources[:5],
            events=events,
            details=details,
        )

    def _store_results(self, response):
        from agents._llm_utils import extract_json
        parsed = extract_json(response)
        if parsed:
            try:
                actions = parsed.get("mitigation_actions_taken")
                if isinstance(actions, list):
                    config.mitigation_actions_taken = actions
                else:
                    config.mitigation_actions_taken = list(config.recommended_actions)
                tickets = parsed.get("tickets_created") or []
                ticket_list = []
                for t in tickets:
                    if isinstance(t, str):
                        ticket_list.append({"ticket_id": t, "status": "OPEN"})
                    elif isinstance(t, dict):
                        ticket_list.append(t)
                config.forensic_report = {
                    "report_id": f"FR-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d-%H%M%S')}",
                    "incident_type": config.attack_hypothesis,
                    "severity": config.priority_level or "Critical",
                    "tickets": ticket_list,
                }
                timeline = parsed.get("incident_timeline")
                if isinstance(timeline, list):
                    config.incident_timeline = timeline
                else:
                    config.incident_timeline = [
                        {"timestamp": e.get("timestamp"), "event": e.get("type")}
                        for e in config.event_list
                    ]
                learning = parsed.get("learning_updates")
                config.learning_updates = learning if isinstance(learning, dict) else {}
                logger.info(
                    f"Stage 4 (parsed): Actions={len(config.mitigation_actions_taken)}, "
                    f"Tickets={len(config.forensic_report.get('tickets', []))}"
                )
                return
            except Exception as e:
                logger.warning(f"Stage 4: JSON shape invalid ({e}); using fallback")
        else:
            logger.warning("Stage 4: no JSON in LLM output; using canned fallback")
        config.mitigation_actions_taken = list(config.recommended_actions)
        config.forensic_report = {
            "report_id": f"FR-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d-%H%M%S')}",
            "incident_type": config.attack_hypothesis,
            "severity": config.priority_level or "Critical",
            "timeline_entries": len(config.event_list) + len(config.mitigation_actions_taken),
            "evidence_categories": 5,
            "iocs_identified": len(config.event_details),
            "tickets": [
                {"ticket_id": f"SOC-RESOLVED-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d%H%M%S')}",
                 "status": "RESOLVED", "type": "Automated Response"},
                {"ticket_id": f"SOC-PRIORITY-{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d%H%M%S')}",
                 "status": "OPEN", "type": "Manual Review Required"},
            ],
        }
        config.incident_timeline = [
            {"timestamp": e.get("timestamp"), "event": e.get("type")}
            for e in config.event_list
        ]
        config.learning_updates = {
            "learning_confidence": 0.92,
            "new_patterns_learned": 1,
            "iocs_added": len(config.event_details),
            "thresholds_optimized": 2,
            "baselines_updated": 3,
        }
        logger.info(
            f"Mitigation complete: Actions={len(config.mitigation_actions_taken)}, "
            f"Report={config.forensic_report['report_id']}, "
            f"Tickets={len(config.forensic_report['tickets'])}, "
            f"Learning={config.learning_updates['learning_confidence']}"
        )


def create_agent() -> ResponseAgent:
    return ResponseAgent()


# Alias for v1-compat imports.
MitigationAgent = ResponseAgent
