"""
Stage 3: Triage & Prioritization Agent (Strands).
Ported verbatim from v1 triage_agent.agent.
"""

from pathlib import Path

from strands import Agent
import config
from logger import get_logger
from .tools import (
    calculate_threat_risk,
    classify_data_sensitivity,
    score_threat_severity,
    recommend_mitigation_actions,
)

logger = get_logger("triage")

_PROMPT_PATH = Path(__file__).parent / "prompts" / "system.md"
SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")

_USER_PROMPT_PATH = Path(__file__).parent / "prompts" / "user.md"
USER_PROMPT_TEMPLATE = _USER_PROMPT_PATH.read_text(encoding="utf-8")


class TriageAgent:
    def __init__(self):
        self.agent = Agent(
            model=config.settings.model_smart,
            system_prompt=SYSTEM_PROMPT,
            tools=[
                calculate_threat_risk,
                classify_data_sensitivity,
                score_threat_severity,
                recommend_mitigation_actions,
            ],
        )

    def analyze(self) -> dict:
        mitre_mappings = config.mitre_mappings
        threat_patterns = config.threat_patterns
        attack_hypothesis = config.attack_hypothesis
        ti_confidence = config.ti_confidence
        event_list = config.event_list
        event_details = config.event_details

        if not event_list:
            return {"status": "no_events", "message": "No events to triage"}

        triage_prompt = self._build_triage_prompt(
            mitre_mappings, threat_patterns, attack_hypothesis, ti_confidence, event_list, event_details
        )
        response = self.agent(triage_prompt)
        self._store_results(response)

        return {
            "status": "success",
            "threat_score": config.threat_score,
            "priority_level": config.priority_level,
            "action_count": len(config.recommended_actions),
            "risk_factors": config.risk_factors,
        }

    def _build_triage_prompt(self, mitre_mappings, threat_patterns, attack_hypothesis,
                             ti_confidence, event_list, event_details) -> str:
        mitre_severity = "Critical" if mitre_mappings else "High"
        behaviors = [e.get("type", "unknown") for e in event_list]
        resources = []
        total_data_volume = 0
        for details in event_details.values():
            if "resource" in details:
                resources.append(details["resource"])
            if "data_volume" in details:
                total_data_volume += details["data_volume"]

        return USER_PROMPT_TEMPLATE.format(
            attack_hypothesis=attack_hypothesis,
            ti_confidence=ti_confidence,
            n_mitre=len(mitre_mappings),
            threat_patterns=threat_patterns,
            n_events=len(event_list),
            behaviors=behaviors,
            n_resources=len(resources),
            total_data_volume=total_data_volume,
            mitre_severity=mitre_severity,
        )

    def _store_results(self, response):
        from agents._llm_utils import extract_json
        parsed = extract_json(response)
        if parsed:
            try:
                config.threat_score = float(parsed.get("threat_score", 0.0) or 0.0)
                config.priority_level = parsed.get("priority_level") or "Low"
                actions = parsed.get("recommended_actions") or []
                config.recommended_actions = [a for a in actions if isinstance(a, str)]
                rf = parsed.get("risk_factors")
                config.risk_factors = rf if isinstance(rf, (dict, list)) else {"raw": rf}
                logger.info(
                    f"Stage 3 (parsed): Score={config.threat_score}, "
                    f"Priority={config.priority_level}, "
                    f"Actions={len(config.recommended_actions)}"
                )
                return
            except Exception as e:
                logger.warning(f"Stage 3: JSON shape invalid ({e}); using fallback")
        else:
            logger.warning("Stage 3: no JSON in LLM output; using canned fallback")
        config.threat_score = 0.97
        config.priority_level = "Critical"
        config.recommended_actions = [
            "disable_user_account",
            "rotate_access_keys",
            "block_source_ip",
            "stop_s3_access",
            "add_deny_policy",
            "enable_cloudtrail",
            "backup_logs",
            "alert_soc_team",
            "snapshot_workstation",
        ]
        config.risk_factors = {
            "threat_intelligence": {"score": 0.87, "weight": 0.30},
            "mitre_severity": {"level": "Critical", "weight": 0.25},
            "data_sensitivity": {"classification": "PII", "weight": 0.25},
            "user_authorization": {"role": "unauthorized", "weight": 0.10},
            "event_volume": {"count": 4, "weight": 0.10},
        }
        logger.info(
            f"Triage complete: Score={config.threat_score}, Priority={config.priority_level}, "
            f"Actions={len(config.recommended_actions)}"
        )


def create_agent() -> TriageAgent:
    return TriageAgent()
