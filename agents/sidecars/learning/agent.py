"""
Learning sidecar.

Ported from the learning-engine portion of v1 mitigation_agent. Calls the
learning-engine tool directly; no LLM invocation.
"""

import config
from logger import get_logger
from .tools.learning_engine import update_learning_models, learn_from_closed_cases

logger = get_logger("learning")


class LearningAgent:
    async def run(self, ctx=None) -> dict:
        updates = update_learning_models(
            incident_data={
                "incident_id": config.forensic_report.get("report_id"),
                "attack_hypothesis": config.attack_hypothesis,
                "ti_confidence": config.ti_confidence,
                "behaviors": [e.get("type") for e in config.event_list],
            },
            attack_patterns=config.threat_patterns,
            iocs=config.forensic_report.get("indicators_of_compromise", {}),
            mitigation_effectiveness={
                a: {"success": True} for a in config.mitigation_actions_taken
            },
        )
        thehive_update = await learn_from_closed_cases(since_hours=24)
        updates.setdefault("updates_applied", []).append(thehive_update)
        config.learning_updates = updates
        logger.info(f"Learning complete: confidence={updates.get('learning_confidence')}")
        return updates

    async def run_nightly(self) -> dict:
        return await self.run()


def create_agent() -> LearningAgent:
    return LearningAgent()
