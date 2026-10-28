"""
Forensics sidecar.

Ported from the forensic-investigator portion of v1 mitigation_agent.
Runs async off the hot path after stage 4. Calls the forensic-investigation
tool directly; no LLM invocation.
"""

import config
from logger import get_logger
from .tools.forensic_investigator import conduct_forensic_investigation

logger = get_logger("forensics")


class ForensicsAgent:
    async def run(self, ctx=None) -> dict:
        report = conduct_forensic_investigation(
            event_list=list(config.event_list),
            event_details=dict(config.event_details),
            mitigation_actions=list(config.mitigation_actions_taken),
            attack_hypothesis=config.attack_hypothesis,
        )
        config.forensic_report = report
        logger.info(f"Forensics complete: {report.get('report_id')}")
        return report


def create_agent() -> ForensicsAgent:
    return ForensicsAgent()
