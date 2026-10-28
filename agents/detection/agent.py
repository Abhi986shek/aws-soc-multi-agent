"""
Stage 1: Threat Detection Agent (Strands).

Ported verbatim from v1 threat_detection_agent.agent.
Analyzes CloudTrail events and flags suspicious activities using LLM intelligence.
"""

from pathlib import Path

from strands import Agent
import config
import json
from logger import get_step_logger
from .tools import get_threat_patterns, analyze_event_with_llm

logger = get_step_logger("stage1")

_PROMPT_PATH = Path(__file__).parent / "prompts" / "system.md"
SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")

_USER_PROMPT_PATH = Path(__file__).parent / "prompts" / "user.md"
USER_PROMPT_TEMPLATE = _USER_PROMPT_PATH.read_text(encoding="utf-8")


class ThreatDetectionAgent:
    """
    Agent 1: Threat Detection Agent (batch of 5 events per invocation).
    """

    def __init__(self):
        self.agent = Agent(
            model=config.settings.model_fast,
            system_prompt=SYSTEM_PROMPT,
            tools=[get_threat_patterns, analyze_event_with_llm],
        )
        self.threshold = 0.6

    async def analyze(self, events: list) -> dict:
        """Analyze a batch of CloudTrail events using LLM intelligence."""
        if not events:
            logger.warn("No events to analyze")
            return {"status": "no_events", "flagged_count": 0}

        logger.info(f"Analyzing {len(events)} events...")

        analysis_prompt = self._build_analysis_prompt(events)

        try:
            response = self.agent(analysis_prompt)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {"status": "error", "error": str(e), "flagged_count": 0}

        scored_events = self._parse_llm_response(response, events)

        flagged_events = []
        for se in scored_events:
            score = se["score_result"]["threat_score"]
            if score >= self.threshold:
                se["score_result"]["is_suspicious"] = True
                flagged_events.append(se)
            else:
                se["score_result"]["is_suspicious"] = False

        if not flagged_events:
            logger.info("No threats detected")
            return {"status": "no_threats", "flagged_count": 0, "total_analyzed": len(events)}

        avg_score = round(
            sum(se["score_result"]["threat_score"] for se in flagged_events) / len(flagged_events), 2
        )

        self._write_to_config(flagged_events, avg_score)

        logger.info(f"Flagged {len(flagged_events)}/{len(events)} events (avg: {avg_score})")
        logger.info(f"event_list: {json.dumps(config.event_list, indent=2)}")

        return {
            "status": "success",
            "total_analyzed": len(events),
            "flagged_count": len(flagged_events),
            "average_score": avg_score,
            "flagged_event_ids": [se["score_result"]["event_id"] for se in flagged_events],
        }

    def _build_analysis_prompt(self, events: list) -> str:
        events_block = ""
        for i, event in enumerate(events, 1):
            event_summary = {
                "event_id": event.get("event_id"),
                "event_name": event.get("event_name"),
                "event_time": event.get("event_time"),
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "aws_region": event.get("aws_region"),
                "event_source": event.get("event_source"),
                "user_identity_type": (event.get("user_identity") or {}).get("type"),
                "resources": event.get("resources", []),
                "request_parameters": event.get("request_parameters"),
            }
            events_block += f"\nEvent {i}:\n{json.dumps(event_summary, indent=2)}\n"

        return USER_PROMPT_TEMPLATE.format(
            n_events=len(events),
            events_block=events_block,
        )

    def _parse_llm_response(self, response, events: list) -> list:
        import re
        scored_events = []
        try:
            json_match = re.search(r"\[[\s\S]*\]", str(response))
            if json_match:
                scores = json.loads(json_match.group(0))
                for event in events:
                    event_id = event.get("event_id")
                    score_result = next((s for s in scores if s.get("event_id") == event_id), None)
                    if score_result:
                        scored_events.append({"event": event, "score_result": score_result})
                    else:
                        logger.warn(f"No score found for event {event_id}")
            else:
                logger.error("Could not find JSON array in LLM response")
                for event in events:
                    scored_events.append({
                        "event": event,
                        "score_result": {
                            "event_id": event.get("event_id"),
                            "event_name": event.get("event_name"),
                            "threat_score": 0.0,
                            "matched_threats": [],
                            "threat_categories": [],
                            "reasoning": "Failed to parse LLM response",
                            "is_suspicious": False,
                        },
                    })
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            for event in events:
                scored_events.append({
                    "event": event,
                    "score_result": {
                        "event_id": event.get("event_id"),
                        "event_name": event.get("event_name"),
                        "threat_score": 0.0,
                        "matched_threats": [],
                        "threat_categories": [],
                        "reasoning": f"Error: {e}",
                        "is_suspicious": False,
                    },
                })
        return scored_events

    def _write_to_config(self, flagged_events: list, avg_score: float):
        config.event_list = []
        config.event_details = {}
        for se in flagged_events:
            event = se["event"]
            sr = se["score_result"]
            config.event_list.append({
                "event_id": event.get("event_id"),
                "timestamp": event.get("event_time"),
                "score": sr["threat_score"],
                "type": sr["threat_categories"][0] if sr["threat_categories"] else "unknown",
            })
            config.event_details[event.get("event_id")] = {
                "user": event.get("username"),
                "action": event.get("event_name"),
                "resource": event.get("resources"),
                "source_ip": event.get("source_ip"),
                "user_agent": event.get("user_agent"),
                "aws_region": event.get("aws_region"),
                "event_source": event.get("event_source"),
                "request_parameters": event.get("request_parameters"),
                "response_elements": event.get("response_elements"),
                "user_identity": event.get("user_identity"),
                "error_code": event.get("error_code"),
                "error_message": event.get("error_message"),
                "threat_score": sr["threat_score"],
                "matched_threats": sr["matched_threats"],
                "threat_categories": sr["threat_categories"],
            }


def create_agent() -> ThreatDetectionAgent:
    return ThreatDetectionAgent()
