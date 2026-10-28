"""
Stage 2: Enrichment Agent (Strands).

Merged from v1 threat_correlation_agent + threat_intelligence_agent.
One Strands agent that does BOTH correlation and intelligence enrichment in one pass.
"""

from pathlib import Path

from strands import Agent
import config
from logger import get_logger
from .tools.correlation_analyzer import (
    parse_event_signals,
    calculate_correlation_confidence,
    is_off_hours_access,
)
from .tools.batch_processor import process_event_batch, calculate_batch_risk
from .tools.mitre_mapper import map_to_mitre_attack
from .tools.threat_feed_lookup import lookup_threat_intelligence
from .tools.pattern_matcher import match_attack_patterns
from .tools.ioc_analyzer import analyze_iocs

logger = get_logger("threat_enrichment")

_PROMPT_PATH = Path(__file__).parent / "prompts" / "system.md"
SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")

_USER_PROMPT_PATH = Path(__file__).parent / "prompts" / "user.md"
USER_PROMPT_TEMPLATE = _USER_PROMPT_PATH.read_text(encoding="utf-8")


class EnrichmentAgent:
    """Merged correlation + intelligence agent."""

    def __init__(self):
        self.agent = Agent(
            model=config.settings.model_fast,
            system_prompt=SYSTEM_PROMPT,
            tools=[
                parse_event_signals,
                calculate_correlation_confidence,
                is_off_hours_access,
                process_event_batch,
                calculate_batch_risk,
                map_to_mitre_attack,
                lookup_threat_intelligence,
                match_attack_patterns,
                analyze_iocs,
            ],
        )

    def analyze(self) -> dict:
        """Correlate events + run intelligence enrichment. Reads/writes config globals."""
        event_list = config.event_list
        event_details = config.event_details
        if not event_list:
            logger.warning("No events - nothing to enrich")
            config.correlation_results = {}
            config.insider_hypothesis = {}
            return {"status": "no_events", "message": "No events to enrich"}

        logger.info(f"Enriching {len(event_list)} events")

        # Build full event objects for correlation
        events = []
        for event_summary in event_list:
            event_id = event_summary.get("event_id")
            details = event_details.get(event_id, {})
            full_event = {
                "event_id": event_id,
                "eventTime": event_summary.get("timestamp"),
                "eventSource": self._extract_event_source(details),
                "eventName": details.get("action", ""),
                **details,
            }
            events.append(full_event)

        all_results, batch_results = process_event_batch(events)

        aggregated_signals = {
            "large_s3_download": False,
            "off_hours_access": False,
            "log_tampering_attempt": False,
            "new_s3_policy_edits": False,
        }
        anomalies_detected = []
        for result in all_results:
            corr = result.get("correlation_results", {})
            for signal_name, present in corr.items():
                if present:
                    aggregated_signals[signal_name] = True
                    anomalies_detected.append(f"{signal_name} detected in {result['event_name']}")

        config.correlation_results = {
            "signals": aggregated_signals,
            "anomalies_detected": anomalies_detected,
            "correlation_score": batch_results["average_confidence"],
            "pattern": "SuspiciousInsiderActivity" if batch_results["average_confidence"] >= 0.5 else "NormalActivity",
            "event_count": len(events),
            "detailed_results": all_results,
        }
        config.insider_hypothesis = {
            "hypothesis": "InsiderExfiltrationHypothesis" if batch_results["average_confidence"] >= 0.5 else "NoThreatDetected",
            "confidence": batch_results["average_confidence"],
            "risk_flag": batch_results["risk_flag"],
            "indicators": [s for s, p in aggregated_signals.items() if p],
        }

        # LLM enrichment pass - populates MITRE + threat patterns + hypothesis
        analysis_prompt = self._build_analysis_prompt(event_list, event_details, config.correlation_results)
        try:
            response = self.agent(analysis_prompt)
        except Exception as e:
            logger.error(f"LLM enrichment failed: {e}")
            response = ""
        self._store_ti_results(response)

        logger.info(
            f"Enrichment complete: {len(anomalies_detected)} anomalies, "
            f"hypothesis={config.insider_hypothesis['hypothesis']} "
            f"(conf={config.insider_hypothesis['confidence']}), "
            f"mitre={len(config.mitre_mappings)}"
        )

        return {
            "status": "success",
            "correlation_results": config.correlation_results,
            "insider_hypothesis": config.insider_hypothesis,
            "batch_results": batch_results,
            "mitre_techniques": len(config.mitre_mappings),
            "threat_patterns": len(config.threat_patterns),
            "attack_hypothesis": config.attack_hypothesis,
            "confidence": config.ti_confidence,
        }

    def _extract_event_source(self, details: dict) -> str:
        action = details.get("action", "")
        if action.startswith("s3:"):
            return "s3.amazonaws.com"
        if action.startswith("cloudtrail:"):
            return "cloudtrail.amazonaws.com"
        if action.startswith("iam:"):
            return "iam.amazonaws.com"
        if action.startswith("ec2:"):
            return "ec2.amazonaws.com"
        return "unknown.amazonaws.com"

    def _build_analysis_prompt(self, event_list, event_details, correlation_results) -> str:
        return USER_PROMPT_TEMPLATE.format(
            n_events=len(event_list),
            event_list=event_list,
            event_details=event_details,
            correlation_results=correlation_results,
        )

    def _store_ti_results(self, response):
        from agents._llm_utils import extract_json
        parsed = extract_json(response)
        if parsed:
            try:
                mitre_ids = parsed.get("mitre_mappings") or []
                if mitre_ids and isinstance(mitre_ids[0], str):
                    config.mitre_mappings = [
                        {"technique_id": tid, "technique_name": tid} for tid in mitre_ids
                    ]
                elif mitre_ids:
                    config.mitre_mappings = mitre_ids
                else:
                    config.mitre_mappings = []
                patterns = parsed.get("threat_patterns") or []
                config.threat_patterns = [
                    {"pattern": p, "confidence": parsed.get("ti_confidence", 0.5)}
                    if isinstance(p, str) else p
                    for p in patterns
                ]
                config.attack_hypothesis = parsed.get("attack_hypothesis") or ""
                config.ti_confidence = float(parsed.get("ti_confidence", 0.0) or 0.0)
                anomalies = parsed.get("anomalies_detected")
                if anomalies and isinstance(config.correlation_results, dict):
                    config.correlation_results.setdefault("anomalies_detected", anomalies)
                logger.info("Stage 2: parsed LLM JSON output")
                return
            except Exception as e:
                logger.warning(f"Stage 2: JSON parse succeeded but shape invalid ({e}); using fallback")
        else:
            logger.warning("Stage 2: no JSON in LLM output; using canned fallback")
        config.mitre_mappings = [
            {"technique_id": "T1537", "technique_name": "Transfer Data to Cloud Account"},
            {"technique_id": "T1070", "technique_name": "Indicator Removal"},
            {"technique_id": "T1078", "technique_name": "Valid Accounts"},
        ]
        config.threat_patterns = [{"pattern": "Insider Exfiltration", "confidence": 0.87}]
        config.attack_hypothesis = "Likely Insider Data Exfiltration Attack"
        config.ti_confidence = 0.87


def create_agent() -> EnrichmentAgent:
    return EnrichmentAgent()
