"""
Batch Processing Tool
Processes multiple events and calculates aggregate risk metrics.
"""

from typing import List, Tuple
from strands import tool
from logger import get_logger
from .correlation_analyzer import parse_event_signals, calculate_correlation_confidence

logger = get_logger("batch_processor")


@tool
def calculate_batch_risk(confidence_scores: List[float]) -> dict:
    """Aggregate risk metrics for a batch of events."""
    if not confidence_scores:
        return {"average_confidence": 0.0, "risk_flag": "NO DATA"}

    avg_confidence = sum(confidence_scores) / len(confidence_scores)
    if avg_confidence >= 0.7:
        risk_flag = "HIGH RISK"
    elif avg_confidence >= 0.4:
        risk_flag = "MEDIUM RISK"
    else:
        risk_flag = "LOW RISK"

    return {
        "average_confidence": round(avg_confidence, 2),
        "risk_flag": risk_flag,
        "event_count": len(confidence_scores),
        "max_confidence": round(max(confidence_scores), 2),
        "min_confidence": round(min(confidence_scores), 2),
    }


@tool
def process_event_batch(events: List[dict]) -> Tuple[List[dict], dict]:
    """Process a batch of CloudTrail events and generate correlation results."""
    logger.info(f"Processing batch of {len(events)} events")

    all_results: list = []
    confidence_scores: list = []

    for event in events:
        signals = parse_event_signals(event)
        confidence = calculate_correlation_confidence(signals)
        confidence_scores.append(confidence)

        correlation_results = {
            signal_name: signal_data["present"]
            for signal_name, signal_data in signals.items()
        }
        insider_hypothesis = {
            "hypothesis": "InsiderExfiltrationHypothesis" if confidence >= 0.5 else "NoThreatDetected",
            "confidence": round(confidence, 2),
        }
        all_results.append({
            "event_id": event.get("event_id", "unknown"),
            "event_name": event.get("eventName", event.get("action", "unknown")),
            "timestamp": event.get("eventTime", event.get("timestamp", "")),
            "correlation_results": correlation_results,
            "insider_hypothesis": insider_hypothesis,
            "confidence": round(confidence, 2),
        })

    batch_results = calculate_batch_risk(confidence_scores)
    logger.info(f"Batch complete: avg={batch_results['average_confidence']}, risk={batch_results['risk_flag']}")
    return all_results, batch_results
