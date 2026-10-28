"""Stage 2 (Enrichment) tools: correlation + intelligence merged."""

from .correlation_analyzer import (
    parse_event_signals,
    calculate_correlation_confidence,
    is_off_hours_access,
)
from .batch_processor import process_event_batch, calculate_batch_risk
from .mitre_mapper import map_to_mitre_attack
from .threat_feed_lookup import lookup_threat_intelligence
from .pattern_matcher import match_attack_patterns
from .ioc_analyzer import analyze_iocs

__all__ = [
    "parse_event_signals",
    "calculate_correlation_confidence",
    "is_off_hours_access",
    "process_event_batch",
    "calculate_batch_risk",
    "map_to_mitre_attack",
    "lookup_threat_intelligence",
    "match_attack_patterns",
    "analyze_iocs",
]
