"""Config package.

Exposes:
- `settings` (typed)
- Mutable process-wide globals that the v1 Strands agents mutate directly:
  `event_list`, `event_details`, `correlation_results`, `insider_hypothesis`,
  `mitre_mappings`, `threat_patterns`, `attack_hypothesis`, `ti_confidence`,
  `threat_score`, `priority_level`, `recommended_actions`, `risk_factors`,
  `mitigation_actions_taken`, `forensic_report`, `incident_timeline`,
  `learning_updates`, and `MODEL_NAME` / `MODEL_FAST` / `MODEL_SMART`.
"""
from __future__ import annotations

from .settings import settings

# --- v1 compat: model id shortcuts (read from settings, which reads .env) ---
MODEL_NAME: str = settings.model_smart or settings.model_fast or ""
MODEL_FAST: str = settings.model_fast
MODEL_SMART: str = settings.model_smart

# --- v1 compat: mutable shared state ---
# Agents 1-2 outputs
event_list: list = []
event_details: dict = {}
correlation_results: dict = {}
insider_hypothesis: dict = {}

# Agent 3 outputs
mitre_mappings: list = []
threat_patterns: list = []
attack_hypothesis: str = ""
ti_confidence: float = 0.0

# Agent 4 outputs
threat_score: float = 0.0
priority_level: str = ""
recommended_actions: list = []
risk_factors: dict = {}

# Agent 5 outputs
mitigation_actions_taken: list = []
forensic_report: dict = {}
incident_timeline: list = []
learning_updates: dict = {}

__all__ = [
    "settings",
    "MODEL_NAME", "MODEL_FAST", "MODEL_SMART",
    "event_list", "event_details",
    "correlation_results", "insider_hypothesis",
    "mitre_mappings", "threat_patterns", "attack_hypothesis", "ti_confidence",
    "threat_score", "priority_level", "recommended_actions", "risk_factors",
    "mitigation_actions_taken", "forensic_report", "incident_timeline",
    "learning_updates",
]
