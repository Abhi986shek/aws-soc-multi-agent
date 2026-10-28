"""
MITRE ATT&CK Mapper Tool
Maps observed behaviors to MITRE ATT&CK techniques and tactics.
"""

from functools import lru_cache

import yaml
from strands import tool

from config import settings
from logger import get_logger

logger = get_logger("mitre_mapper")


# Fallback inline mapping (used when the yaml has no entry for a behavior).
_FALLBACK_MITRE_DB: dict[str, dict] = {
    "large_s3_download": {
        "technique_id": "T1537",
        "technique_name": "Transfer Data to Cloud Account",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data by transferring to cloud storage",
    },
    "cloudtrail_disabled": {
        "technique_id": "T1070.008",
        "technique_name": "Indicator Removal: Clear Cloud Logs",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or disable cloud logs to cover tracks",
    },
    "log_deletion_attempt": {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts to remove evidence",
    },
    "bucket_policy_modification": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate cloud resource policies",
    },
    "off_hours_access": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may use valid accounts at unusual times",
    },
    "new_device_access": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "description": "Access from new or unusual device fingerprint",
    },
    "account_discovery": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate accounts and permissions",
    },
    "data_staged": {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Data staged for exfiltration to external service",
    },
}


@lru_cache(maxsize=1)
def _load_yaml_mappings() -> dict[str, list[str]]:
    """Load config/rules/mitre_map.yaml → {behavior_or_event: [technique_id, ...]}."""
    path = settings.rules_dir / "mitre_map.yaml"
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        mappings = data.get("mappings", {}) if isinstance(data, dict) else {}
        logger.info(f"Loaded MITRE mappings from {path}: {len(mappings)} entries")
        return mappings
    except Exception as e:
        logger.error(f"Error loading mitre_map.yaml: {e}")
        return {}


def _lookup_behavior(behavior: str) -> dict | None:
    """Prefer yaml mapping (strip technique ids' inline comments); fall back to inline dict."""
    yaml_mappings = _load_yaml_mappings()
    if behavior in yaml_mappings:
        technique_ids = yaml_mappings[behavior] or []
        if technique_ids:
            primary_id = str(technique_ids[0]).split()[0].strip()
            # If the fallback dict has a richer entry for the same behavior, keep
            # tactic/description from it; otherwise return a minimal record.
            fallback = _FALLBACK_MITRE_DB.get(behavior)
            if fallback and fallback["technique_id"].split(".")[0] == primary_id.split(".")[0]:
                return fallback
            return {
                "technique_id": primary_id,
                "technique_name": behavior,
                "tactic": "Unknown",
                "description": f"Mapped from config/rules/mitre_map.yaml ({primary_id})",
            }
    return _FALLBACK_MITRE_DB.get(behavior)


@tool
def map_to_mitre_attack(behaviors: list[str], event_context: dict) -> dict:
    """
    Maps observed security behaviors to MITRE ATT&CK framework techniques.
    Primary: STIX bundle keyword match via integrations.mitre.
    Fallback: yaml + inline dict.
    """
    mapped_techniques: list[dict] = []
    tactics_identified: set[str] = set()

    # Primary: STIX bundle lookup (silent no-op when offline/MOCK_MODE)
    covered: set[str] = set()
    try:
        from integrations.mitre import map_behaviors as _stix_map
        for entry in _stix_map(list(behaviors)):
            tactic = (entry.get("tactics") or ["Unknown"])[0]
            mapped_techniques.append({
                "technique_id": entry["technique_id"],
                "technique_name": entry["technique_name"],
                "tactic": tactic.title() if isinstance(tactic, str) else "Unknown",
                "description": "Mapped from MITRE STIX bundle",
            })
            tactics_identified.add(mapped_techniques[-1]["tactic"])
            covered.add(entry["behavior"])
    except Exception as e:
        logger.debug(f"STIX mapping unavailable, falling back: {e}")

    for behavior in behaviors:
        if behavior in covered:
            continue
        mapping = _lookup_behavior(behavior)
        if mapping:
            mapped_techniques.append(mapping)
            tactics_identified.add(mapping["tactic"])

    attack_pattern = _identify_attack_pattern(tactics_identified)

    return {
        "mitre_techniques": mapped_techniques,
        "tactics": list(tactics_identified),
        "attack_pattern": attack_pattern,
        "total_techniques": len(mapped_techniques),
        "severity_indicator": _calculate_mitre_severity(mapped_techniques),
    }


def _identify_attack_pattern(tactics: set) -> str:
    if {"Exfiltration", "Defense Evasion"} <= tactics:
        return "Insider Data Exfiltration"
    if "Exfiltration" in tactics:
        return "Data Theft"
    if {"Defense Evasion", "Persistence"} <= tactics:
        return "Persistent Threat with Evasion"
    if "Defense Evasion" in tactics:
        return "Anti-Forensics Activity"
    return "Reconnaissance/Discovery"


def _calculate_mitre_severity(techniques: list) -> str:
    high_severity_tactics = {"Exfiltration", "Defense Evasion", "Impact"}
    severity_count = sum(1 for t in techniques if t["tactic"] in high_severity_tactics)
    if severity_count >= 2:
        return "Critical"
    if severity_count == 1:
        return "High"
    return "Medium"
