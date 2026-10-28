Perform comprehensive triage and prioritization for this security incident:

THREAT INTELLIGENCE (from Agent 3):
- Attack Hypothesis: {attack_hypothesis}
- TI Confidence: {ti_confidence}
- MITRE Techniques: {n_mitre} identified
- Threat Patterns: {threat_patterns}

EVENT DATA:
- Total Events: {n_events}
- Behaviors: {behaviors}
- Resources Affected: {n_resources}
- Data Volume: {total_data_volume} bytes

TASKS:
1. Use calculate_threat_risk to compute overall threat score
   - TI Confidence: {ti_confidence}
   - MITRE Severity: {mitre_severity}
   - Event Count: {n_events}
2. Use classify_data_sensitivity to classify data impact
3. Use score_threat_severity to score severity with context
4. Use recommend_mitigation_actions to get action plan

Provide a complete triage assessment. Be thorough and use all available tools.