Execute complete incident response for this security incident:

INCIDENT CLASSIFICATION:
- Attack Type: {attack_type}
- Threat Score: {threat_score}
- Priority: {priority}
- Risk Factors: {risk_factors}

RECOMMENDED ACTIONS:
{actions}

INCIDENT DATA:
- User: {user_id}
- Resources: {n_resources} affected
- Source IP: {source_ip}
- Events: {n_events} detected
- Threat Patterns: {patterns}

EXECUTE ALL 4 PHASES:

PHASE 1 - MITIGATION (use execute_aws_mitigation):
- Actions: {actions}
- User: {user_id}
- Resources: {resources_top5}
- Source IP: {source_ip}

PHASE 2 - FORENSICS (use conduct_forensic_investigation):
- Event List: {events}
- Event Details: {details}
- Attack Hypothesis: {attack_type}

PHASE 3 - LEARNING (use update_learning_models):
- Attack Patterns: {patterns}

PHASE 4 - TICKETING (use manage_incident_tickets):
- Mitigation Results: (from Phase 1)
- Priority Level: {priority}
- Actions Taken: {actions}

Create appropriate tickets:
- RESOLVED ticket if all actions succeeded
- PRIORITY ticket if manual intervention needed

Provide complete incident response with all phases executed.