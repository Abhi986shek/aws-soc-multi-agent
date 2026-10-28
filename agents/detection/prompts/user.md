Analyze the following {n_events} CloudTrail events for security threats.

INSTRUCTIONS:
1. First, use get_threat_patterns() to retrieve the threat patterns
2. For EACH event below, analyze it against the threat patterns
3. Provide a threat score (0.01 to 1.00) and reasoning for each event
4. Format your response as a JSON array with one object per event

EVENTS TO ANALYZE:

{events_block}

REQUIRED OUTPUT FORMAT:
Provide your analysis as a JSON array:
[
  {{
    "event_id": "evt_xxx",
    "event_name": "EventName",
    "threat_score": xxx,
    "matched_threats": [["category", "specific pattern"]],
    "threat_categories": ["category1"],
    "reasoning": "Detailed explanation of the score"
  }}
]

Do NOT include "is_suspicious" - that is determined automatically.