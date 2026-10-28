# Agent Flow — Cheat Sheet

```
      +-----------------+
      | CloudTrail (EB) |
      +--------+--------+
               |
        +------v------+   drops ~90% of events (reads, allowlist)
        | stage0      |
        | filter      |
        +------+------+
               |
        +------v------+   Haiku, structured DetectionResult
        | stage1      |
        | detection   |
        +------+------+
               |
        +------v------+   Haiku, merged correlation + intel
        | stage2      |
        | enrichment  |
        +------+------+
               |
        +------v------+   Sonnet, TriageResult (severity, confidence, actions)
        | stage3      |
        | triage      |
        +------+------+
               |
      confidence >= 0.8 & non-destructive?
       yes -> execute      no -> approval_gate (Slack)
               |
        +------v------+   Sonnet; idempotent mitigation + ticket
        | stage4      |
        | response    |
        +---+-----+---+
            |     |
            |     +--> forensics (async)
            |
            +--> outputs (all optional, independent):
            |      DynamoDB | Splunk HEC | SES email | PagerDuty | TheHive
            |
            +----> learning (nightly)
                     ^
                     |  reads closed TheHive cases (TP/FP)
                     +-- TheHive analyst UI
```
