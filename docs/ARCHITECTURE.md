# Architecture

## 1. Design goals

SOC Agent exists to automate L1 SOC triage on AWS. The specific problems
it solves:

- **Signal vs noise on CloudTrail.** ~90% of CloudTrail is benign reads;
  human analysts should never see them.
- **Consistent enrichment.** Every incident should ship with MITRE ATT&CK
  mapping, IOC extraction, and IP reputation — regardless of who is
  on shift.
- **Time-to-mitigate.** Non-destructive actions (archiving GuardDuty
  findings, forensics backup) should fire without a human in the loop;
  destructive ones (disabling users, revoking keys) should page an
  analyst.
- **Audit trail.** Every incident produces a DynamoDB ticket, a TheHive
  case, and a Splunk event — no matter how the pipeline exits.

Non-goals (deliberate):

- Not a SIEM. It ships events *to* Splunk, does not query it.
- Not a network-layer defender. AWS API plane only.
- Not a replacement for a human tier-2 analyst. It runs L1 triage and
  hands off.

## 2. Data flow

```
CloudTrail batch (list[dict])
     │
     ▼
[Stage 0 filter]  →  drops benign_read + allowlisted
     │  kept events (list[dict])
     ▼
[Stage 1 detection]  →  writes config.event_list, event_details
     │  scored + flagged event ids
     ▼
[Stage 2 enrichment]  →  writes config.mitre_mappings, attack_hypothesis,
     │                    correlation_results, ti_confidence
     ▼
[Stage 3 triage]  →  writes config.threat_score, priority_level,
     │                recommended_actions, risk_factors
     ▼
[Approval gate]   →  reads recommended_actions × ti_confidence
     │                emits Slack alert, awaits decision
     ▼
[Stage 4 response]  →  boto3 mitigation, DynamoDB, Splunk, SES,
     │                  PagerDuty, TheHive case
     ▼
[Forensics + Learning sidecars]  →  fire-and-forget async
```

Events themselves are passed as plain `list[dict]` between stages 0 and 1.
Every subsequent hand-off is via the `config` module globals (see State
management below) — that is the load-bearing v1-compat surface.

## 3. Stage table

| Stage | Tier | Input | Output | Tools | Failure mode |
|---|---|---|---|---|---|
| 0 Filter | — | Raw CloudTrail batch | Kept events | `is_benign_read`, `is_allowlisted` | Fail open — batch passes through untouched |
| 1 Detection | fast | Kept events | Flagged events + scores | `get_threat_patterns`, `analyze_event_with_llm` | Parse failure → all scores 0.0, nothing flagged |
| 2 Enrichment | fast | Flagged events | MITRE + IOCs + correlation | Correlation, MITRE mapper, IOC extract, threat feeds, pattern matcher, batch processor | STIX fetch fail → falls back to `config/rules/mitre_map.yaml` |
| 3 Triage | smart | Everything so far | Priority + actions | Risk scorer, action recommender | Parse failure → priority=medium, no destructive actions |
| Approval gate | — | recommended_actions | approved: bool | Slack webhook | Fails **closed** on any exception |
| 4 Response | smart | Full context | Ticket + AWS mitigation | boto3 IAM/EC2/GuardDuty/S3, ticket writer, notification fan-out | Per-tool try/except; ticket + fan-out still fire |
| Forensics sidecar | smart | Full context | Timeline | CloudTrail lookup, ordering | Fire-and-forget; never blocks pipeline |
| Learning sidecar | smart | Closed TheHive cases | Pattern update proposals | TheHive query, YAML diff | No cases → no-op |

Tier → concrete model id: `MODEL_FAST` / `MODEL_SMART` in `.env`.

## 4. Prompt engineering

Every LLM-backed agent has its prompts as **plain markdown files** under
`agents/<stage>/prompts/`:

```
agents/detection/prompts/system.md    role + rules
agents/detection/prompts/user.md      per-invocation template
```

Rationale for externalising:

- **Reviewable in git.** Prompt changes are diffable and reviewable
  independent of code changes.
- **No re-deploy for prompt tweaks.** In a hosted deploy you can mount
  a new `prompts/` directory without touching Python.
- **Easy to A/B.** Swap `system.md` behind a feature flag, keep the
  loader identical.

Iterate by editing the `.md` file, running `MOCK_MODE=true python
main.py` to check parsing, then running `pytest -k detection` to
confirm the tool contract is unchanged.

## 5. State management (config module globals)

The `config` package exposes mutable module-level attributes
(`event_list`, `mitre_mappings`, `threat_score`, …) that agents write
and read directly. Reasons this is honest legacy rather than a design
choice:

- **v1 compatibility.** Every v1 Strands agent already writes into
  `config.*`; keeping that surface avoids a rewrite of every prompt and
  tool.
- **Simplicity of transit.** No `WorkflowContext` class means no
  serialization boundary between stages — the pipeline runs in one
  Python process.

Concrete rules today:

- Stage 1 writes `event_list`, `event_details`.
- Stage 2 writes `mitre_mappings`, `attack_hypothesis`,
  `correlation_results`, `ti_confidence`.
- Stage 3 writes `threat_score`, `priority_level`,
  `recommended_actions`, `risk_factors`.
- Stage 4 reads all of them; writes `mitigation_actions_taken`.

When this should evolve into a real `WorkflowContext` dataclass:

- When we run stages in different processes (e.g. once SQS between-stage
  handoff is turned on via `SQS_*` env vars) — module globals no longer
  survive the process boundary.
- When we need to run two workflows concurrently (module globals collide).

Until then, the trace_id-based logging context (`log_context` in
`logger.py`) is what separates one run from another in the log stream.

## 6. Model tiering rationale

- **Fast tier (Haiku-class)** for stages 1-2. These are
  classification-heavy: score N events, extract IOCs, map to MITRE. Cost
  and latency dominate correctness sensitivity; a cheap model with good
  tool use is optimal.
- **Smart tier (Sonnet-class)** for stages 3-4 and sidecars. Triage
  and Response make decisions with real-world consequences (page vs
  don't page, disable vs don't disable). Worth the extra tokens.

Both tiers use the same `strands.Agent` interface, so the boundary is a
config choice, not a code change.

## 7. Integration points

Every integration is optional and fails safely to no-op.

| Integration | Purpose | Config empty → |
|---|---|---|
| Slack (`slack.py`) | Approval gate + alerts | `send_alert` and `request_approval` return early with a `skipped` log line |
| Email (`email.py`) | Priority SES notification | Returns `{"status": "skipped", "reason": "email_not_configured"}` |
| Splunk HEC (`splunk.py`) | SIEM stream + dashboards | Returns `{"status": "skipped"}` |
| PagerDuty (`pagerduty.py`) | On-call paging | `trigger_incident` returns early |
| TheHive (`thehive.py`) | Case management + feedback | Logs once at startup, then silent |
| MITRE (`mitre.py`) | STIX bundle loader | Falls back to `config/rules/mitre_map.yaml` |
| Threat feeds (`threat_feeds.py`) | AbuseIPDB + GreyNoise IP reputation | Per-feed no-op if key blank |
| Redis (`redis_store.py`) | Rolling correlation window | Non-fatal warning; pipeline still runs |
| DynamoDB (via `agents/response`) | Ticket persistence | No-op in `MOCK_MODE`; live boto3 client otherwise |

## 8. Feedback loop

The Learning sidecar runs nightly. Steps:

1. Query TheHive for cases resolved in the last 24 hours.
2. Group by MITRE technique id and pattern tag.
3. For each group, compute the TruePositive / FalsePositive ratio.
4. Emit a diff to `learning_updates` (in `config`) suggesting pattern
   confidence up/down-grades.
5. In an operator-supervised deploy, that diff turns into a rule-update
   PR against `config/rules/threats.yaml`.

The pipeline never mutates YAML rule files at runtime; the diff is an
input to a human reviewer.

## 9. Failure modes & fallbacks

- **LLM parse failure** (stages 1-3): every stage catches the exception,
  logs it, and writes a safe default (score 0.0, priority=medium, no
  destructive actions). The pipeline continues.
- **STIX bundle fetch failure**: MITRE loader falls back to
  `config/rules/mitre_map.yaml`, a hand-maintained subset.
- **AWS mitigation exception** (Stage 4): each boto3 call is wrapped in
  try/except and recorded on the ticket as `error=...`. The ticket still
  writes, notifications still fire.
- **Approval gate exception**: fails **closed** — returns False. Stage 4
  is skipped, ticket state records `awaiting_approval`.
- **Sidecar exception**: fire-and-forget tasks; exceptions never bubble
  back into the workflow status.
- **Redis unreachable**: `record_event` failure is logged as WARN; the
  correlation window is empty for that event but nothing else breaks.

## 10. Testing strategy

Three test surfaces, all offline:

- `tests/unit/` — per-unit tests for filter rules, detection parsing,
  approval gate mode logic, MITRE loader, etc.
- `tests/integrations/` — one file per external service; asserts each
  is a graceful no-op when unconfigured, and that the request payload
  is correct when configured (using `httpx.MockTransport` /
  monkeypatch).
- `tests/integration/test_full_pipeline.py` — the full stages-0-through-4
  smoke test in `MOCK_MODE`.

Full suite: ~70 tests, ~2.5s wall clock, no network, no AWS, no LLM.
