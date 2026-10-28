# SOC Agent

SOC Agent is an automated Security Operations Center pipeline for AWS. It
ingests CloudTrail events, uses LLM-powered agents to detect, enrich, triage,
and respond to threats, and routes incidents to your SOC tooling (Splunk,
TheHive, PagerDuty, email).

## Table of contents

- [What it does](#what-it-does)
- [Architecture at a glance](#architecture-at-a-glance)
- [Full pipeline walkthrough](#full-pipeline-walkthrough)
- [Features](#features)
- [Repository structure](#repository-structure)
- [Configuration](#configuration)
- [Running](#running)
- [Safety](#safety)
- [Extending](#extending)
- [License / Author](#license--author)

## What it does

- Ingests CloudTrail events in near real time (EventBridge push or pull).
- Drops obviously benign traffic with deterministic rules before any LLM
  call — saves ~90% of tokens.
- Scores remaining events with an LLM-powered detection agent.
- Enriches suspicious events with correlation, MITRE ATT&CK mapping, IOC
  extraction, and IP reputation feed lookups (AbuseIPDB + GreyNoise).
- Triages each incident: severity, priority, confidence, recommended actions.
- Executes real AWS mitigation via boto3, gated by a human-approval step
  for anything destructive.
- Persists tickets in DynamoDB and fans out to Splunk HEC, SES email,
  PagerDuty, and TheHive.
- Feeds closed TheHive cases back into a nightly learning sidecar that
  tunes detection patterns.
- Ships with a full `MOCK_MODE` for offline end-to-end runs — no AWS,
  Redis, or Anthropic access required.

## Architecture at a glance

```
                            +------------------------------+
                            |  AWS CloudTrail (EventBridge)|
                            +--------------+---------------+
                                           |
                                           v
+-----------+   +------------+   +------------+   +---------+   +-----------+
| Stage 0   |-->| Stage 1    |-->| Stage 2    |-->| Stage 3 |-->| Approval  |
| filter    |   | detection  |   | enrichment |   | triage  |   | gate      |
| (rules)   |   | (fast LLM) |   | (fast LLM) |   |(smart)  |   |           |
+-----------+   +------------+   +------------+   +---------+   +-----+-----+
                                                                      |
                          +-------------------------------------------+
                          |
                          v
                    +-----------+          +----------------------------+
                    | Stage 4   |--------->| DynamoDB / Splunk HEC /    |
                    | response  |          | SES email / PagerDuty /    |
                    | (smart)   |          | TheHive case               |
                    +-----+-----+          +-------------+--------------+
                          |                              |
             fire-and-forget                             |  analyst resolves
                          |                              |  case in TheHive UI
                          v                              v
                    +-----------+                +-----------------+
                    | Forensics |                | Learning        |
                    | sidecar   |<---- feedback -| sidecar (nightly)|
                    +-----------+                +-----------------+
```

## Full pipeline walkthrough

### Stage 0 — Filter (rules only)

- Deterministic pre-filter. No LLM.
- Runs `benign_events` (reads / describes) and `allowlist_check`
  (allowlisted principals, IPs, user agents from `config/rules/allowlist.yaml`).
- Records surviving events into a Redis rolling correlation window.
- Writes: kept event list to Stage 1.

### Stage 1 — Detection (fast-tier LLM)

- Model tier: **fast** (`MODEL_FAST`, e.g. a Haiku-class model).
- Tools: `get_threat_patterns` (loads `config/rules/threats.yaml`),
  `analyze_event_with_llm`.
- Batches 5 events, asks the LLM to score each 0.0-1.0 with matched
  patterns and reasoning.
- Writes: `config.event_list`, `config.event_details` (flagged events
  only), average score.

### Stage 2 — Enrichment (fast-tier LLM)

- Model tier: **fast**.
- Tools: correlation lookup (Redis rolling window), MITRE ATT&CK mapper
  (real STIX bundle), IOC extractor, threat feeds (AbuseIPDB + GreyNoise),
  pattern matcher, batch processor.
- Writes: `config.attack_hypothesis`, `config.mitre_mappings`,
  `config.correlation_results`, `config.ti_confidence`.

### Stage 3 — Triage (smart-tier LLM)

- Model tier: **smart** (`MODEL_SMART`, e.g. a Sonnet-class model).
- Reads all Stage 1 + Stage 2 context, produces:
  `threat_score`, `priority_level` (low/medium/high/critical),
  `recommended_actions`, `risk_factors`.
- Writes: `config.threat_score`, `config.priority_level`,
  `config.recommended_actions`.

### Approval gate

- Runs between Stage 3 and Stage 4.
- If any recommended action is destructive (disable_user, revoke_keys,
  isolate_account, …) and triage confidence <
  `TRIAGE_CONFIDENCE_THRESHOLD`, the gate requires human approval.
- Modes (`SLACK_APPROVAL_MODE`): `deny` (fail closed, default),
  `auto_approve` (dev/test), `manual` (poll `approvals/<trace>_<action>.decision`).
- In `DRY_RUN` or `MOCK_MODE`, the gate auto-grants.

### Stage 4 — Response (smart-tier LLM)

- Model tier: **smart**.
- Tools: real boto3 mitigation (IAM DenyAll attach, key revoke, GuardDuty
  archive, EC2 isolate, S3 forensics backup), ticket writer, notification fan-out.
- Rate-limited: `MAX_MITIGATIONS_PER_PRINCIPAL_PER_HOUR`.
- Writes: DynamoDB ticket, Splunk HEC event, SES email (priority),
  PagerDuty page (priority), TheHive case.

### Forensics sidecar (async, off hot path)

- Model tier: **smart**.
- Reconstructs a per-incident timeline from CloudTrail + config globals.
- Fire-and-forget; never blocks the pipeline.

### Learning sidecar (nightly)

- Model tier: **smart**.
- Reads TheHive cases resolved in the last 24 hours; uses
  `resolutionStatus` to up/downgrade MITRE technique and pattern tags.
- Emits proposed rule updates for review.

## Features

**Detection & analysis**

- LLM threat scoring with matched-pattern rationale
- Real MITRE ATT&CK STIX bundle (cached on disk)
- IP reputation lookups via AbuseIPDB + GreyNoise
- Redis rolling correlation window for burst / cross-event patterns

**Response**

- Real boto3 mitigation (IAM, EC2, GuardDuty, S3 forensics backup)
- Approval gate with three modes: `deny`, `auto_approve`, `manual`
- `DRY_RUN` and `AUTO_MITIGATION_ENABLED` kill switches
- Per-principal rate limiting

**Notifications & routing**

- DynamoDB ticket persistence
- Splunk HEC push (importable dashboard XML included)
- SES priority email
- PagerDuty Events API v2
- TheHive case management with tasks + observables

**Feedback loop**

- Closed TheHive cases feed the nightly learning sidecar
- Pattern / technique tags are re-weighted based on TruePositive / FalsePositive

**Ops**

- Structured, greppable logging with per-step markers and trace ids
- `MOCK_MODE` for fully-offline end-to-end runs
- Unit + integrations + integration test suite (~70 tests, ~2.5s)

## Repository structure

```
soc_agents/
├── main.py                        Async entry point; runs mock or continuous mode
├── run_mock.py                    Convenience: MOCK_MODE=true python main.py
├── mock_llm.py                    Monkey-patches strands.Agent for offline runs
├── logger.py                      Namespaced logger factory + step logger + log_context
├── pyproject.toml                 Package metadata, deps, tool configs
├── .env.example                   All configurable env vars documented
│
├── config/                        Configuration
│   ├── settings.py                pydantic-settings - every env var typed
│   ├── __init__.py                Exposes `settings` + v1-compat globals
│   └── rules/                     Rule data files (yaml)
│       ├── allowlist.yaml         Known-good principals/IPs/UAs (Stage 0)
│       ├── threats.yaml           Threat patterns (Stage 1 LLM context)
│       └── mitre_map.yaml         Fallback MITRE mapping (Stage 2)
│
├── agents/
│   ├── orchestrator.py            Runs the pipeline; polls CloudTrail; fans out to stages
│   ├── _llm_utils.py              Shared JSON-from-LLM extractor
│   ├── filter/                    Stage 0: deterministic rules-based pre-filter
│   │   ├── filter.py
│   │   └── rules/
│   ├── detection/                 Stage 1: LLM-based threat scoring
│   ├── enrichment/                Stage 2: correlation + MITRE + IOCs + feeds
│   ├── triage/                    Stage 3: severity + risk + action recommendation
│   ├── response/                  Stage 4: AWS mitigation + ticketing + approval gate
│   │   ├── agent.py
│   │   ├── approval_gate.py
│   │   ├── prompts/
│   │   └── tools/
│   └── sidecars/
│       ├── forensics/             Timeline reconstruction (async, off hot path)
│       └── learning/              Nightly rule tuning from closed TheHive cases
│
├── integrations/                  External services (each optional, no-op if unconfigured)
│   ├── slack.py                   Approval gate messaging + alerts
│   ├── email.py                   SES for priority incident notifications
│   ├── splunk.py                  HEC push for dashboards + search
│   ├── pagerduty.py               Events API v2 for on-call paging
│   ├── thehive.py                 Case management (bidirectional)
│   ├── mitre.py                   Real MITRE ATT&CK STIX bundle loader
│   ├── threat_feeds.py            AbuseIPDB + GreyNoise IP reputation
│   └── redis_store.py             Rolling correlation window
│
├── docs/
│   ├── ARCHITECTURE.md            Deeper design notes
│   ├── AGENT_FLOW.md              ASCII data-flow diagram
│   ├── thehive_setup.md           Docker Compose + first-time setup
│   └── splunk_dashboard.xml       Importable Splunk dashboard (5 panels)
│
└── tests/                         ~70 tests, run in ~2.5s
    ├── conftest.py                Shared fixtures (mock_settings, sample_ticket, ...)
    ├── unit/                      One file per unit (filter, detection tools, ...)
    ├── integrations/              One file per external service (slack, splunk, ...)
    └── integration/               Full end-to-end pipeline smoke test
```

## Configuration

All configuration lives in environment variables (or `.env`) and is parsed
by `config/settings.py`. No secrets, model ids, ARNs, or URLs are
hardcoded. Order and grouping mirrors `.env.example`.

### LLM

| Name | Required for | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Live LLM calls | *(empty)* | Anthropic API key |
| `MODEL_FAST` | Stages 1-2 | *(empty)* | Fast-tier model id (Haiku-class) |
| `MODEL_SMART` | Stages 3-4, sidecars | *(empty)* | Smart-tier model id (Sonnet/Opus-class) |

### AWS

| Name | Required for | Default | Description |
|---|---|---|---|
| `AWS_REGION` | All AWS clients | `us-east-1` | Region for boto3 clients |
| `DYNAMODB_TABLE` | Ticket persistence | `soc_tickets` | Table name |

### Queues (optional)

| Name | Required for | Default | Description |
|---|---|---|---|
| `SQS_DETECTION_URL` | SQS handoff | *(empty)* | Stage 1 queue |
| `SQS_ENRICHMENT_URL` | SQS handoff | *(empty)* | Stage 2 queue |
| `SQS_TRIAGE_URL` | SQS handoff | *(empty)* | Stage 3 queue |
| `SQS_RESPONSE_URL` | SQS handoff | *(empty)* | Stage 4 queue |

### Redis

| Name | Required for | Default | Description |
|---|---|---|---|
| `REDIS_URL` | Correlation window | `redis://localhost:6379/0` | Redis connection URL |
| `CORRELATION_WINDOW_SECONDS` | Correlation | `3600` | Rolling window size |

### Alerting / Slack / Email

| Name | Required for | Default | Description |
|---|---|---|---|
| `SLACK_WEBHOOK_URL` | Slack alerts | *(empty)* | Incoming-webhook URL |
| `SLACK_APPROVAL_CHANNEL` | Approval gate | *(empty)* | Channel id for approvals |
| `SLACK_APPROVAL_MODE` | Approval gate | `deny` | `deny` \| `auto_approve` \| `manual` |
| `SLACK_APPROVAL_TIMEOUT_SECONDS` | Manual approval | `300` | Poll timeout |
| `EMAIL_FROM` | SES email | *(empty)* | Verified SES sender |
| `EMAIL_TO` | SES email | *(empty)* | Comma-separated recipients |

### Mitigation

| Name | Required for | Default | Description |
|---|---|---|---|
| `DENY_ALL_POLICY_ARN` | disable_user action | *(empty)* | IAM policy ARN |
| `FORENSICS_BACKUP_S3_URI` | S3 forensics dump | *(empty)* | e.g. `s3://forensics/` |
| `S3_SENSITIVE_BUCKETS` | S3 protect action | *(empty)* | Comma-separated bucket names |

### Detection tuning

| Name | Required for | Default | Description |
|---|---|---|---|
| `CLOUDTRAIL_LOOKBACK_MAX_RESULTS` | Ingest | `50` | Max events per lookup |
| `OFF_HOURS_START_HOUR` | Detection | `0` | Off-hours window start (UTC) |
| `OFF_HOURS_END_HOUR` | Detection | `8` | Off-hours window end (UTC) |

### Safety

| Name | Required for | Default | Description |
|---|---|---|---|
| `DRY_RUN` | Kill switch | `true` | If true, log-only; never execute AWS calls |
| `AUTO_MITIGATION_ENABLED` | Master switch | `false` | Must be true for Stage 4 to act |
| `TRIAGE_CONFIDENCE_THRESHOLD` | Approval gate | `0.8` | Below this, destructive actions need approval |

### Logging

| Name | Required for | Default | Description |
|---|---|---|---|
| `LOG_LEVEL` | Verbosity | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `LOG_FORMAT` | Format | `text` | `text` or `json` (Splunk/ELK ready) |

### Offline / testing

| Name | Required for | Default | Description |
|---|---|---|---|
| `MOCK_MODE` | Offline runs | `false` | Stub out AWS/Redis/LLM |

### MITRE ATT&CK

| Name | Required for | Default | Description |
|---|---|---|---|
| `MITRE_STIX_URL` | STIX loader | *(public MITRE URL)* | Enterprise-attack bundle URL |
| `MITRE_STIX_CACHE_PATH` | STIX loader | `.cache/mitre-enterprise-attack.json` | Cache path |

### Threat feeds

| Name | Required for | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | IP reputation | *(empty)* | AbuseIPDB key |
| `GREYNOISE_API_KEY` | IP reputation | *(empty)* | GreyNoise Community key |
| `THREAT_FEED_CACHE_TTL_SECONDS` | Caching | `3600` | In-process cache TTL |

### PagerDuty

| Name | Required for | Default | Description |
|---|---|---|---|
| `PAGERDUTY_ROUTING_KEY` | On-call paging | *(empty)* | Events API v2 routing key |

### Splunk

| Name | Required for | Default | Description |
|---|---|---|---|
| `SPLUNK_HEC_URL` | Splunk push | *(empty)* | HEC endpoint URL |
| `SPLUNK_HEC_TOKEN` | Splunk push | *(empty)* | HEC token |
| `SPLUNK_INDEX` | Splunk push | *(empty, → `main`)* | Target index |
| `SPLUNK_VERIFY_TLS` | Splunk push | `true` | Verify HEC TLS cert |

### TheHive

| Name | Required for | Default | Description |
|---|---|---|---|
| `THEHIVE_URL` | Case management | *(empty)* | TheHive base URL |
| `THEHIVE_API_KEY` | Case management | *(empty)* | Personal API key |
| `THEHIVE_ORGANISATION` | Case management | *(empty)* | Organisation header |
| `THEHIVE_TLP` | Case management | `2` | 0=WHITE .. 3=RED |
| `THEHIVE_PAP` | Case management | `2` | 0-3 |
| `THEHIVE_VERIFY_TLS` | Case management | `true` | Verify TheHive TLS cert |

## Running

### Offline / demo mode

Runs the entire pipeline against canned CloudTrail + LLM fixtures — no
AWS, Redis, or Anthropic access required.

```bash
MOCK_MODE=true python main.py
# or
python run_mock.py
```

Expected: Stage 0 → 1 → 2 → 3 → approval gate (auto-granted) → Stage 4 →
forensics + learning sidecars; final workflow JSON printed to stdout.

### Production

```bash
pip install -e ".[dev]"
cp .env.example .env
# fill in ANTHROPIC_API_KEY, MODEL_*, AWS config, etc.
python main.py
```

The default entry point polls CloudTrail every 30s and triggers a workflow
whenever the queue reaches 5 events.

### Tests

```bash
pytest                     # everything (~2.5s, all offline)
pytest tests/unit          # unit tests only
pytest tests/integrations  # per-integration tests
pytest -k splunk           # by keyword
```

### Dashboards

- **Splunk**: import `docs/splunk_dashboard.xml`.
- **TheHive**: browse to `THEHIVE_URL` after setting `THEHIVE_URL` +
  `THEHIVE_API_KEY`. See `docs/thehive_setup.md` for a working
  docker-compose.

## Safety

Three critical flags — read the defaults carefully.

| Flag | Default | Effect |
|---|---|---|
| `DRY_RUN` | `true` | When true, AWS mitigation is logged only, never executed |
| `AUTO_MITIGATION_ENABLED` | `false` | Master switch; must be true for Stage 4 to make any AWS write |
| `TRIAGE_CONFIDENCE_THRESHOLD` | `0.8` | Below this, destructive actions require human approval via the gate |

Ship in production only after reviewing these values against your risk
tolerance.

## Extending

- **New pipeline stage**: add a folder under `agents/`, expose
  `create_agent()`, and slot it into `agents/orchestrator.py` between the
  existing stages. Wrap it with `get_step_logger("stageN")` for uniform
  logs.
- **New integration**: drop a module into `integrations/`, follow the
  pattern of returning early with `skipped=true reason=...` when config
  is empty (all integrations must be graceful no-ops when unconfigured).
  Add a settings field to `config/settings.py` and mirror it into
  `.env.example`.
- **New mitigation action**: add the tool under `agents/response/tools/`,
  register it in `agents/response/agent.py`, and — if destructive — add
  it to the `DESTRUCTIVE` set in `agents/response/approval_gate.py`.
- **Prompt tweaks**: edit `agents/*/prompts/system.md` and `user.md`
  directly. They are plain markdown, loaded at agent init — no code
  change needed.

