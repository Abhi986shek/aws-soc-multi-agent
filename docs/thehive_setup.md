# TheHive Setup

## Overview

TheHive is the case-management workbench for SOC analysts in this pipeline.
Every incident the SOC Agent handles is mirrored into TheHive:

- **PRIORITY tickets** open a case (`InProgress`) with tasks for the actions
  the analyst still needs to complete and observables (source IPs, principal
  ARNs) for pivoting.
- **RESOLVED tickets** open a pre-closed case (`Resolved`) so there is an
  audit trail even for events the agent handled fully automatically.

Analysts triage, comment, and close cases in TheHive using the standard
`TruePositive` / `FalsePositive` / `Indeterminate` / `Duplicate` / `Other`
resolution values. Every 24 hours the Learning sidecar reads back closed
cases and adjusts detection-pattern confidence accordingly.

## Quick start with docker-compose

TheHive 5.x needs Cassandra (data) and Elasticsearch (search).

```yaml
# docker-compose.yml
version: "3.8"

services:
  cassandra:
    image: cassandra:4
    environment:
      - CASSANDRA_CLUSTER_NAME=thp
    volumes:
      - cassandra-data:/var/lib/cassandra

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.24
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - es-data:/usr/share/elasticsearch/data

  thehive:
    image: strangebee/thehive:5.2
    depends_on: [cassandra, elasticsearch]
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms1g -Xmx1g
    command:
      - --no-config
      - --no-config-secret

volumes:
  cassandra-data:
  es-data:
```

```bash
docker compose up -d
# TheHive UI: http://localhost:9000
```

## First-time setup

1. Open http://localhost:9000 and log in with the default admin credentials
   printed by TheHive on first launch.
2. Create an **organisation** (e.g. `soc`).
3. Create a **user** in that organisation with the `analyst` profile.
4. Log in as that user, open the profile menu, and **create an API key**.
5. Paste the values into `.env`:

```
THEHIVE_URL=http://localhost:9000
THEHIVE_API_KEY=<paste>
THEHIVE_ORGANISATION=soc
THEHIVE_TLP=2
THEHIVE_PAP=2
THEHIVE_VERIFY_TLS=true
```

Leaving any of these blank disables the integration silently — the pipeline
continues to write DynamoDB / Splunk / SES / PagerDuty exactly as before.

## Seeing agent-created cases

In the TheHive UI, filter cases by the `soc_agent` tag. Each case also
carries:

- `trace:<trace_id>` — the pipeline trace id, joins the SOC-Agent logs.
- `aws_region:<region>` — the AWS region of the incident.
- `mitre:T####` — one tag per MITRE technique the enrichment stage matched.

Custom fields expose `threat_score` and `attack_hypothesis` for filtering.

## Learning loop

Nightly, the Learning sidecar calls
`integrations.thehive.list_recently_closed_cases(since_hours=24)`. For each
closed case it looks at `resolutionStatus`:

- `TruePositive`  → tags on the case are marked as **upgraded** (increased
  confidence in the corresponding detection pattern / MITRE technique).
- `FalsePositive` → same tags are marked as **downgraded**.

The result becomes an entry in the sidecar's `updates_applied` list and is
persisted to `config.learning_updates` for downstream rule-update PRs.
