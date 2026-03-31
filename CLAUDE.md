# ZainGuard AI — Open Source AI Security Operations Framework

## Vision

An open-source framework for implementing AI-assisted security operations. The goal is to lower the barrier for security teams to leverage AI in SOC workflows — from alert triage through full investigation — without bloated infrastructure or vendor lock-in.

Simplicity is the governing principle: every piece of code should be easy to read, understand, and contribute to.

---

## The Problem This Solves

Modern SOC teams face an alert fatigue problem. Most alerts fire for benign reasons — developers doing expected things, normal business changes, or known activity. Analysts spend significant time:

1. Querying multiple log sources to piece together context
2. Reaching out to users/teams to confirm whether activity was expected
3. Searching internal knowledge bases to rule out known-good changes
4. Manually enriching IOCs against external threat intelligence

AI agents with the right data access can dramatically accelerate this work — not to replace human judgment, but to surface evidence faster and more thoroughly, so humans can decide with confidence.

---

## Framework Philosophy

- **Evidence-first**: Agents surface evidence, not conclusions. Humans decide.
- **Human in the loop**: All outputs are reviewed by a human. AI accelerates, not replaces.
- **Simple by default**: Fewer files, less abstraction, easier to follow the code.
- **Connector-first**: The framework is only as useful as the data it can reach. Connectors are first-class citizens.
- **Open and composable**: Every agent, tool, and connector should be independently usable.

---

## The Three Data Layers

For an AI security investigation agent to be effective, it needs access to three categories of data:

### Layer 1: Security Telemetry (The Data Lake)

The primary source of evidence — raw security logs from your environment.

Examples:
- **Snowflake** (or other data lakes): centralized security logs
- **AWS CloudTrail**: API and management activity
- **Okta**: Authentication and identity events
- **Wiz Runtime**: Cloud workload and container activity
- **CrowdStrike / EDR**: Endpoint telemetry
- **Network logs**: VPC flow logs, proxy logs, DNS

The Investigator agent must have access to a **schema registry** — a mapping of log source type → table name → field schema — to construct accurate queries without hallucinating column names. This is a hard requirement for reliable investigations.

### Layer 2: Organizational Knowledge Base

Context that helps determine whether activity is malicious or expected.

Examples:
- **Glean**: Unified enterprise search across connected sources (ideal if available — already connects Slack, GitHub, Drive, etc.)
- **Slack / Teams**: Conversation context, change announcements
- **GitHub**: Code changes, PR activity, deploy events
- **Google Drive / Confluence / SharePoint**: Runbooks, architecture docs, change records
- **Internal ticketing**: Approved change requests, maintenance windows

The Investigator agent queries this layer to answer: "Was this activity expected? Does any internal context explain it?"

### Layer 3: External Threat Intelligence

Enrichment to assess whether observed activity is associated with known threats.

Examples:
- **VirusTotal**: IP, domain, hash reputation
- **AbuseIPDB**: IP abuse reports
- **Shodan**: Open ports, exposed services
- **MISP / OpenCTI**: Community threat feeds
- **Any TI MCP server**: Model Context Protocol integration for TI lookups

The Investigator agent uses this layer to enrich IOCs and raise/lower severity based on community intelligence.

---

## Agent Architecture

Given a single alert or array of alert events, three agents collaborate to produce a documented investigation.

```
[Alert Event(s)]
       │
       ▼
┌─────────────┐
│   Director  │  ← Triage + generate 3 investigative questions
└──────┬──────┘
       │  questions
       ▼
┌──────────────┐
│ Investigator │  ← Query Layer 1 + Layer 2 + Layer 3, document evidence
└──────┬───────┘
       │  evidence report
       ▼
┌──────────────┐
│   Reviewer   │  ← Validate, finalize case, recommend actions
└──────┬───────┘
       │  case report
       ▼
[Human Analyst]
```

### Director Agent

**Role**: First-level triage and investigation framing

**Inputs**: Raw alert event(s)

**Responsibilities**:
- Understand what the alert is about
- Identify the key actors, assets, and actions involved
- Generate exactly **3 primary investigative questions** that:
  - Are directly answerable using available evidence
  - Push the investigation toward a clear resolution
  - Cover different angles (identity, system, network — as applicable)

**Output**: Structured triage summary + 3 investigative questions

**Example** (reverse shell alert on EC2):
1. Was there any successful authentication to this EC2 instance from an unusual source prior to the command execution?
2. Is the destination IP address associated with known malicious infrastructure or has it been observed in threat intelligence feeds?
3. Did any recent code deployments or change requests authorize network connectivity changes on this instance?

---

### Investigator Agent

**Role**: Evidence gathering and documentation

**Inputs**: Alert event(s) + Director's 3 investigative questions

**Responsibilities**:
- For each investigative question, construct and execute appropriate queries against available data sources
- Layer 1 queries: data lake / SIEM for security logs
- Layer 2 queries: knowledge base for organizational context
- Layer 3 queries: threat intelligence enrichment for IOCs
- Document all findings — both what was found AND what was not found (absence of evidence is also evidence)
- Never hallucinate query results; if a query fails or returns nothing, document that explicitly

**Critical requirement**: The Investigator must have access to a **schema registry** — a structured mapping of available tables and their schemas — to construct valid queries. Without this, query accuracy degrades significantly.

**Output**: Structured evidence report per question + raw query results + analyst notes

---

### Reviewer Agent

**Role**: Quality assurance, case finalization, and human handoff

**Inputs**: Director triage summary + Investigator evidence report

**Responsibilities**:
- Validate that the investigative questions were adequately answered
- Identify any gaps or additional questions raised by the evidence
- Assess the weight of evidence: malicious, benign, or inconclusive?
- Produce a clean, concise case summary suitable for human review
- Generate short-form recommendations for the human analyst (next steps, escalation paths)
- Flag the case for human review with appropriate severity

**Output**: Final case report + severity assessment + recommended actions + human review request

---

## Human in the Loop

This is a core, non-negotiable principle.

The framework is designed to **accelerate** human decision-making, not replace it. The Reviewer Agent's final output is always handed to a human analyst for review before any response actions are taken.

AI agents:
- Surface evidence
- Propose interpretations
- Suggest actions

Humans:
- Validate the evidence
- Make the final call
- Approve any response actions

---

## Foundational Requirements

For this framework to function effectively, the following must be in place:

1. **Centralized Security Data Lake**: All relevant security logs must be queryable from a single interface (Snowflake, BigQuery, Elasticsearch, etc.)

2. **Schema Registry**: A mapping file (JSON or YAML) documenting available tables, their log source types, and key field schemas — provided to the Investigator Agent as context. See `schema_examples/` for reference formats.

3. **Knowledge Base Access**: At minimum, one queryable knowledge source (Glean API, GitHub search, Confluence API, etc.)

4. **Threat Intelligence Source**: At minimum, one TI API (VirusTotal free tier is sufficient to start)

5. **API Keys / Credentials**: Stored in environment variables, never hardcoded. See `.env.example`.

---

## Interface Approach

The framework supports multiple entry points to serve different users:

| Interface | Primary Audience | Use Case |
|-----------|-----------------|----------|
| **Python SDK** | Security engineers, developers | Import and integrate into any Python project |
| **CLI** | SOC analysts, DevOps | Run investigations from terminal |
| **REST API** | SOAR tools, integrations | Integrate with ticketing, alerting, or custom UIs |
| **Web UI** (optional) | Non-technical stakeholders | Case review, approval workflow |

Open-source contributors should focus on **SDK + CLI**. The REST API powers ZainGuard app integration and enterprise deployments.

---

## Connector Development Guide

Each connector follows a standard interface defined in `zainguard_ai_soc/connectors/base.py`:

```python
class BaseConnector:
    def query(self, params: dict) -> QueryResult: ...
    def health_check(self) -> bool: ...
    def get_schema(self) -> dict: ...  # data lake connectors only
```

Connectors are stateless and independently testable. When contributing a new connector:
1. Implement the base interface
2. Add a working usage example in `examples/`
3. For data lake connectors, include a schema definition in `schema_examples/`
4. Write tests against mock data (no live credentials required)

---

## Repository Structure

```
zainguard-ai/
├── zainguard_ai_soc/                        # Core Python package
│   ├── agents/
│   │   ├── director.py               # Director Agent
│   │   ├── investigator.py           # Investigator Agent
│   │   └── reviewer.py               # Reviewer Agent
│   ├── connectors/                   # Data source connectors
│   │   ├── base.py                   # Base connector interface
│   │   ├── snowflake.py              # Snowflake (Layer 1 - data lake)
│   │   ├── okta.py                   # Okta (Layer 1 - identity)
│   │   ├── cloudtrail.py             # AWS CloudTrail (Layer 1)
│   │   ├── wiz.py                    # Wiz runtime (Layer 1)
│   │   ├── glean.py                  # Glean (Layer 2 - knowledge base)
│   │   ├── github.py                 # GitHub (Layer 2 - code/changes)
│   │   ├── virustotal.py             # VirusTotal (Layer 3 - TI)
│   │   ├── abuseipdb.py              # AbuseIPDB (Layer 3 - TI)
│   │   ├── shodan.py                 # Shodan (Layer 3 - TI)
│   │   └── jira.py                   # Jira (case management)
│   ├── schema/
│   │   ├── registry.py               # Schema registry loader
│   │   └── examples/                 # Example schema YAML files
│   ├── pipeline.py                   # Main pipeline: Director → Investigator → Reviewer
│   └── models.py                     # Shared data models
├── cli/
│   └── main.py                       # CLI entry point
├── api/
│   └── main.py                       # REST API (FastAPI)
├── examples/
│   ├── reverse_shell_alert.py        # Example end-to-end investigation
│   └── phishing_alert.py             # Example end-to-end investigation
├── schema_examples/
│   └── snowflake_security.yaml       # Example schema registry file
├── tests/
├── src/                              # Legacy v1 code (preserved for reference)
├── CLAUDE.md                         # This file — project vision and architecture
├── README.md
└── pyproject.toml
```

---

## What Changed from v1

### Preserved
- LLM provider abstraction (OpenAI, Anthropic, Ollama)
- VirusTotal, AbuseIPDB, Shodan integrations (migrated to connector interface)
- Jira integration
- Docker support
- FastAPI REST API pattern

### Replaced / Removed
- 4-agent model (Triage, Email Investigation, Incident Response, Threat Intel) → 3-agent pipeline
- LangChain → direct Anthropic SDK (simpler, fewer dependencies)
- ChromaDB → knowledge base queried live via connectors (YAGNI)
- Complex AgentManager orchestration → simple `pipeline.py`

---

## Contributing

See `CONTRIBUTING.md`. Key priorities for contributors:
- **New connectors** are the most impactful contributions
- Each connector needs a working example and (for data lake connectors) a schema definition
- Test against mock data — no live credentials required in tests
- Keep PRs focused: one connector or one change at a time
