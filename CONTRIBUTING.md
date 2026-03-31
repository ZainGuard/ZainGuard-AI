# Contributing to ZainGuard AI

Thank you for your interest in contributing. ZainGuard AI is an open-source framework for AI-assisted security operations — built to be read, understood, and extended by the community.

---

## What Matters Most

**New connectors are the highest-impact contribution.**

The framework is only as useful as the data it can reach. Every new connector extends what the Investigator Agent can see:
- Layer 1 connectors (Snowflake, Okta, CloudTrail, Wiz, CrowdStrike) give access to raw security telemetry
- Layer 2 connectors (Glean, GitHub, Confluence, Slack) give organizational context
- Layer 3 connectors (VirusTotal, AbuseIPDB, Shodan, MISP) provide threat intelligence enrichment

If your organization uses a security tool that isn't yet supported, that's the connector to write.

---

## How to Add a Connector

1. **Create the connector file** at `zainguard_ai_soc/connectors/<name>.py`
2. **Implement the `BaseConnector` interface** (`zainguard_ai_soc/connectors/base.py`):
   - `query(params: dict) -> QueryResult` — required for all connectors
   - `health_check() -> bool` — required for all connectors
   - `get_schema() -> dict` — required for Layer 1 (data lake) connectors only
3. **Add a usage example** in `examples/<name>_connector.py`
4. **For Layer 1 connectors**, add a schema YAML in `schema_examples/` — the Investigator Agent uses this to construct valid queries without hallucinating column names
5. **Write tests** against mock data in `tests/` — no live credentials required

Keep PRs focused: **one connector per PR**.

---

## Connector Template

```python
# zainguard_ai_soc/connectors/myconnector.py
from zainguard_ai_soc.connectors.base import BaseConnector
from zainguard_ai_soc.models import QueryResult

class MyConnector(BaseConnector):
    layer = "layer1"   # or "layer2" / "layer3"
    name = "myconnector"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def query(self, params: dict) -> QueryResult:
        # execute query, return QueryResult
        # if nothing found: return QueryResult(..., found=False)
        # if error: return QueryResult(..., found=False, error=str(e))
        ...

    def health_check(self) -> bool:
        # return True if the API is reachable, False otherwise
        ...
```

---

## Development Setup

```bash
git clone https://github.com/sadewale4/zainguard-ai
cd zainguard-ai
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp env.example .env   # fill in your API keys
```

Run the example investigation:
```bash
export ANTHROPIC_API_KEY=...
python examples/reverse_shell_alert.py
```

Run tests:
```bash
pytest
```

---

## Other Ways to Contribute

- **Schema files** — if you use a data lake (Snowflake, BigQuery, Elasticsearch), add a real schema YAML for your log sources
- **Example investigations** — add `examples/` scripts for different alert types (phishing, privilege escalation, data exfiltration, etc.)
- **Bug fixes** — open an issue first so we can align on approach
- **Documentation** — keep CLAUDE.md accurate as the framework evolves

---

## Guidelines

- No live credentials in tests — mock the HTTP layer
- Keep PRs focused and small
- Write clear commit messages (`feat:`, `fix:`, `docs:`)
- Never hardcode secrets — use environment variables
- Report security issues privately to security@zainguard.com

---

## Questions?

Open a GitHub Discussion or file an issue. We're happy to help scope a contribution before you start building.
