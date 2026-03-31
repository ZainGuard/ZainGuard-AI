"""
Base connector interface for ZainGuard AI data source connectors.

All connectors — whether they query a data lake, knowledge base, or
threat intelligence API — implement this interface. This keeps them
stateless, independently testable, and easy to swap out.

Data Layer Classification:
  Layer 1 — Security Telemetry: Snowflake, CloudTrail, Okta, Wiz, CrowdStrike
  Layer 2 — Organizational Knowledge: Glean, GitHub, Confluence, Slack
  Layer 3 — External Threat Intelligence: VirusTotal, AbuseIPDB, Shodan, MISP
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from zainguard_ai_soc.models import QueryResult


class BaseConnector(ABC):
    """
    Abstract base class for all ZainGuard connectors.

    Every connector must implement `query()` and `health_check()`.
    Data lake connectors (Layer 1) should also implement `get_schema()`.
    """

    # Subclasses declare which data layer they belong to
    layer: str = ""  # "layer1", "layer2", or "layer3"
    name: str = ""   # human-readable name, e.g. "virustotal"

    @abstractmethod
    def query(self, params: dict[str, Any]) -> QueryResult:
        """
        Execute a query against this data source.

        Args:
            params: Query parameters. Shape varies by connector —
                    see each connector's docstring for expected keys.

        Returns:
            QueryResult with findings or explicit absence of data.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """
        Verify this connector can reach its data source.

        Returns True if reachable, False otherwise. Should not raise.
        """

    def get_schema(self) -> dict[str, Any]:
        """
        Return the schema for this data source (Layer 1 connectors only).

        Returns a dict mapping table names to their field schemas.
        Used by the Investigator Agent to construct valid queries.

        Layer 2 and Layer 3 connectors do not need to implement this.
        """
        return {}
