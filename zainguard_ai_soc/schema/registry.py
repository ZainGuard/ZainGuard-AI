"""
Schema Registry — Provides the Investigator Agent with table and field
mappings for data lake connectors.

Without accurate schema context, the Investigator will hallucinate
column names and produce invalid queries. This registry loads schema
definitions from YAML files and makes them available to agents.

Schema files live in zainguard/schema/examples/ and schema_examples/.
"""
from __future__ import annotations

import yaml
from pathlib import Path
from typing import Any


class SchemaRegistry:
    """
    Loads and serves schema definitions for data lake connectors.

    Usage:
        registry = SchemaRegistry.from_file("schema_examples/snowflake_security.yaml")
        investigator = InvestigatorAgent(connectors=[...], schema_registry=registry)
    """

    def __init__(self, schemas: dict[str, Any]) -> None:
        self._schemas = schemas

    @classmethod
    def from_file(cls, path: str | Path) -> "SchemaRegistry":
        """Load a schema registry from a YAML file."""
        with open(path) as f:
            schemas = yaml.safe_load(f)
        return cls(schemas)

    @classmethod
    def from_dict(cls, schemas: dict[str, Any]) -> "SchemaRegistry":
        """Create a schema registry from a Python dict (useful for tests)."""
        return cls(schemas)

    def get_all(self) -> dict[str, Any]:
        """Return all schemas — passed as context to the Investigator Agent."""
        return self._schemas

    def get_table_schema(self, table_name: str) -> dict[str, Any] | None:
        """Return the schema for a specific table."""
        tables = self._schemas.get("tables", {})
        return tables.get(table_name)

    def list_tables(self) -> list[str]:
        """List all available table names."""
        return list(self._schemas.get("tables", {}).keys())
