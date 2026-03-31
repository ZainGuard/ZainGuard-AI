"""
ZainGuard AI Investigation Pipeline.

This is the main entry point for running security investigations.
Given one or more alert events, the pipeline runs:

    Director → Investigator → Reviewer → CaseReport (for human review)

Usage:
    from zainguard_ai_soc.pipeline import investigate
    from zainguard_ai_soc.models import Alert, Severity
    from zainguard_ai_soc.connectors.virustotal import VirusTotalConnector

    report = investigate(
        alert=Alert(id="1", title="Reverse shell", source="wiz", severity=Severity.HIGH, raw={...}),
        connectors=[VirusTotalConnector(api_key="...")],
        schema_registry=SchemaRegistry.from_file("schema_examples/snowflake_security.yaml"),
    )
    print(report.executive_summary)
"""
from __future__ import annotations

from zainguard_ai_soc.agents.director import DirectorAgent
from zainguard_ai_soc.agents.investigator import InvestigatorAgent
from zainguard_ai_soc.agents.reviewer import ReviewerAgent
from zainguard_ai_soc.connectors.base import BaseConnector
from zainguard_ai_soc.models import Alert, CaseReport
from zainguard_ai_soc.schema.registry import SchemaRegistry


def investigate(
    alert: Alert,
    connectors: list[BaseConnector] | None = None,
    schema_registry: SchemaRegistry | None = None,
    model: str = "claude-opus-4-6",
) -> CaseReport:
    """
    Run a full investigation on a security alert.

    Args:
        alert: The security alert to investigate.
        connectors: Data source connectors available to the Investigator.
                    Include Layer 1 (security logs), Layer 2 (knowledge base),
                    and Layer 3 (threat intelligence) connectors as needed.
        schema_registry: Schema definitions for data lake connectors.
                         Required if any Layer 1 connectors are provided.
        model: Model to use for all agents. Provider is auto-detected from
               the model name. Examples:
               - "claude-opus-4-6" (Anthropic, default — recommended)
               - "claude-sonnet-4-6" (Anthropic, faster/cheaper)
               - "gpt-4o" (OpenAI)
               - "ollama:llama3.2" (local Ollama)

    Returns:
        CaseReport ready for human analyst review.
        Always has requires_human_review=True.
    """
    connectors = connectors or []

    director = DirectorAgent(model=model)
    investigator = InvestigatorAgent(connectors=connectors, schema_registry=schema_registry, model=model)
    reviewer = ReviewerAgent(model=model)

    director_output = director.run(alert)
    investigator_output = investigator.run(alert, director_output)
    case_report = reviewer.run(alert, director_output, investigator_output)

    return case_report


def investigate_batch(
    alerts: list[Alert],
    connectors: list[BaseConnector] | None = None,
    schema_registry: SchemaRegistry | None = None,
    model: str = "claude-opus-4-6",
) -> list[CaseReport]:
    """
    Run investigations on a batch of alerts, one at a time.

    Args:
        alerts: List of security alerts.
        connectors: Data source connectors (shared across all investigations).
        schema_registry: Schema definitions for data lake connectors.
        model: Model to use for all agents (see investigate() for options).

    Returns:
        List of CaseReports, one per alert, in the same order.
    """
    return [
        investigate(alert, connectors=connectors, schema_registry=schema_registry, model=model)
        for alert in alerts
    ]
