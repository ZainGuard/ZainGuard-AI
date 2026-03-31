"""
Investigator Agent — Evidence gathering and documentation.

Responsibilities:
- Take the Director's 3 investigative questions and answer them
- Query Layer 1 (security telemetry), Layer 2 (knowledge base), and Layer 3 (TI)
  as appropriate for each question
- Document all findings including explicit absence of evidence
- Produce a structured evidence report per question

Critical constraint: This agent MUST have a schema registry loaded to
construct valid data lake queries. Without it, query accuracy degrades.

The Investigator does not make verdicts — it surfaces evidence and
lets the Reviewer draw conclusions.
"""
from __future__ import annotations

import json
from typing import Any

from zainguard_ai_soc.connectors.base import BaseConnector
from zainguard_ai_soc.llm import LLMClient
from zainguard_ai_soc.models import (
    Alert,
    DirectorOutput,
    EvidenceItem,
    InvestigatorOutput,
    QueryResult,
)
from zainguard_ai_soc.schema.registry import SchemaRegistry

INVESTIGATOR_SYSTEM_PROMPT = """You are the Investigator Agent in a security operations investigation pipeline.

Your job is to answer investigative questions by querying available data sources.
For each question you receive, determine:
1. Which data layer(s) to query (layer1=security logs, layer2=knowledge base, layer3=threat intel)
2. What specific query to run against each connector
3. How to interpret the results

Rules:
- Always document what you searched for, even if you found nothing
- Absence of evidence is meaningful — state it explicitly ("no results found")
- Never fabricate query results — if a query fails, say so
- Be specific about what connector and query produced each finding
- Keep analyst notes factual and evidence-based

When asked to plan queries for a question, output JSON only:
{
  "queries": [
    {
      "connector": "<connector_name>",
      "layer": "layer1|layer2|layer3",
      "query": "<the query string or parameters as JSON>",
      "rationale": "<why this query answers the question>"
    }
  ]
}
"""


class InvestigatorAgent:
    """
    Answers investigative questions by querying available data sources.

    Connectors are passed in at initialization — this makes it easy to
    configure which data sources are available for a given deployment.
    """

    def __init__(
        self,
        connectors: list[BaseConnector],
        schema_registry: SchemaRegistry | None = None,
        model: str = "claude-opus-4-6",
    ) -> None:
        self.llm = LLMClient(model=model)
        self.connectors: dict[str, BaseConnector] = {c.name: c for c in connectors}
        self.schema_registry = schema_registry

    def run(self, alert: Alert, director_output: DirectorOutput) -> InvestigatorOutput:
        """
        Answer the Director's investigative questions using available connectors.

        Args:
            alert: The original security alert.
            director_output: Triage summary and 3 questions from the Director.

        Returns:
            InvestigatorOutput with structured evidence for each question.
        """
        evidence_items: list[EvidenceItem] = []

        for question in director_output.questions:
            evidence = self._investigate_question(alert, director_output, question.question, question.number)
            evidence_items.append(evidence)

        # Enrich all IOCs from the Director's output
        ioc_enrichments = self._enrich_iocs(director_output.iocs)

        return InvestigatorOutput(
            alert_id=alert.id,
            evidence=evidence_items,
            raw_ioc_enrichments=ioc_enrichments,
        )

    def _investigate_question(
        self,
        alert: Alert,
        director_output: DirectorOutput,
        question: str,
        question_number: int,
    ) -> EvidenceItem:
        """Plan and execute queries to answer a single investigative question."""

        schema_context = ""
        if self.schema_registry:
            schema_context = f"\nAvailable schema:\n{json.dumps(self.schema_registry.get_all(), indent=2)}\n"

        connector_context = f"Available connectors: {', '.join(self.connectors.keys())}"

        prompt = f"""Alert: {alert.title}
Triage summary: {director_output.triage_summary}
Key actors: {', '.join(director_output.key_actors)}
Key assets: {', '.join(director_output.key_assets)}
IOCs: {', '.join(director_output.iocs)}
{schema_context}
{connector_context}

Investigative question #{question_number}: {question}

Plan queries to answer this question."""

        plan = json.loads(self.llm.complete_json(system=INVESTIGATOR_SYSTEM_PROMPT, user=prompt, max_tokens=1024))
        query_results = self._execute_query_plan(plan["queries"])
        analyst_notes = self._synthesize_findings(question, query_results)

        supports_malicious = None
        if any(r.found for r in query_results):
            supports_malicious = self._assess_malicious_likelihood(question, query_results)

        return EvidenceItem(
            question_number=question_number,
            question=question,
            query_results=query_results,
            analyst_notes=analyst_notes,
            supports_malicious=supports_malicious,
        )

    def _execute_query_plan(self, queries: list[dict[str, Any]]) -> list[QueryResult]:
        """Execute each planned query against the appropriate connector."""
        results: list[QueryResult] = []

        for q in queries:
            connector_name = q["connector"]
            raw_query = q["query"]
            query_str = json.dumps(raw_query) if isinstance(raw_query, dict) else str(raw_query)
            if connector_name not in self.connectors:
                results.append(QueryResult(
                    connector=connector_name,
                    layer=q.get("layer", "unknown"),
                    query=query_str,
                    data=[],
                    found=False,
                    error=f"Connector '{connector_name}' not configured",
                ))
                continue

            connector = self.connectors[connector_name]
            try:
                params = raw_query if isinstance(raw_query, dict) else (
                    json.loads(raw_query) if raw_query.startswith("{") else {"query": raw_query}
                )
                result = connector.query(params)
                results.append(result)
            except Exception as e:
                results.append(QueryResult(
                    connector=connector_name,
                    layer=q.get("layer", "unknown"),
                    query=query_str,
                    data=[],
                    found=False,
                    error=str(e),
                ))

        return results

    def _enrich_iocs(self, iocs: list[str]) -> list[QueryResult]:
        """Enrich all IOCs from Layer 3 (TI) connectors."""
        ti_connectors = [c for c in self.connectors.values() if c.layer == "layer3"]
        results: list[QueryResult] = []

        for ioc in iocs:
            for connector in ti_connectors:
                try:
                    result = connector.query({"ioc": ioc})
                    results.append(result)
                except Exception as e:
                    results.append(QueryResult(
                        connector=connector.name,
                        layer="layer3",
                        query=ioc,
                        data=[],
                        found=False,
                        error=str(e),
                    ))

        return results

    def _synthesize_findings(self, question: str, results: list[QueryResult]) -> str:
        """Ask the LLM to write analyst notes summarizing the query results."""
        results_text = json.dumps(
            [{"connector": r.connector, "found": r.found, "data": r.data, "error": r.error} for r in results],
            indent=2,
            default=str,
        )

        prompt = f"""Question: {question}

Query results:
{results_text}

Write concise analyst notes summarizing what the evidence shows (or doesn't show).
Be factual. If no results were found, say so explicitly. Do not make assumptions beyond the data."""

        return self.llm.complete(system="You are a factual security analyst. Summarize evidence concisely.", user=prompt, max_tokens=512)

    def _assess_malicious_likelihood(self, question: str, results: list[QueryResult]) -> bool | None:
        """Return True if results suggest malicious activity, False if benign, None if inconclusive."""
        results_text = json.dumps(
            [{"connector": r.connector, "found": r.found, "data": r.data} for r in results],
            indent=2,
            default=str,
        )

        prompt = f"""Question: {question}

Evidence:
{results_text}

Does this evidence support malicious activity? Answer with exactly one word: "yes", "no", or "inconclusive"."""

        answer = self.llm.complete(system="Answer with exactly one word: yes, no, or inconclusive.", user=prompt, max_tokens=10).strip().lower()
        if answer == "yes":
            return True
        if answer == "no":
            return False
        return None
