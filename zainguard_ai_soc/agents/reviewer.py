"""
Reviewer Agent — Case finalization and human handoff.

Responsibilities:
- Validate the Director's questions were adequately answered
- Identify evidence gaps and unanswered questions
- Assess the overall weight of evidence (malicious / benign / inconclusive)
- Produce a clean case report for the human analyst
- Generate short, actionable recommendations
- Always flag for human review — this is non-negotiable

The Reviewer does not query data sources. It works from the outputs
of the Director and Investigator to produce the final case report.
"""
from __future__ import annotations

import json

from zainguard_ai_soc.llm import LLMClient
from zainguard_ai_soc.models import (
    Alert,
    CaseReport,
    DirectorOutput,
    InvestigatorOutput,
    Severity,
    Verdict,
)

REVIEWER_SYSTEM_PROMPT = """You are the Reviewer Agent in a security operations investigation pipeline.

Your job is to review the work done by the Director and Investigator agents and produce
a final case report for a human security analyst.

Rules:
1. Assess the overall weight of evidence fairly — do not over-inflate or minimize
2. Call out evidence gaps clearly — what was not answered?
3. Recommendations must be short and actionable (max 5 bullet points)
4. Always set requires_human_review to true — AI does not make final calls
5. Confidence should reflect how much evidence was found: high/medium/low

Output JSON only. No prose before or after. Schema:
{
  "severity": "critical|high|medium|low|informational|inconclusive",
  "verdict": "malicious|benign|inconclusive",
  "confidence": "high|medium|low",
  "executive_summary": "<2-3 sentences for non-technical stakeholders>",
  "findings_summary": "<detailed findings referencing specific evidence>",
  "evidence_gaps": ["<unanswered question or missing data>"],
  "recommendations": ["<action 1>", "<action 2>"]
}
"""


class ReviewerAgent:
    """
    Reviews the investigation and produces the final case report.
    """

    def __init__(self, model: str = "claude-opus-4-6") -> None:
        self.llm = LLMClient(model=model)

    def run(
        self,
        alert: Alert,
        director_output: DirectorOutput,
        investigator_output: InvestigatorOutput,
    ) -> CaseReport:
        """
        Review all investigation outputs and produce the final case report.

        Args:
            alert: The original security alert.
            director_output: Triage summary and questions from the Director.
            investigator_output: Evidence report from the Investigator.

        Returns:
            CaseReport ready for human analyst review.
        """
        evidence_summary = self._format_evidence_for_review(director_output, investigator_output)

        prompt = f"""Security Alert: {alert.title}
Source: {alert.source}
Original Severity: {alert.severity.value}

Director Triage:
{director_output.triage_summary}

Key Actors: {', '.join(director_output.key_actors)}
Key Assets: {', '.join(director_output.key_assets)}
IOCs: {', '.join(director_output.iocs)}

Investigation Evidence:
{evidence_summary}

Review the investigation and produce the final case report."""

        raw = json.loads(self.llm.complete_json(system=REVIEWER_SYSTEM_PROMPT, user=prompt, max_tokens=2048))

        return CaseReport(
            alert_id=alert.id,
            title=alert.title,
            severity=Severity(raw["severity"]),
            verdict=Verdict(raw["verdict"]),
            confidence=raw["confidence"],
            executive_summary=raw["executive_summary"],
            findings_summary=raw["findings_summary"],
            director_output=director_output,
            investigator_output=investigator_output,
            evidence_gaps=raw.get("evidence_gaps", []),
            recommendations=raw.get("recommendations", []),
            requires_human_review=True,
        )

    def _format_evidence_for_review(
        self,
        director_output: DirectorOutput,
        investigator_output: InvestigatorOutput,
    ) -> str:
        """Format the investigation evidence into a readable summary for the LLM."""
        lines: list[str] = []

        for item in investigator_output.evidence:
            lines.append(f"\nQuestion {item.question_number}: {item.question}")
            lines.append(f"Assessment: {'supports malicious' if item.supports_malicious else 'benign/inconclusive' if item.supports_malicious is False else 'inconclusive'}")
            lines.append(f"Analyst Notes: {item.analyst_notes}")

            for qr in item.query_results:
                status = f"found {len(qr.data)} result(s)" if qr.found else "no results"
                if qr.error:
                    status = f"error: {qr.error}"
                lines.append(f"  [{qr.connector}] {status} — query: {str(qr.query)[:100]}")

        if investigator_output.raw_ioc_enrichments:
            lines.append("\nIOC Enrichment Results:")
            for qr in investigator_output.raw_ioc_enrichments:
                status = f"found: {json.dumps(qr.data, default=str)[:200]}" if qr.found else "no hits"
                if qr.error:
                    status = f"error: {qr.error}"
                lines.append(f"  [{qr.connector}] {qr.query} — {status}")

        return "\n".join(lines)
