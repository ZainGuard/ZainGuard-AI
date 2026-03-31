"""
Director Agent — First-level triage and investigation framing.

Responsibilities:
- Parse and understand the incoming alert event(s)
- Identify key actors, assets, and IOCs involved
- Generate exactly 3 investigative questions that:
    * Are directly answerable using available evidence
    * Push the investigation toward clear resolution
    * Cover different angles (identity, system, network)

The Director does NOT query any data sources — it works from the
alert payload alone. Its output sets the agenda for the Investigator.
"""
from __future__ import annotations

import json
from typing import Any

from zainguard_ai_soc.llm import LLMClient
from zainguard_ai_soc.models import (
    Alert,
    DirectorOutput,
    InvestigativeQuestion,
    Severity,
)

DIRECTOR_SYSTEM_PROMPT = """You are the Director Agent in a security operations investigation pipeline.

Your job is to perform first-level triage on a security alert and frame the investigation
by generating exactly 3 focused investigative questions.

Rules:
1. Each question must be directly answerable using log data, knowledge base context, or threat intelligence
2. Questions must push toward a clear resolution (malicious vs benign)
3. Cover different angles — identity/authentication, system/process activity, network/external
4. Be specific: name the actual IPs, users, hostnames, or processes from the alert
5. Do not ask vague questions — every question should have a yes/no or specific factual answer

Output JSON only. No prose before or after. Schema:
{
  "triage_summary": "<2-3 sentence description of what happened>",
  "key_actors": ["<user1>", "<IP1>"],
  "key_assets": ["<hostname>", "<resource ARN>"],
  "iocs": ["<IP>", "<domain>", "<hash>"],
  "questions": [
    {
      "number": 1,
      "question": "<specific, answerable question>",
      "rationale": "<why this question matters>",
      "target_layers": ["layer1", "layer3"]
    }
  ]
}
"""


class DirectorAgent:
    """
    Triages security alerts and generates investigative questions.
    """

    def __init__(self, model: str = "claude-opus-4-6") -> None:
        self.llm = LLMClient(model=model)

    def run(self, alert: Alert) -> DirectorOutput:
        """
        Triage a single alert and return 3 investigative questions.

        Args:
            alert: The security alert to investigate.

        Returns:
            DirectorOutput with triage summary and 3 questions.
        """
        prompt = f"""Security Alert:
Title: {alert.title}
Source: {alert.source}
Severity: {alert.severity.value}
Description: {alert.description}

Raw Event Payload:
{json.dumps(alert.raw, indent=2)}

Generate your triage summary and 3 investigative questions for this alert."""

        raw = json.loads(self.llm.complete_json(system=DIRECTOR_SYSTEM_PROMPT, user=prompt, max_tokens=1024))
        return self._parse_output(alert.id, raw)

    def _parse_output(self, alert_id: str, raw: dict[str, Any]) -> DirectorOutput:
        questions = [
            InvestigativeQuestion(
                number=q["number"],
                question=q["question"],
                rationale=q["rationale"],
                target_layers=q.get("target_layers", []),
            )
            for q in raw["questions"]
        ]
        return DirectorOutput(
            alert_id=alert_id,
            triage_summary=raw["triage_summary"],
            key_actors=raw.get("key_actors", []),
            key_assets=raw.get("key_assets", []),
            iocs=raw.get("iocs", []),
            questions=questions,
        )
