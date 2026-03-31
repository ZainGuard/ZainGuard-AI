"""
ZainGuard AI SOC — Open Source AI Investigation Framework for Security Operations.

Quick start:
    from zainguard_ai_soc.pipeline import investigate
    from zainguard_ai_soc.models import Alert, Severity

    report = investigate(
        alert=Alert(id="1", title="...", source="wiz", severity=Severity.HIGH, raw={...}),
        connectors=[...],
    )
"""
from zainguard_ai_soc.pipeline import investigate, investigate_batch
from zainguard_ai_soc.models import Alert, CaseReport, Severity, Verdict

__version__ = "0.2.0"
__all__ = ["investigate", "investigate_batch", "Alert", "CaseReport", "Severity", "Verdict"]
