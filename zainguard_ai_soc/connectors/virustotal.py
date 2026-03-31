"""
VirusTotal connector — Layer 3 (External Threat Intelligence).

Enriches IPs, domains, and file hashes against VirusTotal's
threat intelligence database.

Environment variable:
    VIRUSTOTAL_API_KEY — your VirusTotal API key (free tier works)

Usage:
    from zainguard_ai_soc.connectors.virustotal import VirusTotalConnector

    connector = VirusTotalConnector(api_key=os.environ["VIRUSTOTAL_API_KEY"])
    result = connector.query({"ioc": "1.2.3.4"})
"""
from __future__ import annotations

import re
import os
from typing import Any

import httpx

from zainguard_ai_soc.connectors.base import BaseConnector
from zainguard_ai_soc.models import QueryResult

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


class VirusTotalConnector(BaseConnector):
    """
    Query VirusTotal for IP, domain, and file hash reputation.

    Params for query():
        ioc (str): An IP address, domain, or file hash (MD5/SHA1/SHA256)
    """

    layer = "layer3"
    name = "virustotal"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")

    def query(self, params: dict[str, Any]) -> QueryResult:
        ioc = params.get("ioc", "")
        if not ioc:
            return QueryResult(connector=self.name, layer=self.layer, query="", data=[], found=False, error="No IOC provided")

        endpoint = self._resolve_endpoint(ioc)
        if not endpoint:
            return QueryResult(connector=self.name, layer=self.layer, query=ioc, data=[], found=False, error=f"Cannot determine IOC type for: {ioc}")

        try:
            response = httpx.get(
                endpoint,
                headers={"x-apikey": self.api_key},
                timeout=15.0,
            )
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                total = sum(stats.values()) or 1

                parsed = {
                    "ioc": ioc,
                    "malicious": malicious_count > 0,
                    "malicious_detections": malicious_count,
                    "total_engines": total,
                    "confidence": round(malicious_count / total, 3),
                    "categories": attrs.get("categories", {}),
                    "country": attrs.get("country"),
                    "asn": attrs.get("asn"),
                    "registrar": attrs.get("registrar"),
                    "file_type": attrs.get("type_description"),
                }
                return QueryResult(connector=self.name, layer=self.layer, query=ioc, data=[parsed], found=True)

            if response.status_code == 404:
                return QueryResult(connector=self.name, layer=self.layer, query=ioc, data=[], found=False)

            return QueryResult(connector=self.name, layer=self.layer, query=ioc, data=[], found=False, error=f"HTTP {response.status_code}")

        except Exception as e:
            return QueryResult(connector=self.name, layer=self.layer, query=ioc, data=[], found=False, error=str(e))

    def health_check(self) -> bool:
        try:
            response = httpx.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": self.api_key},
                timeout=10.0,
            )
            return response.status_code == 200
        except Exception:
            return False

    def _resolve_endpoint(self, ioc: str) -> str | None:
        if _IP_RE.match(ioc):
            return f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        if _HASH_RE.match(ioc):
            return f"https://www.virustotal.com/api/v3/files/{ioc}"
        if "." in ioc and not ioc.startswith("http"):
            return f"https://www.virustotal.com/api/v3/domains/{ioc}"
        return None
