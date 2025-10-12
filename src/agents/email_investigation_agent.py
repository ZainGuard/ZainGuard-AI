"""Email investigation agent for ZainGuard AI Platform."""

import hashlib
import json
import re
from datetime import datetime
from email.utils import parseaddr
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from loguru import logger

from ..core.agent_manager import AgentTask, BaseAgent
from ..core.llm_interface import LLMInterface
from ..tools.threat_intel_api import ThreatIntelAPI


class EmailInvestigationAgent(BaseAgent):
    """AI agent for comprehensive email security investigation."""

    def __init__(
        self,
        agent_id: str,
        name: str = "Email Investigation Agent",
        description: str = "Comprehensive email security analysis and investigation",
        llm_interface: Optional[LLMInterface] = None,
    ):
        super().__init__(agent_id, name, description, llm_interface)

        # Initialize tools
        self.threat_intel = ThreatIntelAPI()

        # Register tools
        self.register_tool(
            "check_domain_reputation", self.threat_intel.check_domain_reputation
        )
        self.register_tool("check_ip_reputation", self.threat_intel.check_ip_reputation)
        self.register_tool("check_file_hash", self.threat_intel.check_file_hash)
        self.register_tool("analyze_email_headers", self._analyze_email_headers)
        self.register_tool("extract_urls", self._extract_urls)
        self.register_tool("analyze_attachments", self._analyze_attachments)
        self.register_tool("detect_phishing_patterns", self._detect_phishing_patterns)
        self.register_tool("check_sender_reputation", self._check_sender_reputation)

        # Phishing indicators
        self.phishing_indicators = [
            "urgent",
            "immediate action",
            "verify account",
            "suspended account",
            "click here",
            "limited time",
            "act now",
            "expires soon",
            "confirm your identity",
            "security alert",
            "unauthorized access",
        ]

        # Suspicious domains/TLDs
        self.suspicious_tlds = [
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".click",
            ".download",
            ".zip",
        ]

    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process an email investigation task."""
        try:
            email_data = task.input_data
            investigation_id = task.task_id

            logger.info(f"Starting email investigation {investigation_id}")

            # Initialize investigation results
            results = {
                "investigation_id": investigation_id,
                "timestamp": datetime.utcnow().isoformat(),
                "email_metadata": {},
                "header_analysis": {},
                "content_analysis": {},
                "threat_intelligence": {},
                "risk_assessment": {},
                "recommendations": [],
            }

            # 1. Extract and analyze email headers
            if "headers" in email_data:
                results["header_analysis"] = await self._analyze_email_headers(
                    email_data["headers"]
                )

            # 2. Analyze email content
            if "content" in email_data or "body" in email_data:
                content = email_data.get("content", email_data.get("body", ""))
                results["content_analysis"] = await self._analyze_email_content(content)

            # 3. Extract and analyze URLs
            urls = await self._extract_urls(
                email_data.get("content", email_data.get("body", ""))
            )
            if urls:
                results["url_analysis"] = await self._analyze_urls(urls)

            # 4. Analyze attachments
            if "attachments" in email_data:
                results["attachment_analysis"] = await self._analyze_attachments(
                    email_data["attachments"]
                )

            # 5. Check sender reputation
            sender = email_data.get("from", "")
            if sender:
                results["sender_analysis"] = await self._check_sender_reputation(sender)

            # 6. Detect phishing patterns using LLM
            results["phishing_analysis"] = await self._detect_phishing_patterns(
                email_data
            )

            # 7. Generate risk assessment
            results["risk_assessment"] = await self._generate_risk_assessment(results)

            # 8. Generate recommendations
            results["recommendations"] = await self._generate_recommendations(results)

            logger.info(f"Email investigation {investigation_id} completed")

            return {"status": "completed", "investigation_results": results}

        except Exception as e:
            logger.error(f"Email investigation failed: {e}")
            return {"status": "failed", "error": str(e)}

    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        return list(self.tools.keys())

    async def _analyze_email_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze email headers for security indicators."""
        analysis = {
            "spoofing_indicators": [],
            "authentication_results": {},
            "routing_analysis": {},
            "security_flags": [],
        }

        # Check for spoofing indicators
        if "from" in headers and "reply-to" in headers:
            if headers["from"] != headers["reply-to"]:
                analysis["spoofing_indicators"].append(
                    "From and Reply-To addresses differ"
                )

        # Check SPF, DKIM, DMARC
        if "received-spf" in headers:
            analysis["authentication_results"]["spf"] = headers["received-spf"]

        if "authentication-results" in headers:
            analysis["authentication_results"]["dkim"] = headers[
                "authentication-results"
            ]

        # Check for suspicious routing
        if "received" in headers:
            received_headers = headers.get("received", "").split("\n")
            analysis["routing_analysis"]["hop_count"] = len(received_headers)

            # Check for unusual routing patterns
            for received in received_headers:
                if any(
                    indicator in received.lower()
                    for indicator in ["relay", "proxy", "anonymizer"]
                ):
                    analysis["security_flags"].append("Suspicious routing detected")

        # Check message ID for uniqueness
        if "message-id" in headers:
            msg_id = headers["message-id"]
            if len(msg_id) < 10 or msg_id.count("@") != 1:
                analysis["security_flags"].append("Suspicious Message-ID format")

        return analysis

    async def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from email content."""
        url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        urls = re.findall(url_pattern, content)
        return list(set(urls))  # Remove duplicates

    async def _analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """Analyze extracted URLs for threats."""
        analysis = {
            "total_urls": len(urls),
            "suspicious_urls": [],
            "domain_analysis": {},
            "threat_intel_results": {},
        }

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc

                # Check for suspicious TLDs
                if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                    analysis["suspicious_urls"].append(
                        {"url": url, "reason": "Suspicious TLD", "domain": domain}
                    )

                # Check domain reputation
                if domain not in analysis["domain_analysis"]:
                    try:
                        domain_reputation = await self.execute_tool(
                            "check_domain_reputation", domain=domain
                        )
                        analysis["domain_analysis"][domain] = domain_reputation
                    except Exception as e:
                        logger.warning(
                            f"Failed to check domain reputation for {domain}: {e}"
                        )
                        analysis["domain_analysis"][domain] = {"error": str(e)}

            except Exception as e:
                logger.warning(f"Failed to parse URL {url}: {e}")

        return analysis

    async def _analyze_attachments(
        self, attachments: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze email attachments for threats."""
        analysis = {
            "total_attachments": len(attachments),
            "suspicious_attachments": [],
            "file_analysis": {},
        }

        for attachment in attachments:
            filename = attachment.get("filename", "")
            file_hash = attachment.get("hash", "")
            file_size = attachment.get("size", 0)

            # Check for suspicious file extensions
            suspicious_extensions = [
                ".exe",
                ".scr",
                ".bat",
                ".cmd",
                ".com",
                ".pif",
                ".vbs",
                ".js",
            ]
            if any(filename.lower().endswith(ext) for ext in suspicious_extensions):
                analysis["suspicious_attachments"].append(
                    {"filename": filename, "reason": "Suspicious file extension"}
                )

            # Check file size
            if file_size > 10 * 1024 * 1024:  # 10MB
                analysis["suspicious_attachments"].append(
                    {
                        "filename": filename,
                        "reason": "Large file size",
                        "size": file_size,
                    }
                )

            # Check file hash if available
            if file_hash:
                try:
                    hash_analysis = await self.execute_tool(
                        "check_file_hash", file_hash=file_hash
                    )
                    analysis["file_analysis"][filename] = hash_analysis
                except Exception as e:
                    logger.warning(f"Failed to check file hash for {filename}: {e}")
                    analysis["file_analysis"][filename] = {"error": str(e)}

        return analysis

    async def _detect_phishing_patterns(
        self, email_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to detect phishing patterns in email content."""
        content = email_data.get("content", email_data.get("body", ""))
        subject = email_data.get("subject", "")

        # Basic phishing detection without LLM
        phishing_score = 0
        indicators = []

        # Check for urgency tactics
        urgency_words = [
            "urgent",
            "immediate",
            "asap",
            "expires",
            "limited time",
            "act now",
        ]
        urgency_count = sum(1 for word in urgency_words if word in content.lower())
        if urgency_count > 0:
            phishing_score += 20 * urgency_count
            indicators.append(f"Urgency tactics detected ({urgency_count} indicators)")

        # Check for suspicious requests
        suspicious_requests = [
            "verify",
            "confirm",
            "update",
            "click here",
            "login",
            "password",
        ]
        request_count = sum(
            1 for word in suspicious_requests if word in content.lower()
        )
        if request_count > 0:
            phishing_score += 15 * request_count
            indicators.append(
                f"Suspicious requests detected ({request_count} indicators)"
            )

        # Check subject line
        if any(
            word in subject.lower()
            for word in ["urgent", "verify", "suspended", "alert"]
        ):
            phishing_score += 25
            indicators.append("Suspicious subject line")

        # Check for poor grammar/spelling (basic check)
        if len(content.split()) > 10:  # Only check if there's substantial content
            if content.count("!") > 3:  # Excessive exclamation marks
                phishing_score += 10
                indicators.append("Excessive exclamation marks")

        # Try LLM analysis if available
        try:
            prompt = f"""
            Analyze the following email for phishing indicators:
            
            Subject: {subject}
            Content: {content[:500]}...
            
            Provide a phishing score (0-100) and list key indicators.
            """

            messages = [{"role": "user", "content": prompt}]
            llm_response = await self.llm_interface.generate_response(messages)

            return {
                "llm_analysis": llm_response,
                "phishing_score": min(phishing_score, 100),
                "indicators": indicators,
                "basic_analysis": True,
            }
        except Exception as e:
            logger.warning(f"LLM analysis not available: {e}")
            return {
                "error": "LLM not available",
                "phishing_score": min(phishing_score, 100),
                "indicators": indicators,
                "basic_analysis": True,
            }

    async def _check_sender_reputation(self, sender: str) -> Dict[str, Any]:
        """Check sender reputation and extract domain for analysis."""
        analysis = {"sender": sender, "domain_reputation": {}, "email_analysis": {}}

        try:
            # Parse sender email
            name, email = parseaddr(sender)
            if "@" in email:
                domain = email.split("@")[1]

                # Check domain reputation
                try:
                    domain_reputation = await self.execute_tool(
                        "check_domain_reputation", domain=domain
                    )
                    analysis["domain_reputation"] = domain_reputation
                except Exception as e:
                    analysis["domain_reputation"] = {"error": str(e)}

                # Analyze email format
                analysis["email_analysis"] = {
                    "display_name": name,
                    "email_address": email,
                    "domain": domain,
                    "is_valid_format": bool(
                        re.match(
                            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email
                        )
                    ),
                }

        except Exception as e:
            analysis["error"] = str(e)

        return analysis

    async def _analyze_email_content(self, content: str) -> Dict[str, Any]:
        """Analyze email content for security indicators."""
        analysis = {
            "phishing_indicators": [],
            "suspicious_keywords": [],
            "content_metrics": {},
        }

        content_lower = content.lower()

        # Check for phishing indicators
        for indicator in self.phishing_indicators:
            if indicator in content_lower:
                analysis["phishing_indicators"].append(indicator)

        # Basic content metrics
        analysis["content_metrics"] = {
            "length": len(content),
            "word_count": len(content.split()),
            "has_html": "<html>" in content_lower or "<body>" in content_lower,
            "has_forms": "<form>" in content_lower,
            "has_scripts": "<script>" in content_lower,
        }

        return analysis

    async def _generate_risk_assessment(
        self, investigation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate overall risk assessment based on investigation results."""
        risk_score = 0
        risk_factors = []

        # Analyze header analysis
        header_analysis = investigation_results.get("header_analysis", {})
        if header_analysis.get("spoofing_indicators"):
            risk_score += 30
            risk_factors.append("Email spoofing indicators detected")

        if header_analysis.get("security_flags"):
            risk_score += 20
            risk_factors.append("Security flags in headers")

        # Analyze content analysis
        content_analysis = investigation_results.get("content_analysis", {})
        if content_analysis.get("phishing_indicators"):
            risk_score += 25
            risk_factors.append("Phishing indicators in content")

        # Analyze URLs
        url_analysis = investigation_results.get("url_analysis", {})
        if url_analysis.get("suspicious_urls"):
            risk_score += 35
            risk_factors.append("Suspicious URLs detected")

        # Analyze attachments
        attachment_analysis = investigation_results.get("attachment_analysis", {})
        if attachment_analysis.get("suspicious_attachments"):
            risk_score += 40
            risk_factors.append("Suspicious attachments detected")

        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "risk_score": min(risk_score, 100),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": datetime.utcnow().isoformat(),
        }

    async def _generate_recommendations(
        self, investigation_results: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations based on investigation results."""
        recommendations = []

        risk_assessment = investigation_results.get("risk_assessment", {})
        risk_level = risk_assessment.get("risk_level", "MINIMAL")

        if risk_level == "HIGH":
            recommendations.extend(
                [
                    "IMMEDIATE ACTION REQUIRED: Block sender and quarantine email",
                    "Scan all systems for potential compromise",
                    "Notify security team immediately",
                    "Review and update email security policies",
                ]
            )
        elif risk_level == "MEDIUM":
            recommendations.extend(
                [
                    "Flag email for manual review",
                    "Block sender domain temporarily",
                    "Monitor for similar emails",
                    "Update email filters",
                ]
            )
        elif risk_level == "LOW":
            recommendations.extend(
                [
                    "Monitor sender for future emails",
                    "Add to watch list",
                    "Review email security training",
                ]
            )
        else:
            recommendations.append("Email appears safe - continue monitoring")

        # Add specific recommendations based on findings
        if investigation_results.get("attachment_analysis", {}).get(
            "suspicious_attachments"
        ):
            recommendations.append("Scan all attachments with antivirus before opening")

        if investigation_results.get("url_analysis", {}).get("suspicious_urls"):
            recommendations.append("Block access to suspicious URLs")

        if investigation_results.get("header_analysis", {}).get("spoofing_indicators"):
            recommendations.append(
                "Implement stricter email authentication (DMARC, DKIM, SPF)"
            )

        return recommendations
