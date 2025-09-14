"""Alert triage agent for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime
from loguru import logger

from ..core.agent_manager import BaseAgent, AgentTask
from ..core.llm_interface import LLMInterface
from ..tools.siem_connector import SIEMConnector
from ..tools.threat_intel_api import ThreatIntelAPI


class TriageAgent(BaseAgent):
    """AI agent for automated alert triage and prioritization."""
    
    def __init__(
        self,
        agent_id: str,
        name: str = "Alert Triage Agent",
        description: str = "Automatically triages and prioritizes security alerts",
        llm_interface: Optional[LLMInterface] = None
    ):
        super().__init__(agent_id, name, description, llm_interface)
        
        # Initialize tools
        self.siem_connector = SIEMConnector()
        self.threat_intel = ThreatIntelAPI()
        
        # Register tools
        self.register_tool("search_siem_logs", self.siem_connector.search_logs)
        self.register_tool("get_alert_details", self.siem_connector.get_alert_details)
        self.register_tool("check_ip_reputation", self.threat_intel.check_ip_reputation)
        self.register_tool("check_domain_reputation", self.threat_intel.check_domain_reputation)
        self.register_tool("check_file_hash", self.threat_intel.check_file_hash)
        
        # Triage rules and thresholds
        self.severity_mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
        
        self.risk_indicators = [
            "malware", "phishing", "ransomware", "apt", "botnet",
            "command_and_control", "data_exfiltration", "privilege_escalation",
            "lateral_movement", "persistence", "defense_evasion"
        ]
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        return list(self.tools.keys())
    
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process a triage task."""
        try:
            task_type = task.task_type
            input_data = task.input_data
            
            if task_type == "triage_alert":
                return await self._triage_alert(input_data)
            elif task_type == "batch_triage":
                return await self._batch_triage(input_data)
            elif task_type == "update_triage_rules":
                return await self._update_triage_rules(input_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Error processing triage task: {e}")
            raise
    
    async def _triage_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Triage a single security alert."""
        try:
            alert_id = alert_data.get("alert_id")
            if not alert_id:
                raise ValueError("Alert ID is required")
            
            # Get detailed alert information
            alert_details = await self.siem_connector.get_alert_details(alert_id)
            if not alert_details:
                return {
                    "alert_id": alert_id,
                    "status": "error",
                    "message": "Alert not found"
                }
            
            # Perform triage analysis
            triage_result = await self._analyze_alert(alert_details)
            
            # Update alert with triage results
            await self.siem_connector.update_alert_status(
                alert_id, 
                triage_result["status"],
                triage_result["priority"],
                triage_result["analysis"]
            )
            
            return {
                "alert_id": alert_id,
                "status": "success",
                "triage_result": triage_result
            }
            
        except Exception as e:
            logger.error(f"Error triaging alert: {e}")
            raise
    
    async def _analyze_alert(self, alert_details: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an alert using AI and threat intelligence."""
        try:
            # Prepare context for LLM analysis
            context = self._prepare_alert_context(alert_details)
            
            # Get threat intelligence data
            threat_data = await self._gather_threat_intelligence(alert_details)
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(context, threat_data)
            
            # Get AI analysis
            messages = [
                {
                    "role": "system",
                    "content": """You are a senior security analyst specializing in alert triage. 
                    Analyze the provided security alert and determine:
                    1. Alert severity (critical, high, medium, low, info)
                    2. Priority level (1-5, where 5 is highest)
                    3. Risk assessment
                    4. Recommended actions
                    5. False positive likelihood
                    
                    Provide your analysis in JSON format."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            analysis_response = await self.llm_interface.generate_response(messages)
            
            # Parse AI response
            try:
                analysis = json.loads(analysis_response)
            except json.JSONDecodeError:
                # Fallback to rule-based analysis if AI response is invalid
                analysis = self._rule_based_analysis(alert_details, threat_data)
            
            # Calculate final priority score
            priority_score = self._calculate_priority_score(alert_details, analysis, threat_data)
            
            return {
                "severity": analysis.get("severity", "medium"),
                "priority": priority_score,
                "status": "triaged",
                "analysis": analysis,
                "threat_intel": threat_data,
                "confidence": analysis.get("confidence", 0.7),
                "recommended_actions": analysis.get("recommended_actions", []),
                "false_positive_likelihood": analysis.get("false_positive_likelihood", 0.3)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing alert: {e}")
            # Fallback to basic analysis
            return self._basic_analysis(alert_details)
    
    def _prepare_alert_context(self, alert_details: Dict[str, Any]) -> str:
        """Prepare alert context for AI analysis."""
        context_parts = [
            f"Alert ID: {alert_details.get('id', 'Unknown')}",
            f"Event Type: {alert_details.get('event_type', 'Unknown')}",
            f"Source: {alert_details.get('source', 'Unknown')}",
            f"Timestamp: {alert_details.get('timestamp', 'Unknown')}",
            f"Description: {alert_details.get('description', 'No description')}",
        ]
        
        if alert_details.get('raw_data'):
            context_parts.append(f"Raw Data: {json.dumps(alert_details['raw_data'], indent=2)}")
        
        return "\n".join(context_parts)
    
    async def _gather_threat_intelligence(self, alert_details: Dict[str, Any]) -> Dict[str, Any]:
        """Gather threat intelligence for the alert."""
        threat_data = {}
        
        try:
            # Extract IOCs from alert
            iocs = self._extract_iocs(alert_details)
            
            # Check IP addresses
            for ip in iocs.get("ips", []):
                threat_data[f"ip_{ip}"] = await self.threat_intel.check_ip_reputation(ip)
            
            # Check domains
            for domain in iocs.get("domains", []):
                threat_data[f"domain_{domain}"] = await self.threat_intel.check_domain_reputation(domain)
            
            # Check file hashes
            for file_hash in iocs.get("hashes", []):
                threat_data[f"hash_{file_hash}"] = await self.threat_intel.check_file_hash(file_hash)
            
        except Exception as e:
            logger.warning(f"Error gathering threat intelligence: {e}")
        
        return threat_data
    
    def _extract_iocs(self, alert_details: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract indicators of compromise from alert data."""
        iocs = {"ips": [], "domains": [], "hashes": [], "urls": []}
        
        # Simple regex patterns for IOC extraction
        import re
        
        raw_data = json.dumps(alert_details.get("raw_data", {}))
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs["ips"] = list(set(re.findall(ip_pattern, raw_data)))
        
        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domains"] = list(set(re.findall(domain_pattern, raw_data)))
        
        # MD5 hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        iocs["hashes"].extend(re.findall(md5_pattern, raw_data))
        
        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        iocs["hashes"].extend(re.findall(sha256_pattern, raw_data))
        
        return iocs
    
    def _create_analysis_prompt(self, context: str, threat_data: Dict[str, Any]) -> str:
        """Create analysis prompt for the LLM."""
        prompt_parts = [
            "Please analyze the following security alert:",
            "",
            "ALERT CONTEXT:",
            context,
            "",
            "THREAT INTELLIGENCE DATA:",
            json.dumps(threat_data, indent=2),
            "",
            "Please provide your analysis in the following JSON format:",
            json.dumps({
                "severity": "critical|high|medium|low|info",
                "priority": 1,
                "risk_assessment": "Brief risk assessment",
                "recommended_actions": ["action1", "action2"],
                "false_positive_likelihood": 0.0,
                "confidence": 0.0,
                "reasoning": "Brief explanation of your analysis"
            }, indent=2)
        ]
        
        return "\n".join(prompt_parts)
    
    def _rule_based_analysis(self, alert_details: Dict[str, Any], threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based analysis when AI analysis fails."""
        severity = "medium"
        priority = 3
        
        # Check for high-risk indicators
        description = alert_details.get("description", "").lower()
        for indicator in self.risk_indicators:
            if indicator in description:
                severity = "high"
                priority = 4
                break
        
        # Check threat intelligence data
        for key, data in threat_data.items():
            if isinstance(data, dict) and data.get("malicious", False):
                severity = "critical"
                priority = 5
                break
        
        return {
            "severity": severity,
            "priority": priority,
            "risk_assessment": "Rule-based analysis",
            "recommended_actions": ["Review alert details", "Check threat intelligence"],
            "false_positive_likelihood": 0.5,
            "confidence": 0.6,
            "reasoning": "Rule-based analysis due to AI analysis failure"
        }
    
    def _basic_analysis(self, alert_details: Dict[str, Any]) -> Dict[str, Any]:
        """Basic analysis when all else fails."""
        return {
            "severity": "medium",
            "priority": 3,
            "status": "triaged",
            "analysis": {
                "severity": "medium",
                "priority": 3,
                "risk_assessment": "Requires manual review",
                "recommended_actions": ["Manual investigation required"],
                "false_positive_likelihood": 0.5,
                "confidence": 0.5,
                "reasoning": "Basic analysis due to processing error"
            },
            "threat_intel": {},
            "confidence": 0.5,
            "recommended_actions": ["Manual investigation required"],
            "false_positive_likelihood": 0.5
        }
    
    def _calculate_priority_score(self, alert_details: Dict[str, Any], analysis: Dict[str, Any], threat_data: Dict[str, Any]) -> int:
        """Calculate final priority score based on multiple factors."""
        base_priority = analysis.get("priority", 3)
        
        # Adjust based on threat intelligence
        malicious_count = sum(1 for data in threat_data.values() 
                            if isinstance(data, dict) and data.get("malicious", False))
        
        if malicious_count > 0:
            base_priority = min(5, base_priority + malicious_count)
        
        # Adjust based on false positive likelihood
        fp_likelihood = analysis.get("false_positive_likelihood", 0.5)
        if fp_likelihood > 0.7:
            base_priority = max(1, base_priority - 1)
        
        return min(5, max(1, base_priority))
    
    async def _batch_triage(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process multiple alerts in batch."""
        alert_ids = input_data.get("alert_ids", [])
        results = []
        
        for alert_id in alert_ids:
            try:
                result = await self._triage_alert({"alert_id": alert_id})
                results.append(result)
            except Exception as e:
                results.append({
                    "alert_id": alert_id,
                    "status": "error",
                    "message": str(e)
                })
        
        return {
            "status": "completed",
            "total_alerts": len(alert_ids),
            "successful": len([r for r in results if r["status"] == "success"]),
            "failed": len([r for r in results if r["status"] == "error"]),
            "results": results
        }
    
    async def _update_triage_rules(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update triage rules and thresholds."""
        # This would typically update a rules database or configuration
        # For now, just update in-memory rules
        
        if "severity_mapping" in input_data:
            self.severity_mapping.update(input_data["severity_mapping"])
        
        if "risk_indicators" in input_data:
            self.risk_indicators.extend(input_data["risk_indicators"])
        
        return {
            "status": "success",
            "message": "Triage rules updated successfully",
            "updated_rules": {
                "severity_mapping": self.severity_mapping,
                "risk_indicators": self.risk_indicators
            }
        }