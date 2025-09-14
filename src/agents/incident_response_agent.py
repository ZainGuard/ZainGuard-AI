"""Incident response agent for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime
from loguru import logger

from ..core.agent_manager import BaseAgent, AgentTask
from ..core.llm_interface import LLMInterface
from ..tools.siem_connector import SIEMConnector
from ..tools.threat_intel_api import ThreatIntelAPI
from ..tools.jira_manager import JiraManager


class IncidentResponseAgent(BaseAgent):
    """AI agent for automated incident response and management."""
    
    def __init__(
        self,
        agent_id: str,
        name: str = "Incident Response Agent",
        description: str = "Automated incident response and management",
        llm_interface: Optional[LLMInterface] = None
    ):
        super().__init__(agent_id, name, description, llm_interface)
        
        # Initialize tools
        self.siem_connector = SIEMConnector()
        self.threat_intel = ThreatIntelAPI()
        self.jira_manager = JiraManager()
        
        # Register tools
        self.register_tool("search_siem_logs", self.siem_connector.search_logs)
        self.register_tool("get_alert_details", self.siem_connector.get_alert_details)
        self.register_tool("check_ip_reputation", self.threat_intel.check_ip_reputation)
        self.register_tool("check_domain_reputation", self.threat_intel.check_domain_reputation)
        self.register_tool("create_incident_ticket", self.jira_manager.create_incident_ticket)
        self.register_tool("update_ticket", self.jira_manager.update_ticket)
        self.register_tool("add_comment", self.jira_manager.add_comment)
        
        # Incident response playbooks
        self.playbooks = {
            "malware": self._malware_playbook,
            "phishing": self._phishing_playbook,
            "ddos": self._ddos_playbook,
            "data_breach": self._data_breach_playbook,
            "insider_threat": self._insider_threat_playbook
        }
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        return list(self.tools.keys())
    
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process an incident response task."""
        try:
            task_type = task.task_type
            input_data = task.input_data
            
            if task_type == "respond_to_incident":
                return await self._respond_to_incident(input_data)
            elif task_type == "create_incident":
                return await self._create_incident(input_data)
            elif task_type == "update_incident":
                return await self._update_incident(input_data)
            elif task_type == "execute_playbook":
                return await self._execute_playbook(input_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Error processing incident response task: {e}")
            raise
    
    async def _respond_to_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Respond to a security incident."""
        try:
            incident_id = incident_data.get("incident_id")
            incident_type = incident_data.get("incident_type", "unknown")
            severity = incident_data.get("severity", "medium")
            
            logger.info(f"Responding to incident {incident_id} of type {incident_type}")
            
            # Analyze the incident
            analysis = await self._analyze_incident(incident_data)
            
            # Determine response strategy
            response_strategy = await self._determine_response_strategy(incident_data, analysis)
            
            # Execute response actions
            response_actions = await self._execute_response_actions(
                incident_id, response_strategy, analysis
            )
            
            # Create incident ticket
            ticket_key = await self._create_incident_ticket(incident_data, analysis, response_actions)
            
            return {
                "incident_id": incident_id,
                "status": "responded",
                "analysis": analysis,
                "response_strategy": response_strategy,
                "actions_taken": response_actions,
                "ticket_key": ticket_key
            }
            
        except Exception as e:
            logger.error(f"Error responding to incident: {e}")
            raise
    
    async def _analyze_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze incident using AI and threat intelligence."""
        try:
            # Gather additional context
            context = await self._gather_incident_context(incident_data)
            
            # Get threat intelligence
            threat_data = await self._gather_threat_intelligence(incident_data)
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(incident_data, context, threat_data)
            
            messages = [
                {
                    "role": "system",
                    "content": """You are a senior incident response analyst. Analyze the provided security incident and provide:
                    1. Incident classification and severity assessment
                    2. Root cause analysis
                    3. Impact assessment
                    4. Affected systems and data
                    5. Recommended containment actions
                    6. Evidence collection requirements
                    7. Communication requirements
                    
                    Provide your analysis in JSON format."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            analysis_response = await self.llm_interface.generate_response(messages)
            
            try:
                analysis = json.loads(analysis_response)
            except json.JSONDecodeError:
                # Fallback analysis
                analysis = self._basic_incident_analysis(incident_data, context, threat_data)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing incident: {e}")
            return self._basic_incident_analysis(incident_data, {}, {})
    
    async def _gather_incident_context(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather additional context about the incident."""
        context = {
            "timeline": [],
            "related_alerts": [],
            "affected_systems": [],
            "network_activity": []
        }
        
        try:
            # Search for related alerts
            if incident_data.get("source_ip"):
                alerts = await self.siem_connector.search_logs(
                    f"src_ip:{incident_data['source_ip']}",
                    limit=10
                )
                context["related_alerts"] = alerts
            
            # Search for network activity
            if incident_data.get("source_ip"):
                network_logs = await self.siem_connector.search_logs(
                    f"src_ip:{incident_data['source_ip']} AND event_type:network",
                    limit=20
                )
                context["network_activity"] = network_logs
            
        except Exception as e:
            logger.warning(f"Error gathering incident context: {e}")
        
        return context
    
    async def _gather_threat_intelligence(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gather threat intelligence for the incident."""
        threat_data = {}
        
        try:
            # Check IP addresses
            if incident_data.get("source_ip"):
                threat_data["source_ip"] = await self.threat_intel.check_ip_reputation(
                    incident_data["source_ip"]
                )
            
            if incident_data.get("destination_ip"):
                threat_data["destination_ip"] = await self.threat_intel.check_ip_reputation(
                    incident_data["destination_ip"]
                )
            
            # Check domains
            if incident_data.get("domain"):
                threat_data["domain"] = await self.threat_intel.check_domain_reputation(
                    incident_data["domain"]
                )
            
            # Check file hashes
            if incident_data.get("file_hash"):
                threat_data["file_hash"] = await self.threat_intel.check_file_hash(
                    incident_data["file_hash"]
                )
            
        except Exception as e:
            logger.warning(f"Error gathering threat intelligence: {e}")
        
        return threat_data
    
    def _create_analysis_prompt(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any],
        threat_data: Dict[str, Any]
    ) -> str:
        """Create analysis prompt for the LLM."""
        prompt_parts = [
            "INCIDENT DATA:",
            json.dumps(incident_data, indent=2),
            "",
            "ADDITIONAL CONTEXT:",
            json.dumps(context, indent=2),
            "",
            "THREAT INTELLIGENCE:",
            json.dumps(threat_data, indent=2),
            "",
            "Please provide your incident analysis in the following JSON format:",
            json.dumps({
                "classification": "incident_type",
                "severity": "critical|high|medium|low",
                "root_cause": "Brief root cause analysis",
                "impact_assessment": "Description of potential impact",
                "affected_systems": ["system1", "system2"],
                "affected_data": ["data_type1", "data_type2"],
                "containment_actions": ["action1", "action2"],
                "evidence_collection": ["evidence1", "evidence2"],
                "communication_required": ["stakeholder1", "stakeholder2"],
                "confidence": 0.0
            }, indent=2)
        ]
        
        return "\n".join(prompt_parts)
    
    def _basic_incident_analysis(
        self,
        incident_data: Dict[str, Any],
        context: Dict[str, Any],
        threat_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Basic incident analysis when AI analysis fails."""
        return {
            "classification": incident_data.get("incident_type", "unknown"),
            "severity": incident_data.get("severity", "medium"),
            "root_cause": "Requires manual investigation",
            "impact_assessment": "Impact assessment pending",
            "affected_systems": [incident_data.get("source_ip", "unknown")],
            "affected_data": ["Unknown"],
            "containment_actions": ["Isolate affected systems", "Preserve evidence"],
            "evidence_collection": ["System logs", "Network traffic", "Memory dumps"],
            "communication_required": ["Security team", "Management"],
            "confidence": 0.5
        }
    
    async def _determine_response_strategy(
        self,
        incident_data: Dict[str, Any],
        analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Determine the appropriate response strategy."""
        incident_type = analysis.get("classification", "unknown")
        severity = analysis.get("severity", "medium")
        
        # Get appropriate playbook
        playbook = self.playbooks.get(incident_type, self._generic_playbook)
        
        strategy = {
            "incident_type": incident_type,
            "severity": severity,
            "playbook": incident_type,
            "priority": self._get_priority_from_severity(severity),
            "estimated_duration": self._estimate_response_duration(severity, incident_type),
            "required_team": self._get_required_team(incident_type, severity),
            "escalation_required": severity in ["critical", "high"]
        }
        
        return strategy
    
    def _get_priority_from_severity(self, severity: str) -> int:
        """Convert severity to priority number."""
        priority_mapping = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2
        }
        return priority_mapping.get(severity, 3)
    
    def _estimate_response_duration(self, severity: str, incident_type: str) -> str:
        """Estimate response duration."""
        if severity == "critical":
            return "2-4 hours"
        elif severity == "high":
            return "4-8 hours"
        elif severity == "medium":
            return "1-2 days"
        else:
            return "2-5 days"
    
    def _get_required_team(self, incident_type: str, severity: str) -> List[str]:
        """Get required team members for response."""
        base_team = ["Security Analyst", "Incident Commander"]
        
        if severity in ["critical", "high"]:
            base_team.extend(["Senior Security Analyst", "Legal Counsel"])
        
        if incident_type in ["data_breach", "insider_threat"]:
            base_team.extend(["Privacy Officer", "HR Representative"])
        
        if incident_type == "malware":
            base_team.append("Malware Analyst")
        
        return base_team
    
    async def _execute_response_actions(
        self,
        incident_id: str,
        strategy: Dict[str, Any],
        analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute response actions based on strategy."""
        actions = []
        
        try:
            # Execute playbook
            playbook_name = strategy.get("playbook", "generic")
            playbook_func = self.playbooks.get(playbook_name, self._generic_playbook)
            
            playbook_actions = await playbook_func(incident_id, analysis)
            actions.extend(playbook_actions)
            
            # Add containment actions
            containment_actions = analysis.get("containment_actions", [])
            for action in containment_actions:
                actions.append({
                    "action": action,
                    "status": "pending",
                    "timestamp": datetime.utcnow().isoformat()
                })
            
        except Exception as e:
            logger.error(f"Error executing response actions: {e}")
            actions.append({
                "action": "Error in response execution",
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return actions
    
    async def _create_incident_ticket(
        self,
        incident_data: Dict[str, Any],
        analysis: Dict[str, Any],
        response_actions: List[Dict[str, Any]]
    ) -> Optional[str]:
        """Create incident ticket in Jira."""
        try:
            summary = f"Security Incident: {analysis.get('classification', 'Unknown')} - {incident_data.get('incident_id', 'Unknown')}"
            
            description = f"""
Incident ID: {incident_data.get('incident_id', 'Unknown')}
Classification: {analysis.get('classification', 'Unknown')}
Severity: {analysis.get('severity', 'Unknown')}
Root Cause: {analysis.get('root_cause', 'Under investigation')}

Impact Assessment:
{analysis.get('impact_assessment', 'Assessment pending')}

Affected Systems:
{', '.join(analysis.get('affected_systems', ['Unknown']))}

Response Actions:
{chr(10).join([f"- {action['action']}" for action in response_actions])}

Threat Intelligence:
{json.dumps(incident_data.get('threat_intel', {}), indent=2)}
"""
            
            ticket_key = await self.jira_manager.create_incident_ticket(
                incident_id=incident_data.get('incident_id', 'unknown'),
                summary=summary,
                description=description,
                severity=analysis.get('severity', 'Medium'),
                assignee=None
            )
            
            return ticket_key
            
        except Exception as e:
            logger.error(f"Error creating incident ticket: {e}")
            return None
    
    # Playbook implementations
    async def _malware_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Malware incident response playbook."""
        return [
            {"action": "Isolate affected systems", "status": "pending"},
            {"action": "Collect malware samples", "status": "pending"},
            {"action": "Analyze malware behavior", "status": "pending"},
            {"action": "Update antivirus signatures", "status": "pending"},
            {"action": "Scan network for similar infections", "status": "pending"}
        ]
    
    async def _phishing_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Phishing incident response playbook."""
        return [
            {"action": "Block malicious URLs/domains", "status": "pending"},
            {"action": "Quarantine suspicious emails", "status": "pending"},
            {"action": "Notify affected users", "status": "pending"},
            {"action": "Reset compromised credentials", "status": "pending"},
            {"action": "Conduct security awareness training", "status": "pending"}
        ]
    
    async def _ddos_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """DDoS incident response playbook."""
        return [
            {"action": "Activate DDoS mitigation", "status": "pending"},
            {"action": "Block malicious IPs", "status": "pending"},
            {"action": "Scale up resources", "status": "pending"},
            {"action": "Monitor network traffic", "status": "pending"},
            {"action": "Coordinate with ISP", "status": "pending"}
        ]
    
    async def _data_breach_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Data breach incident response playbook."""
        return [
            {"action": "Contain the breach", "status": "pending"},
            {"action": "Assess data exposure", "status": "pending"},
            {"action": "Notify legal team", "status": "pending"},
            {"action": "Prepare breach notification", "status": "pending"},
            {"action": "Implement additional controls", "status": "pending"}
        ]
    
    async def _insider_threat_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Insider threat incident response playbook."""
        return [
            {"action": "Revoke access privileges", "status": "pending"},
            {"action": "Preserve evidence", "status": "pending"},
            {"action": "Notify HR and legal", "status": "pending"},
            {"action": "Monitor user activity", "status": "pending"},
            {"action": "Conduct investigation", "status": "pending"}
        ]
    
    async def _generic_playbook(self, incident_id: str, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generic incident response playbook."""
        return [
            {"action": "Assess the situation", "status": "pending"},
            {"action": "Contain the threat", "status": "pending"},
            {"action": "Preserve evidence", "status": "pending"},
            {"action": "Investigate root cause", "status": "pending"},
            {"action": "Implement remediation", "status": "pending"}
        ]
    
    async def _create_incident(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident."""
        # Implementation for creating incidents
        return {"status": "created", "incident_id": input_data.get("incident_id")}
    
    async def _update_incident(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing incident."""
        # Implementation for updating incidents
        return {"status": "updated", "incident_id": input_data.get("incident_id")}
    
    async def _execute_playbook(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific playbook."""
        playbook_name = input_data.get("playbook_name")
        incident_id = input_data.get("incident_id")
        
        if playbook_name in self.playbooks:
            playbook_func = self.playbooks[playbook_name]
            actions = await playbook_func(incident_id, input_data)
            return {"status": "executed", "actions": actions}
        else:
            raise ValueError(f"Unknown playbook: {playbook_name}")