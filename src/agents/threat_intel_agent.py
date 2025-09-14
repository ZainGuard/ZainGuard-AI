"""Threat intelligence agent for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime, timedelta
from loguru import logger

from ..core.agent_manager import BaseAgent, AgentTask
from ..core.llm_interface import LLMInterface
from ..tools.threat_intel_api import ThreatIntelAPI
from ..core.database_connector import db_connector


class ThreatIntelAgent(BaseAgent):
    """AI agent for threat intelligence gathering and analysis."""
    
    def __init__(
        self,
        agent_id: str,
        name: str = "Threat Intelligence Agent",
        description: str = "Automated threat intelligence gathering and analysis",
        llm_interface: Optional[LLMInterface] = None
    ):
        super().__init__(agent_id, name, description, llm_interface)
        
        # Initialize tools
        self.threat_intel = ThreatIntelAPI()
        
        # Register tools
        self.register_tool("check_ip_reputation", self.threat_intel.check_ip_reputation)
        self.register_tool("check_domain_reputation", self.threat_intel.check_domain_reputation)
        self.register_tool("check_file_hash", self.threat_intel.check_file_hash)
        self.register_tool("get_threat_feed", self.threat_intel.get_threat_feed)
        self.register_tool("search_threat_actors", self.threat_intel.search_threat_actors)
        self.register_tool("get_malware_families", self.threat_intel.get_malware_families)
        
        # Threat intelligence categories
        self.threat_categories = [
            "malware", "phishing", "apt", "ransomware", "botnet",
            "command_and_control", "data_exfiltration", "insider_threat"
        ]
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        return list(self.tools.keys())
    
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process a threat intelligence task."""
        try:
            task_type = task.task_type
            input_data = task.input_data
            
            if task_type == "analyze_ioc":
                return await self._analyze_ioc(input_data)
            elif task_type == "bulk_ioc_analysis":
                return await self._bulk_ioc_analysis(input_data)
            elif task_type == "threat_hunting":
                return await self._threat_hunting(input_data)
            elif task_type == "update_threat_feed":
                return await self._update_threat_feed(input_data)
            elif task_type == "generate_threat_report":
                return await self._generate_threat_report(input_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Error processing threat intel task: {e}")
            raise
    
    async def _analyze_ioc(self, ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single indicator of compromise."""
        try:
            ioc_type = ioc_data.get("type")
            ioc_value = ioc_data.get("value")
            
            if not ioc_type or not ioc_value:
                raise ValueError("IOC type and value are required")
            
            logger.info(f"Analyzing {ioc_type}: {ioc_value}")
            
            # Get threat intelligence data
            threat_data = await self._gather_ioc_intelligence(ioc_type, ioc_value)
            
            # Perform AI analysis
            analysis = await self._analyze_threat_data(ioc_type, ioc_value, threat_data)
            
            # Store in knowledge base
            await self._store_threat_intelligence(ioc_type, ioc_value, threat_data, analysis)
            
            return {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "threat_data": threat_data,
                "analysis": analysis,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing IOC: {e}")
            raise
    
    async def _gather_ioc_intelligence(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Gather threat intelligence for an IOC."""
        threat_data = {}
        
        try:
            if ioc_type == "ip":
                threat_data = await self.threat_intel.check_ip_reputation(ioc_value)
            elif ioc_type == "domain":
                threat_data = await self.threat_intel.check_domain_reputation(ioc_value)
            elif ioc_type in ["md5", "sha1", "sha256"]:
                threat_data = await self.threat_intel.check_file_hash(ioc_value)
            else:
                logger.warning(f"Unsupported IOC type: {ioc_type}")
        
        except Exception as e:
            logger.warning(f"Error gathering intelligence for {ioc_type}:{ioc_value}: {e}")
        
        return threat_data
    
    async def _analyze_threat_data(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze threat data using AI."""
        try:
            # Create analysis prompt
            prompt = self._create_threat_analysis_prompt(ioc_type, ioc_value, threat_data)
            
            messages = [
                {
                    "role": "system",
                    "content": """You are a threat intelligence analyst. Analyze the provided IOC and threat intelligence data to determine:
                    1. Threat level (critical, high, medium, low, benign)
                    2. Threat category (malware, phishing, apt, etc.)
                    3. Confidence level (0.0 to 1.0)
                    4. Risk assessment
                    5. Recommended actions
                    6. Attribution information if available
                    
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
                analysis = self._basic_threat_analysis(ioc_type, ioc_value, threat_data)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing threat data: {e}")
            return self._basic_threat_analysis(ioc_type, ioc_value, threat_data)
    
    def _create_threat_analysis_prompt(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_data: Dict[str, Any]
    ) -> str:
        """Create threat analysis prompt for the LLM."""
        prompt_parts = [
            f"Analyze the following {ioc_type.upper()} indicator of compromise:",
            f"IOC Value: {ioc_value}",
            f"IOC Type: {ioc_type}",
            "",
            "Threat Intelligence Data:",
            json.dumps(threat_data, indent=2),
            "",
            "Please provide your analysis in the following JSON format:",
            json.dumps({
                "threat_level": "critical|high|medium|low|benign",
                "threat_category": "malware|phishing|apt|ransomware|botnet|other",
                "confidence": 0.0,
                "risk_assessment": "Brief risk assessment",
                "recommended_actions": ["action1", "action2"],
                "attribution": "Attribution information if available",
                "first_seen": "Date if available",
                "last_seen": "Date if available",
                "related_campaigns": ["campaign1", "campaign2"],
                "ioc_relationships": ["related_ioc1", "related_ioc2"]
            }, indent=2)
        ]
        
        return "\n".join(prompt_parts)
    
    def _basic_threat_analysis(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Basic threat analysis when AI analysis fails."""
        threat_level = "low"
        confidence = 0.5
        
        # Check if any source indicates malicious activity
        if threat_data.get("malicious", False):
            threat_level = "high"
            confidence = 0.8
        
        # Check detection counts
        sources = threat_data.get("sources", {})
        for source, data in sources.items():
            if isinstance(data, dict) and data.get("malicious", False):
                threat_level = "high"
                confidence = max(confidence, data.get("confidence", 0.5))
        
        return {
            "threat_level": threat_level,
            "threat_category": "unknown",
            "confidence": confidence,
            "risk_assessment": "Requires manual review",
            "recommended_actions": ["Monitor for additional activity", "Block if confirmed malicious"],
            "attribution": "Unknown",
            "first_seen": None,
            "last_seen": None,
            "related_campaigns": [],
            "ioc_relationships": []
        }
    
    async def _store_threat_intelligence(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_data: Dict[str, Any],
        analysis: Dict[str, Any]
    ) -> str:
        """Store threat intelligence in the knowledge base."""
        try:
            document = {
                "title": f"Threat Intelligence: {ioc_type.upper()} - {ioc_value}",
                "content": f"""
IOC Type: {ioc_type}
IOC Value: {ioc_value}
Threat Level: {analysis.get('threat_level', 'unknown')}
Threat Category: {analysis.get('threat_category', 'unknown')}
Confidence: {analysis.get('confidence', 0.0)}

Threat Intelligence Data:
{json.dumps(threat_data, indent=2)}

Analysis:
{json.dumps(analysis, indent=2)}
""",
                "category": "threat_intelligence",
                "tags": [
                    f"ioc_{ioc_type}",
                    f"threat_{analysis.get('threat_level', 'unknown')}",
                    f"category_{analysis.get('threat_category', 'unknown')}"
                ],
                "source": "threat_intel_agent"
            }
            
            doc_id = await db_connector.save_knowledge_document(document)
            return doc_id
            
        except Exception as e:
            logger.error(f"Error storing threat intelligence: {e}")
            return None
    
    async def _bulk_ioc_analysis(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze multiple IOCs in bulk."""
        iocs = input_data.get("iocs", [])
        results = []
        
        for ioc in iocs:
            try:
                result = await self._analyze_ioc(ioc)
                results.append({
                    "ioc": ioc,
                    "status": "success",
                    "result": result
                })
            except Exception as e:
                results.append({
                    "ioc": ioc,
                    "status": "error",
                    "error": str(e)
                })
        
        return {
            "total_iocs": len(iocs),
            "successful": len([r for r in results if r["status"] == "success"]),
            "failed": len([r for r in results if r["status"] == "error"]),
            "results": results
        }
    
    async def _threat_hunting(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat hunting based on provided criteria."""
        try:
            hunt_criteria = input_data.get("criteria", {})
            time_range = input_data.get("time_range", 24)  # hours
            
            # Search for IOCs in the knowledge base
            search_queries = self._build_hunt_queries(hunt_criteria)
            
            findings = []
            for query in search_queries:
                results = await db_connector.search_knowledge(query, k=10)
                findings.extend(results)
            
            # Analyze findings
            analysis = await self._analyze_hunt_findings(findings, hunt_criteria)
            
            return {
                "hunt_criteria": hunt_criteria,
                "time_range": time_range,
                "findings_count": len(findings),
                "findings": findings,
                "analysis": analysis,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in threat hunting: {e}")
            raise
    
    def _build_hunt_queries(self, criteria: Dict[str, Any]) -> List[str]:
        """Build search queries for threat hunting."""
        queries = []
        
        if criteria.get("threat_category"):
            queries.append(f"threat_category:{criteria['threat_category']}")
        
        if criteria.get("threat_level"):
            queries.append(f"threat_level:{criteria['threat_level']}")
        
        if criteria.get("ioc_type"):
            queries.append(f"ioc_type:{criteria['ioc_type']}")
        
        if criteria.get("attribution"):
            queries.append(f"attribution:{criteria['attribution']}")
        
        # Add generic threat hunting queries
        queries.extend([
            "malicious true",
            "threat_level:high OR threat_level:critical",
            "threat_category:apt OR threat_category:ransomware"
        ])
        
        return queries
    
    async def _analyze_hunt_findings(
        self,
        findings: List[Dict[str, Any]],
        criteria: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze threat hunting findings."""
        if not findings:
            return {
                "summary": "No findings matching hunt criteria",
                "risk_level": "low",
                "recommendations": ["Continue monitoring"]
            }
        
        # Count findings by category
        category_counts = {}
        threat_levels = []
        
        for finding in findings:
            metadata = finding.get("metadata", {})
            category = metadata.get("threat_category", "unknown")
            threat_level = metadata.get("threat_level", "unknown")
            
            category_counts[category] = category_counts.get(category, 0) + 1
            threat_levels.append(threat_level)
        
        # Determine overall risk level
        if "critical" in threat_levels:
            risk_level = "critical"
        elif "high" in threat_levels:
            risk_level = "high"
        elif "medium" in threat_levels:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "summary": f"Found {len(findings)} potential threats",
            "risk_level": risk_level,
            "category_breakdown": category_counts,
            "threat_levels": list(set(threat_levels)),
            "recommendations": self._generate_hunt_recommendations(findings, risk_level)
        }
    
    def _generate_hunt_recommendations(
        self,
        findings: List[Dict[str, Any]],
        risk_level: str
    ) -> List[str]:
        """Generate recommendations based on hunt findings."""
        recommendations = []
        
        if risk_level in ["critical", "high"]:
            recommendations.extend([
                "Immediately investigate high-priority findings",
                "Implement additional monitoring",
                "Consider incident response procedures"
            ])
        
        if len(findings) > 10:
            recommendations.append("High volume of findings - consider automated filtering")
        
        # Check for specific threat categories
        categories = set()
        for finding in findings:
            metadata = finding.get("metadata", {})
            category = metadata.get("threat_category")
            if category:
                categories.add(category)
        
        if "apt" in categories:
            recommendations.append("APT activity detected - escalate to senior analysts")
        
        if "ransomware" in categories:
            recommendations.append("Ransomware indicators - check backup systems")
        
        return recommendations
    
    async def _update_threat_feed(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update threat intelligence feeds."""
        try:
            feed_type = input_data.get("feed_type", "malware")
            
            # Get threat feed data
            feed_data = await self.threat_intel.get_threat_feed(feed_type)
            
            # Process and store feed data
            processed_count = 0
            for item in feed_data:
                try:
                    # Store in knowledge base
                    document = {
                        "title": f"Threat Feed: {item.get('title', 'Unknown')}",
                        "content": json.dumps(item, indent=2),
                        "category": "threat_feed",
                        "tags": [feed_type, "threat_feed"],
                        "source": "threat_intel_agent"
                    }
                    
                    await db_connector.save_knowledge_document(document)
                    processed_count += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing feed item: {e}")
            
            return {
                "feed_type": feed_type,
                "items_processed": processed_count,
                "total_items": len(feed_data),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating threat feed: {e}")
            raise
    
    async def _generate_threat_report(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a threat intelligence report."""
        try:
            report_type = input_data.get("report_type", "summary")
            time_range = input_data.get("time_range", 7)  # days
            
            # Gather threat data
            threat_data = await self._gather_report_data(time_range)
            
            # Generate AI-powered report
            report = await self._generate_ai_report(threat_data, report_type)
            
            return {
                "report_type": report_type,
                "time_range": time_range,
                "threat_data": threat_data,
                "report": report,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating threat report: {e}")
            raise
    
    async def _gather_report_data(self, time_range: int) -> Dict[str, Any]:
        """Gather data for threat report."""
        # This would typically query the database for recent threat intelligence
        # For now, return a placeholder structure
        return {
            "total_iocs_analyzed": 0,
            "threat_categories": {},
            "threat_levels": {},
            "top_indicators": [],
            "attribution_data": {}
        }
    
    async def _generate_ai_report(
        self,
        threat_data: Dict[str, Any],
        report_type: str
    ) -> Dict[str, Any]:
        """Generate AI-powered threat report."""
        try:
            prompt = f"""
Generate a {report_type} threat intelligence report based on the following data:

{json.dumps(threat_data, indent=2)}

The report should include:
1. Executive summary
2. Key findings
3. Threat landscape overview
4. Recommendations
5. Next steps

Format the report in JSON with clear sections.
"""
            
            messages = [
                {
                    "role": "system",
                    "content": "You are a threat intelligence analyst creating a professional report."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            report_response = await self.llm_interface.generate_response(messages)
            
            try:
                return json.loads(report_response)
            except json.JSONDecodeError:
                return {
                    "executive_summary": "Report generation in progress",
                    "key_findings": [],
                    "recommendations": ["Manual review required"]
                }
                
        except Exception as e:
            logger.error(f"Error generating AI report: {e}")
            return {
                "executive_summary": "Report generation failed",
                "key_findings": [],
                "recommendations": ["Manual review required"]
            }