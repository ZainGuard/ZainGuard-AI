#!/usr/bin/env python3
"""
Custom Agent Example for ZainGuard AI Platform.

This example demonstrates how to create a custom security agent that:
1. Extends the BaseAgent class
2. Implements custom task processing logic
3. Uses custom tools
4. Integrates with the agent manager
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from loguru import logger

from src.core.agent_manager import BaseAgent, AgentTask
from src.core.llm_interface import LLMInterface
from src.core.agent_manager import agent_manager


class VulnerabilityScannerAgent(BaseAgent):
    """Custom agent for vulnerability scanning and management."""
    
    def __init__(
        self,
        agent_id: str,
        name: str = "Vulnerability Scanner Agent",
        description: str = "Scans and manages security vulnerabilities",
        llm_interface: Optional[LLMInterface] = None
    ):
        super().__init__(agent_id, name, description, llm_interface)
        
        # Initialize custom tools
        self.register_tool("scan_host", self._scan_host)
        self.register_tool("get_vulnerability_details", self._get_vulnerability_details)
        self.register_tool("prioritize_vulnerabilities", self._prioritize_vulnerabilities)
        self.register_tool("generate_remediation_plan", self._generate_remediation_plan)
        
        # Vulnerability severity mapping
        self.severity_scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2,
            "info": 1
        }
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        return list(self.tools.keys())
    
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process a vulnerability scanning task."""
        try:
            task_type = task.task_type
            input_data = task.input_data
            
            if task_type == "scan_network":
                return await self._scan_network(input_data)
            elif task_type == "analyze_vulnerability":
                return await self._analyze_vulnerability(input_data)
            elif task_type == "prioritize_vulnerabilities":
                return await self._prioritize_vulnerabilities_task(input_data)
            elif task_type == "generate_remediation":
                return await self._generate_remediation_task(input_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Error processing vulnerability task: {e}")
            raise
    
    async def _scan_network(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a network for vulnerabilities."""
        try:
            network_range = input_data.get("network_range", "192.168.1.0/24")
            scan_type = input_data.get("scan_type", "comprehensive")
            
            logger.info(f"Scanning network {network_range} with {scan_type} scan")
            
            # Simulate network scanning
            scan_results = await self._simulate_network_scan(network_range, scan_type)
            
            # Analyze results with AI
            analysis = await self._analyze_scan_results(scan_results)
            
            return {
                "network_range": network_range,
                "scan_type": scan_type,
                "vulnerabilities_found": len(scan_results),
                "scan_results": scan_results,
                "analysis": analysis,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            raise
    
    async def _simulate_network_scan(self, network_range: str, scan_type: str) -> List[Dict[str, Any]]:
        """Simulate a network vulnerability scan."""
        # This is a simulation - in a real implementation, you would integrate
        # with tools like Nessus, OpenVAS, or Nmap
        
        vulnerabilities = [
            {
                "host": "192.168.1.10",
                "port": 80,
                "service": "http",
                "vulnerability": "CVE-2023-1234",
                "severity": "high",
                "description": "SQL injection vulnerability in web application",
                "cvss_score": 8.5
            },
            {
                "host": "192.168.1.15",
                "port": 22,
                "service": "ssh",
                "vulnerability": "CVE-2023-5678",
                "severity": "medium",
                "description": "Weak SSH configuration allows brute force attacks",
                "cvss_score": 5.3
            },
            {
                "host": "192.168.1.20",
                "port": 445,
                "service": "smb",
                "vulnerability": "CVE-2023-9012",
                "severity": "critical",
                "description": "Remote code execution vulnerability in SMB service",
                "cvss_score": 9.8
            }
        ]
        
        # Simulate scan delay
        await asyncio.sleep(2)
        
        return vulnerabilities
    
    async def _analyze_scan_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze scan results using AI."""
        try:
            # Prepare context for AI analysis
            context = self._prepare_scan_context(scan_results)
            
            # Create analysis prompt
            prompt = f"""
Analyze the following vulnerability scan results and provide:

1. Overall risk assessment
2. Critical vulnerabilities that need immediate attention
3. Recommended remediation priorities
4. Business impact assessment
5. Timeline for remediation

Scan Results:
{json.dumps(scan_results, indent=2)}

Provide your analysis in JSON format.
"""
            
            messages = [
                {
                    "role": "system",
                    "content": """You are a senior vulnerability management analyst. 
                    Analyze vulnerability scan results and provide actionable recommendations 
                    for remediation prioritization and risk management."""
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
                analysis = self._basic_vulnerability_analysis(scan_results)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing scan results: {e}")
            return self._basic_vulnerability_analysis(scan_results)
    
    def _prepare_scan_context(self, scan_results: List[Dict[str, Any]]) -> str:
        """Prepare context for AI analysis."""
        context_parts = [
            f"Total vulnerabilities found: {len(scan_results)}",
            "Vulnerability breakdown by severity:"
        ]
        
        severity_counts = {}
        for vuln in scan_results:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            context_parts.append(f"  {severity}: {count}")
        
        context_parts.append("\nDetailed vulnerability information:")
        for vuln in scan_results:
            context_parts.append(f"- {vuln['vulnerability']} on {vuln['host']}:{vuln['port']} ({vuln['severity']})")
        
        return "\n".join(context_parts)
    
    def _basic_vulnerability_analysis(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Basic vulnerability analysis when AI analysis fails."""
        critical_count = len([v for v in scan_results if v.get("severity") == "critical"])
        high_count = len([v for v in scan_results if v.get("severity") == "high"])
        
        risk_level = "low"
        if critical_count > 0:
            risk_level = "critical"
        elif high_count > 2:
            risk_level = "high"
        elif high_count > 0:
            risk_level = "medium"
        
        return {
            "overall_risk": risk_level,
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "recommendations": [
                "Address critical vulnerabilities immediately",
                "Implement regular vulnerability scanning",
                "Establish patch management process"
            ],
            "remediation_timeline": "1-2 weeks for critical, 1 month for high priority"
        }
    
    async def _analyze_vulnerability(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a specific vulnerability."""
        try:
            cve_id = input_data.get("cve_id")
            host = input_data.get("host")
            
            logger.info(f"Analyzing vulnerability {cve_id} on {host}")
            
            # Get vulnerability details
            vuln_details = await self._get_vulnerability_details(cve_id)
            
            # Generate remediation plan
            remediation = await self._generate_remediation_plan(vuln_details)
            
            return {
                "cve_id": cve_id,
                "host": host,
                "vulnerability_details": vuln_details,
                "remediation_plan": remediation,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {e}")
            raise
    
    async def _prioritize_vulnerabilities_task(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prioritize a list of vulnerabilities."""
        try:
            vulnerabilities = input_data.get("vulnerabilities", [])
            
            # Sort by severity and CVSS score
            prioritized = sorted(
                vulnerabilities,
                key=lambda v: (
                    self.severity_scores.get(v.get("severity", "info"), 0),
                    v.get("cvss_score", 0)
                ),
                reverse=True
            )
            
            return {
                "total_vulnerabilities": len(vulnerabilities),
                "prioritized_list": prioritized,
                "priority_justification": "Prioritized by severity and CVSS score"
            }
            
        except Exception as e:
            logger.error(f"Error prioritizing vulnerabilities: {e}")
            raise
    
    async def _generate_remediation_task(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a remediation plan for vulnerabilities."""
        try:
            vulnerabilities = input_data.get("vulnerabilities", [])
            timeline = input_data.get("timeline", "30 days")
            
            # Group vulnerabilities by severity
            grouped = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info")
                if severity not in grouped:
                    grouped[severity] = []
                grouped[severity].append(vuln)
            
            # Generate remediation phases
            phases = []
            if "critical" in grouped:
                phases.append({
                    "phase": "Immediate (0-7 days)",
                    "vulnerabilities": grouped["critical"],
                    "actions": ["Emergency patching", "System isolation if needed"]
                })
            
            if "high" in grouped:
                phases.append({
                    "phase": "High Priority (1-2 weeks)",
                    "vulnerabilities": grouped["high"],
                    "actions": ["Scheduled patching", "Configuration updates"]
                })
            
            if "medium" in grouped:
                phases.append({
                    "phase": "Medium Priority (2-4 weeks)",
                    "vulnerabilities": grouped["medium"],
                    "actions": ["Regular patching cycle", "Security hardening"]
                })
            
            return {
                "remediation_plan": {
                    "timeline": timeline,
                    "phases": phases,
                    "total_vulnerabilities": len(vulnerabilities)
                },
                "estimated_effort": f"{len(vulnerabilities) * 2} hours",
                "resources_required": ["Security team", "System administrators"]
            }
            
        except Exception as e:
            logger.error(f"Error generating remediation plan: {e}")
            raise
    
    # Tool implementations
    async def _scan_host(self, host: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """Scan a single host for vulnerabilities."""
        # Simulate host scanning
        await asyncio.sleep(1)
        
        return {
            "host": host,
            "scan_type": scan_type,
            "status": "completed",
            "vulnerabilities_found": 3,
            "scan_duration": "45 seconds"
        }
    
    async def _get_vulnerability_details(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed information about a vulnerability."""
        # Simulate vulnerability database lookup
        await asyncio.sleep(0.5)
        
        return {
            "cve_id": cve_id,
            "title": f"Vulnerability in {cve_id}",
            "description": f"Detailed description of {cve_id}",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_software": ["Software A", "Software B"],
            "published_date": "2024-01-15",
            "last_modified": "2024-01-20"
        }
    
    async def _prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize a list of vulnerabilities."""
        return sorted(
            vulnerabilities,
            key=lambda v: self.severity_scores.get(v.get("severity", "info"), 0),
            reverse=True
        )
    
    async def _generate_remediation_plan(self, vulnerability_details: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a remediation plan for a vulnerability."""
        return {
            "vulnerability": vulnerability_details.get("cve_id"),
            "remediation_steps": [
                "Apply security patch",
                "Update affected software",
                "Verify fix effectiveness",
                "Monitor for similar issues"
            ],
            "estimated_time": "2-4 hours",
            "required_access": "Administrator privileges"
        }


async def main():
    """Main example function."""
    print("🔧 ZainGuard AI Platform - Custom Agent Example")
    print("=" * 50)
    
    # Register the custom agent type
    print("📝 Registering custom agent type...")
    agent_manager.register_agent_type("vulnerability_scanner", VulnerabilityScannerAgent)
    
    # Create the custom agent
    print("🤖 Creating custom vulnerability scanner agent...")
    vuln_agent = agent_manager.create_agent(
        agent_type="vulnerability_scanner",
        agent_id="vuln-scanner-001",
        name="Custom Vulnerability Scanner",
        description="Custom agent for vulnerability scanning and management"
    )
    
    # Start the agent
    print("▶️  Starting agent...")
    await vuln_agent.start()
    
    print(f"Agent created: {vuln_agent.name}")
    print(f"Available tools: {vuln_agent.get_available_tools()}")
    
    # Example 1: Network vulnerability scan
    print("\n🔍 Example 1: Network Vulnerability Scan")
    print("-" * 40)
    
    scan_data = {
        "network_range": "192.168.1.0/24",
        "scan_type": "comprehensive"
    }
    
    print(f"Scanning network: {scan_data['network_range']}")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="vuln-scanner-001",
        task_type="scan_network",
        input_data=scan_data,
        priority=1
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(3)
    
    # Check results
    status = agent_manager.get_task_status("vuln-scanner-001", task_id)
    if status and status['result']:
        result = status['result']
        print(f"Scan completed: {result['vulnerabilities_found']} vulnerabilities found")
        print(f"Risk assessment: {result['analysis'].get('overall_risk', 'unknown')}")
    
    # Example 2: Vulnerability analysis
    print("\n🔬 Example 2: Vulnerability Analysis")
    print("-" * 40)
    
    vuln_data = {
        "cve_id": "CVE-2023-1234",
        "host": "192.168.1.10"
    }
    
    print(f"Analyzing vulnerability: {vuln_data['cve_id']}")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="vuln-scanner-001",
        task_type="analyze_vulnerability",
        input_data=vuln_data,
        priority=2
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(2)
    
    # Check results
    status = agent_manager.get_task_status("vuln-scanner-001", task_id)
    if status and status['result']:
        result = status['result']
        print(f"Analysis completed for {result['cve_id']}")
        print(f"Remediation plan: {len(result['remediation_plan']['remediation_steps'])} steps")
    
    # Example 3: Vulnerability prioritization
    print("\n📊 Example 3: Vulnerability Prioritization")
    print("-" * 40)
    
    vulnerabilities = [
        {"cve_id": "CVE-2023-001", "severity": "medium", "cvss_score": 5.5},
        {"cve_id": "CVE-2023-002", "severity": "critical", "cvss_score": 9.8},
        {"cve_id": "CVE-2023-003", "severity": "high", "cvss_score": 7.2},
        {"cve_id": "CVE-2023-004", "severity": "low", "cvss_score": 3.1}
    ]
    
    print(f"Prioritizing {len(vulnerabilities)} vulnerabilities...")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="vuln-scanner-001",
        task_type="prioritize_vulnerabilities",
        input_data={"vulnerabilities": vulnerabilities},
        priority=3
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(1)
    
    # Check results
    status = agent_manager.get_task_status("vuln-scanner-001", task_id)
    if status and status['result']:
        result = status['result']
        print(f"Prioritization completed:")
        for i, vuln in enumerate(result['prioritized_list'][:3], 1):
            print(f"  {i}. {vuln['cve_id']} ({vuln['severity']}) - CVSS: {vuln['cvss_score']}")
    
    # Example 4: Generate remediation plan
    print("\n📋 Example 4: Generate Remediation Plan")
    print("-" * 40)
    
    remediation_data = {
        "vulnerabilities": vulnerabilities,
        "timeline": "30 days"
    }
    
    print("Generating remediation plan...")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="vuln-scanner-001",
        task_type="generate_remediation",
        input_data=remediation_data,
        priority=2
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(2)
    
    # Check results
    status = agent_manager.get_task_status("vuln-scanner-001", task_id)
    if status and status['result']:
        result = status['result']
        plan = result['remediation_plan']
        print(f"Remediation plan generated:")
        print(f"  Timeline: {plan['timeline']}")
        print(f"  Phases: {len(plan['phases'])}")
        print(f"  Total vulnerabilities: {plan['total_vulnerabilities']}")
        print(f"  Estimated effort: {result['estimated_effort']}")
    
    # Stop the agent
    print("\n⏹️  Stopping agent...")
    await vuln_agent.stop()
    
    print("\n✅ Custom agent example completed successfully!")
    print("\nKey takeaways:")
    print("1. Custom agents extend BaseAgent class")
    print("2. Implement process_task() and get_available_tools() methods")
    print("3. Register custom tools using register_tool()")
    print("4. Use AI for intelligent analysis and recommendations")
    print("5. Handle errors gracefully with proper logging")


if __name__ == "__main__":
    asyncio.run(main())