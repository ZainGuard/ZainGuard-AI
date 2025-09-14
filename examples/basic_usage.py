#!/usr/bin/env python3
"""
Basic usage example for ZainGuard AI Platform.

This example demonstrates how to:
1. Create and start agents
2. Submit tasks to agents
3. Monitor task progress
4. Retrieve results
"""

import asyncio
import json
from datetime import datetime
from src.core.agent_manager import agent_manager
from src.agents.triage_agent import TriageAgent
from src.agents.incident_response_agent import IncidentResponseAgent
from src.agents.threat_intel_agent import ThreatIntelAgent


async def main():
    """Main example function."""
    print("🚀 ZainGuard AI Platform - Basic Usage Example")
    print("=" * 50)
    
    # Register agent types
    print("📝 Registering agent types...")
    agent_manager.register_agent_type("triage", TriageAgent)
    agent_manager.register_agent_type("incident_response", IncidentResponseAgent)
    agent_manager.register_agent_type("threat_intel", ThreatIntelAgent)
    
    # Create agents
    print("🤖 Creating agents...")
    
    # Triage Agent
    triage_agent = agent_manager.create_agent(
        agent_type="triage",
        agent_id="triage-agent-001",
        name="Security Alert Triage Agent",
        description="Automatically triages and prioritizes security alerts"
    )
    
    # Incident Response Agent
    incident_agent = agent_manager.create_agent(
        agent_type="incident_response",
        agent_id="incident-agent-001",
        name="Incident Response Agent",
        description="Handles security incident response and management"
    )
    
    # Threat Intelligence Agent
    threat_agent = agent_manager.create_agent(
        agent_type="threat_intel",
        agent_id="threat-agent-001",
        name="Threat Intelligence Agent",
        description="Gathers and analyzes threat intelligence data"
    )
    
    # Start all agents
    print("▶️  Starting agents...")
    await agent_manager.start_all_agents()
    
    # List all agents
    print("\n📋 Available agents:")
    agents = agent_manager.list_agents()
    for agent in agents:
        print(f"  - {agent['name']} ({agent['agent_id']})")
        print(f"    Status: {'Running' if agent['is_running'] else 'Stopped'}")
        print(f"    Tools: {len(agent['available_tools'])}")
    
    # Example 1: Triage a security alert
    print("\n🔍 Example 1: Triage Security Alert")
    print("-" * 40)
    
    alert_data = {
        "alert_id": "ALERT-2024-001",
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.50",
        "severity": "medium",
        "description": "Multiple failed login attempts from external IP",
        "timestamp": datetime.utcnow().isoformat(),
        "raw_data": {
            "user": "admin",
            "attempts": 5,
            "time_window": "5 minutes"
        }
    }
    
    print(f"Submitting alert: {alert_data['alert_id']}")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="triage-agent-001",
        task_type="triage_alert",
        input_data=alert_data,
        priority=1
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    print("⏳ Waiting for processing...")
    await asyncio.sleep(3)
    
    # Check task status
    status = agent_manager.get_task_status("triage-agent-001", task_id)
    if status:
        print(f"Task status: {status['status']}")
        if status['result']:
            print(f"Triage result: {json.dumps(status['result'], indent=2)}")
    
    # Example 2: Analyze threat intelligence
    print("\n🕵️  Example 2: Threat Intelligence Analysis")
    print("-" * 40)
    
    ioc_data = {
        "type": "ip",
        "value": "8.8.8.8"  # Using a known safe IP for testing
    }
    
    print(f"Analyzing IOC: {ioc_data['type']} - {ioc_data['value']}")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="threat-agent-001",
        task_type="analyze_ioc",
        input_data=ioc_data,
        priority=2
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(3)
    
    # Check task status
    status = agent_manager.get_task_status("threat-agent-001", task_id)
    if status:
        print(f"Task status: {status['status']}")
        if status['result']:
            print(f"Analysis result: {json.dumps(status['result'], indent=2)}")
    
    # Example 3: Incident Response
    print("\n🚨 Example 3: Incident Response")
    print("-" * 40)
    
    incident_data = {
        "incident_id": "INC-2024-001",
        "incident_type": "malware",
        "severity": "high",
        "description": "Malware detected on multiple workstations",
        "affected_systems": ["WS-001", "WS-002", "WS-003"],
        "source_ip": "192.168.1.100",
        "malware_hash": "a1b2c3d4e5f6...",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    print(f"Responding to incident: {incident_data['incident_id']}")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="incident-agent-001",
        task_type="respond_to_incident",
        input_data=incident_data,
        priority=1
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(5)
    
    # Check task status
    status = agent_manager.get_task_status("incident-agent-001", task_id)
    if status:
        print(f"Task status: {status['status']}")
        if status['result']:
            print(f"Response result: {json.dumps(status['result'], indent=2)}")
    
    # Example 4: Bulk IOC Analysis
    print("\n📊 Example 4: Bulk IOC Analysis")
    print("-" * 40)
    
    iocs = [
        {"type": "ip", "value": "1.2.3.4"},
        {"type": "domain", "value": "example.com"},
        {"type": "md5", "value": "5d41402abc4b2a76b9719d911017c592"}
    ]
    
    print(f"Analyzing {len(iocs)} IOCs in bulk...")
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="threat-agent-001",
        task_type="bulk_ioc_analysis",
        input_data={"iocs": iocs},
        priority=3
    )
    print(f"Task submitted: {task_id}")
    
    # Wait for processing
    await asyncio.sleep(5)
    
    # Check task status
    status = agent_manager.get_task_status("threat-agent-001", task_id)
    if status:
        print(f"Task status: {status['status']}")
        if status['result']:
            result = status['result']
            print(f"Bulk analysis completed:")
            print(f"  Total IOCs: {result['total_iocs']}")
            print(f"  Successful: {result['successful']}")
            print(f"  Failed: {result['failed']}")
    
    # Get agent metrics
    print("\n📈 Agent Metrics")
    print("-" * 40)
    
    for agent_info in agents:
        metrics = agent_manager.get_agent_metrics(agent_info['agent_id'])
        if metrics:
            print(f"\n{metrics['name']}:")
            print(f"  Current tasks: {metrics['current_tasks']}")
            print(f"  Available tools: {metrics['available_tools']}")
            print(f"  Running: {metrics['is_running']}")
    
    # Stop all agents
    print("\n⏹️  Stopping agents...")
    await agent_manager.stop_all_agents()
    
    print("\n✅ Example completed successfully!")
    print("\nNext steps:")
    print("1. Check the API documentation at http://localhost:8000/docs")
    print("2. Explore the examples in the examples/ directory")
    print("3. Read the documentation in docs/")
    print("4. Start building your own custom agents!")


if __name__ == "__main__":
    asyncio.run(main())