"""Tool management endpoints."""

from fastapi import APIRouter, HTTPException
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from loguru import logger

from ...tools.siem_connector import SIEMConnector
from ...tools.threat_intel_api import ThreatIntelAPI
from ...tools.jira_manager import JiraManager

router = APIRouter()


class ToolTestRequest(BaseModel):
    parameters: Dict[str, Any]


@router.get("/tools")
async def list_available_tools():
    """List all available tools."""
    return {
        "tools": [
            {
                "name": "siem_connector",
                "description": "Security Information and Event Management connector",
                "endpoints": [
                    "search_logs",
                    "get_alert_details",
                    "update_alert_status",
                    "get_alerts_by_status",
                    "get_high_priority_alerts",
                    "get_security_events",
                    "test_query"
                ]
            },
            {
                "name": "threat_intel_api",
                "description": "Threat intelligence API connector",
                "endpoints": [
                    "check_ip_reputation",
                    "check_domain_reputation",
                    "check_file_hash",
                    "get_threat_feed",
                    "search_threat_actors",
                    "get_malware_families"
                ]
            },
            {
                "name": "jira_manager",
                "description": "Jira ticket management",
                "endpoints": [
                    "create_ticket",
                    "get_ticket",
                    "update_ticket",
                    "add_comment",
                    "transition_ticket",
                    "search_tickets",
                    "create_incident_ticket",
                    "create_vulnerability_ticket"
                ]
            }
        ]
    }


@router.post("/tools/siem/search_logs")
async def siem_search_logs(request: ToolTestRequest):
    """Test SIEM log search."""
    try:
        siem = SIEMConnector()
        result = await siem.search_logs(**request.parameters)
        await siem.close()
        
        return {
            "tool": "siem_connector",
            "function": "search_logs",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing SIEM search: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/siem/test_query")
async def siem_test_query(request: ToolTestRequest):
    """Test SIEM query."""
    try:
        siem = SIEMConnector()
        query = request.parameters.get("query", "*")
        result = await siem.test_query(query)
        await siem.close()
        
        return {
            "tool": "siem_connector",
            "function": "test_query",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing SIEM query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/threat_intel/check_ip")
async def threat_intel_check_ip(request: ToolTestRequest):
    """Test threat intelligence IP check."""
    try:
        threat_intel = ThreatIntelAPI()
        ip_address = request.parameters.get("ip_address")
        if not ip_address:
            raise HTTPException(status_code=400, detail="ip_address parameter required")
        
        result = await threat_intel.check_ip_reputation(ip_address)
        await threat_intel.close()
        
        return {
            "tool": "threat_intel_api",
            "function": "check_ip_reputation",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing threat intel IP check: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/threat_intel/check_domain")
async def threat_intel_check_domain(request: ToolTestRequest):
    """Test threat intelligence domain check."""
    try:
        threat_intel = ThreatIntelAPI()
        domain = request.parameters.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="domain parameter required")
        
        result = await threat_intel.check_domain_reputation(domain)
        await threat_intel.close()
        
        return {
            "tool": "threat_intel_api",
            "function": "check_domain_reputation",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing threat intel domain check: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/threat_intel/check_hash")
async def threat_intel_check_hash(request: ToolTestRequest):
    """Test threat intelligence hash check."""
    try:
        threat_intel = ThreatIntelAPI()
        file_hash = request.parameters.get("file_hash")
        if not file_hash:
            raise HTTPException(status_code=400, detail="file_hash parameter required")
        
        result = await threat_intel.check_file_hash(file_hash)
        await threat_intel.close()
        
        return {
            "tool": "threat_intel_api",
            "function": "check_file_hash",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing threat intel hash check: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/jira/create_ticket")
async def jira_create_ticket(request: ToolTestRequest):
    """Test Jira ticket creation."""
    try:
        jira = JiraManager()
        result = await jira.create_ticket(**request.parameters)
        await jira.close()
        
        return {
            "tool": "jira_manager",
            "function": "create_ticket",
            "result": {"ticket_key": result}
        }
    except Exception as e:
        logger.error(f"Error testing Jira ticket creation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/jira/search_tickets")
async def jira_search_tickets(request: ToolTestRequest):
    """Test Jira ticket search."""
    try:
        jira = JiraManager()
        jql = request.parameters.get("jql", "project = SEC")
        result = await jira.search_tickets(jql)
        await jira.close()
        
        return {
            "tool": "jira_manager",
            "function": "search_tickets",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error testing Jira ticket search: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/health")
async def check_tools_health():
    """Check health of all tools."""
    health_status = {
        "siem_connector": {"status": "unknown", "message": "Not tested"},
        "threat_intel_api": {"status": "unknown", "message": "Not tested"},
        "jira_manager": {"status": "unknown", "message": "Not tested"}
    }
    
    # Test SIEM connector
    try:
        siem = SIEMConnector()
        health = await siem.get_siem_health()
        health_status["siem_connector"] = health
        await siem.close()
    except Exception as e:
        health_status["siem_connector"] = {
            "status": "error",
            "message": str(e)
        }
    
    # Test threat intelligence API
    try:
        threat_intel = ThreatIntelAPI()
        # Simple test with a known safe IP
        result = await threat_intel.check_ip_reputation("8.8.8.8")
        health_status["threat_intel_api"] = {
            "status": "healthy",
            "message": "API accessible"
        }
        await threat_intel.close()
    except Exception as e:
        health_status["threat_intel_api"] = {
            "status": "error",
            "message": str(e)
        }
    
    # Test Jira manager
    try:
        jira = JiraManager()
        # Test with a simple search
        result = await jira.search_tickets("project = SEC", max_results=1)
        health_status["jira_manager"] = {
            "status": "healthy",
            "message": "API accessible"
        }
        await jira.close()
    except Exception as e:
        health_status["jira_manager"] = {
            "status": "error",
            "message": str(e)
        }
    
    return health_status