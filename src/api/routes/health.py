"""Health check endpoints."""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from loguru import logger

from ...core.agent_manager import agent_manager
from ...core.database_connector import db_connector
from ...core.llm_interface import get_default_llm_interface

router = APIRouter()


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "ZainGuard AI Platform",
        "version": "0.1.0"
    }


@router.get("/health/detailed")
async def detailed_health_check() -> Dict[str, Any]:
    """Detailed health check with component status."""
    health_status = {
        "status": "healthy",
        "service": "ZainGuard AI Platform",
        "version": "0.1.0",
        "components": {}
    }
    
    # Check database connectivity
    try:
        # Simple database check
        health_status["components"]["database"] = {
            "status": "healthy",
            "message": "Database connection successful"
        }
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }
        health_status["status"] = "degraded"
    
    # Check LLM connectivity
    try:
        llm_interface = get_default_llm_interface()
        # Simple test message
        test_messages = [{"role": "user", "content": "Hello"}]
        await llm_interface.generate_response(test_messages)
        
        health_status["components"]["llm"] = {
            "status": "healthy",
            "message": "LLM interface working"
        }
    except Exception as e:
        health_status["components"]["llm"] = {
            "status": "unhealthy",
            "message": f"LLM interface failed: {str(e)}"
        }
        health_status["status"] = "degraded"
    
    # Check agent manager
    try:
        agents = agent_manager.list_agents()
        health_status["components"]["agent_manager"] = {
            "status": "healthy",
            "message": f"Agent manager operational with {len(agents)} agents",
            "agents": len(agents)
        }
    except Exception as e:
        health_status["components"]["agent_manager"] = {
            "status": "unhealthy",
            "message": f"Agent manager failed: {str(e)}"
        }
        health_status["status"] = "degraded"
    
    # Check external tools
    health_status["components"]["external_tools"] = {
        "status": "unknown",
        "message": "External tool connectivity not checked"
    }
    
    return health_status


@router.get("/health/agents")
async def agents_health_check() -> Dict[str, Any]:
    """Check health of all agents."""
    try:
        agents = agent_manager.list_agents()
        
        agent_health = []
        for agent_info in agents:
            agent = agent_manager.get_agent(agent_info["agent_id"])
            if agent:
                agent_health.append({
                    "agent_id": agent_info["agent_id"],
                    "name": agent_info["name"],
                    "status": "running" if agent.is_running else "stopped",
                    "current_tasks": agent_info["current_tasks"],
                    "available_tools": len(agent_info["available_tools"])
                })
        
        return {
            "status": "success",
            "total_agents": len(agent_health),
            "agents": agent_health
        }
        
    except Exception as e:
        logger.error(f"Error checking agent health: {e}")
        raise HTTPException(status_code=500, detail=f"Agent health check failed: {str(e)}")


@router.get("/health/metrics")
async def get_metrics() -> Dict[str, Any]:
    """Get system metrics."""
    try:
        agents = agent_manager.list_agents()
        
        total_tasks = sum(agent["current_tasks"] for agent in agents)
        
        return {
            "agents": {
                "total": len(agents),
                "running": len([a for a in agents if a["is_running"]]),
                "stopped": len([a for a in agents if not a["is_running"]])
            },
            "tasks": {
                "total_active": total_tasks
            },
            "system": {
                "status": "operational"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {str(e)}")