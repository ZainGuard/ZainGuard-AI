"""Agent management endpoints."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from loguru import logger

from ...core.agent_manager import agent_manager

router = APIRouter()


class CreateAgentRequest(BaseModel):
    agent_type: str
    agent_id: str
    name: str
    description: str
    config: Optional[Dict[str, Any]] = None


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    description: str
    is_running: bool
    available_tools: List[str]
    current_tasks: int


@router.get("/agents", response_model=List[AgentResponse])
async def list_agents():
    """List all agents."""
    try:
        agents = agent_manager.list_agents()
        return [AgentResponse(**agent) for agent in agents]
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str):
    """Get agent details by ID."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return AgentResponse(
            agent_id=agent.agent_id,
            name=agent.name,
            description=agent.description,
            is_running=agent.is_running,
            available_tools=agent.get_available_tools(),
            current_tasks=len(agent.current_tasks)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents", response_model=AgentResponse)
async def create_agent(request: CreateAgentRequest):
    """Create a new agent."""
    try:
        agent = agent_manager.create_agent(
            agent_type=request.agent_type,
            agent_id=request.agent_id,
            name=request.name,
            description=request.description,
            **(request.config or {})
        )
        
        # Start the agent
        await agent.start()
        
        return AgentResponse(
            agent_id=agent.agent_id,
            name=agent.name,
            description=agent.description,
            is_running=agent.is_running,
            available_tools=agent.get_available_tools(),
            current_tasks=len(agent.current_tasks)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/start")
async def start_agent(agent_id: str):
    """Start an agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        await agent.start()
        
        return {"message": f"Agent {agent_id} started successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/stop")
async def stop_agent(agent_id: str):
    """Stop an agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        await agent.stop()
        
        return {"message": f"Agent {agent_id} stopped successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/metrics")
async def get_agent_metrics(agent_id: str):
    """Get agent metrics."""
    try:
        metrics = agent_manager.get_agent_metrics(agent_id)
        if not metrics:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return metrics
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/tools")
async def get_agent_tools(agent_id: str):
    """Get available tools for an agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {
            "agent_id": agent_id,
            "tools": agent.get_available_tools()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/tools/{tool_name}/execute")
async def execute_agent_tool(
    agent_id: str,
    tool_name: str,
    parameters: Dict[str, Any]
):
    """Execute a tool on an agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        if not agent.is_running:
            raise HTTPException(status_code=400, detail="Agent is not running")
        
        result = await agent.execute_tool(tool_name, **parameters)
        
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "result": result
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))