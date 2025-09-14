#!/usr/bin/env python3
"""
Simple demo of ZainGuard AI Platform without heavy dependencies.

This demonstrates the core concepts and basic functionality.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from loguru import logger

# Simple configuration
class SimpleConfig:
    def __init__(self):
        self.api_host = "0.0.0.0"
        self.api_port = 8000
        self.log_level = "INFO"

# Simple agent base class
class SimpleAgent:
    def __init__(self, agent_id: str, name: str, description: str):
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.is_running = False
        self.tasks = []
    
    async def start(self):
        self.is_running = True
        logger.info(f"Agent '{self.name}' started")
    
    async def stop(self):
        self.is_running = False
        logger.info(f"Agent '{self.name}' stopped")
    
    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a task - to be implemented by subclasses."""
        raise NotImplementedError

# Simple Triage Agent
class SimpleTriageAgent(SimpleAgent):
    def __init__(self, agent_id: str, name: str, description: str):
        super().__init__(agent_id, name, description)
        self.severity_scores = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }
    
    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a triage task."""
        alert_id = task_data.get("alert_id", "unknown")
        severity = task_data.get("severity", "medium")
        description = task_data.get("description", "No description")
        
        logger.info(f"Processing alert {alert_id} with severity {severity}")
        
        # Simple triage logic
        priority_score = self.severity_scores.get(severity, 3)
        
        # Simulate AI analysis
        analysis = {
            "alert_id": alert_id,
            "severity": severity,
            "priority_score": priority_score,
            "analysis": f"Alert analyzed: {description}",
            "recommendations": [
                "Review alert details",
                "Check related logs",
                "Update security rules if needed"
            ],
            "confidence": 0.8,
            "processed_at": datetime.utcnow().isoformat()
        }
        
        return analysis

# Simple Agent Manager
class SimpleAgentManager:
    def __init__(self):
        self.agents = {}
        self.is_running = False
    
    def create_agent(self, agent_type: str, agent_id: str, name: str, description: str) -> SimpleAgent:
        """Create a new agent."""
        if agent_type == "triage":
            agent = SimpleTriageAgent(agent_id, name, description)
        else:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        self.agents[agent_id] = agent
        logger.info(f"Created agent: {name} ({agent_id})")
        return agent
    
    def get_agent(self, agent_id: str) -> Optional[SimpleAgent]:
        """Get an agent by ID."""
        return self.agents.get(agent_id)
    
    async def start_all_agents(self):
        """Start all agents."""
        self.is_running = True
        for agent in self.agents.values():
            await agent.start()
        logger.info("All agents started")
    
    async def stop_all_agents(self):
        """Stop all agents."""
        self.is_running = False
        for agent in self.agents.values():
            await agent.stop()
        logger.info("All agents stopped")
    
    async def submit_task(self, agent_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a task to an agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        if not agent.is_running:
            raise ValueError(f"Agent not running: {agent_id}")
        
        result = await agent.process_task(task_data)
        agent.tasks.append({
            "task_data": task_data,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return result

# Simple FastAPI app
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ZainGuard AI Platform - Simple Demo", version="0.1.0")

# Global agent manager
agent_manager = SimpleAgentManager()

# Pydantic models
class CreateAgentRequest(BaseModel):
    agent_type: str
    agent_id: str
    name: str
    description: str

class TaskRequest(BaseModel):
    task_data: Dict[str, Any]

@app.on_event("startup")
async def startup_event():
    """Initialize the platform on startup."""
    logger.info("🚀 Starting ZainGuard AI Platform - Simple Demo")
    
    # Create a default triage agent
    agent_manager.create_agent(
        agent_type="triage",
        agent_id="default-triage-agent",
        name="Default Triage Agent",
        description="Automatically triages security alerts"
    )
    
    # Start all agents
    await agent_manager.start_all_agents()
    
    logger.info("✅ Platform started successfully!")

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to ZainGuard AI Platform - Simple Demo",
        "version": "0.1.0",
        "status": "running",
        "agents": len(agent_manager.agents)
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "ZainGuard AI Platform - Simple Demo",
        "version": "0.1.0",
        "agents_running": len([a for a in agent_manager.agents.values() if a.is_running])
    }

@app.get("/agents")
async def list_agents():
    """List all agents."""
    agents = []
    for agent in agent_manager.agents.values():
        agents.append({
            "agent_id": agent.agent_id,
            "name": agent.name,
            "description": agent.description,
            "is_running": agent.is_running,
            "tasks_processed": len(agent.tasks)
        })
    return {"agents": agents}

@app.post("/agents")
async def create_agent(request: CreateAgentRequest):
    """Create a new agent."""
    try:
        agent = agent_manager.create_agent(
            agent_type=request.agent_type,
            agent_id=request.agent_id,
            name=request.name,
            description=request.description
        )
        await agent.start()
        
        return {
            "message": f"Agent '{request.name}' created successfully",
            "agent_id": request.agent_id
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/agents/{agent_id}/tasks")
async def submit_task(agent_id: str, request: TaskRequest):
    """Submit a task to an agent."""
    try:
        result = await agent_manager.submit_task(agent_id, request.task_data)
        return {
            "message": "Task submitted successfully",
            "agent_id": agent_id,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/agents/{agent_id}/tasks")
async def get_agent_tasks(agent_id: str):
    """Get tasks for an agent."""
    agent = agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {
        "agent_id": agent_id,
        "tasks": agent.tasks
    }

if __name__ == "__main__":
    import uvicorn
    
    config = SimpleConfig()
    logger.info(f"Starting server on {config.api_host}:{config.api_port}")
    
    uvicorn.run(
        "simple_demo:app",
        host=config.api_host,
        port=config.api_port,
        reload=True,
        log_level=config.log_level.lower()
    )