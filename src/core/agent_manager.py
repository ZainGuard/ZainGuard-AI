"""Agent management system for ZainGuard AI Platform."""

from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod
import asyncio
from datetime import datetime
from loguru import logger
import uuid

from .llm_interface import LLMInterface, get_default_llm_interface
from .config import settings


class AgentTask:
    """Represents a task for an agent."""
    
    def __init__(
        self,
        task_id: str,
        agent_id: str,
        task_type: str,
        input_data: Dict[str, Any],
        priority: int = 1
    ):
        self.task_id = task_id
        self.agent_id = agent_id
        self.task_type = task_type
        self.input_data = input_data
        self.priority = priority
        self.status = "pending"
        self.created_at = datetime.utcnow()
        self.started_at = None
        self.completed_at = None
        self.result = None
        self.error = None


class BaseAgent(ABC):
    """Base class for all security operation agents."""
    
    def __init__(
        self,
        agent_id: str,
        name: str,
        description: str,
        llm_interface: Optional[LLMInterface] = None
    ):
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.llm_interface = llm_interface or get_default_llm_interface()
        self.tools = {}
        self.is_running = False
        self.current_tasks: Dict[str, AgentTask] = {}
    
    @abstractmethod
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        """Process a task and return results."""
        pass
    
    @abstractmethod
    def get_available_tools(self) -> List[str]:
        """Get list of available tools for this agent."""
        pass
    
    async def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """Execute a tool by name."""
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not available for agent '{self.name}'")
        
        tool = self.tools[tool_name]
        if asyncio.iscoroutinefunction(tool):
            return await tool(**kwargs)
        else:
            return tool(**kwargs)
    
    def register_tool(self, name: str, tool_func):
        """Register a tool with this agent."""
        self.tools[name] = tool_func
    
    async def start(self):
        """Start the agent."""
        self.is_running = True
        logger.info(f"Agent '{self.name}' started")
    
    async def stop(self):
        """Stop the agent."""
        self.is_running = False
        # Wait for current tasks to complete
        if self.current_tasks:
            await asyncio.gather(
                *[self._wait_for_task(task_id) for task_id in self.current_tasks.keys()],
                return_exceptions=True
            )
        logger.info(f"Agent '{self.name}' stopped")
    
    async def _wait_for_task(self, task_id: str):
        """Wait for a specific task to complete."""
        while task_id in self.current_tasks and self.current_tasks[task_id].status in ["pending", "running"]:
            await asyncio.sleep(0.1)
    
    async def submit_task(self, task_type: str, input_data: Dict[str, Any], priority: int = 1) -> str:
        """Submit a task to this agent."""
        task_id = str(uuid.uuid4())
        task = AgentTask(
            task_id=task_id,
            agent_id=self.agent_id,
            task_type=task_type,
            input_data=input_data,
            priority=priority
        )
        
        self.current_tasks[task_id] = task
        asyncio.create_task(self._process_task_async(task))
        
        return task_id
    
    async def _process_task_async(self, task: AgentTask):
        """Process a task asynchronously."""
        try:
            task.status = "running"
            task.started_at = datetime.utcnow()
            
            result = await self.process_task(task)
            
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.result = result
            
            logger.info(f"Task {task.task_id} completed successfully")
            
        except Exception as e:
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            task.error = str(e)
            logger.error(f"Task {task.task_id} failed: {e}")
        
        finally:
            # Remove completed task from current tasks
            if task.task_id in self.current_tasks:
                del self.current_tasks[task.task_id]
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a task."""
        if task_id not in self.current_tasks:
            return None
        
        task = self.current_tasks[task_id]
        return {
            "task_id": task.task_id,
            "agent_id": task.agent_id,
            "task_type": task.task_type,
            "status": task.status,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "result": task.result,
            "error": task.error
        }


class AgentManager:
    """Manages all agents in the system."""
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_types: Dict[str, Type[BaseAgent]] = {}
        self.is_running = False
    
    def register_agent_type(self, agent_type: str, agent_class: Type[BaseAgent]):
        """Register an agent type."""
        self.agent_types[agent_type] = agent_class
        logger.info(f"Registered agent type: {agent_type}")
    
    def create_agent(
        self,
        agent_type: str,
        agent_id: str,
        name: str,
        description: str,
        **kwargs
    ) -> BaseAgent:
        """Create a new agent instance."""
        if agent_type not in self.agent_types:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        agent_class = self.agent_types[agent_type]
        agent = agent_class(
            agent_id=agent_id,
            name=name,
            description=description,
            **kwargs
        )
        
        self.agents[agent_id] = agent
        logger.info(f"Created agent: {name} ({agent_id})")
        
        return agent
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get an agent by ID."""
        return self.agents.get(agent_id)
    
    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents."""
        return [
            {
                "agent_id": agent.agent_id,
                "name": agent.name,
                "description": agent.description,
                "is_running": agent.is_running,
                "available_tools": agent.get_available_tools(),
                "current_tasks": len(agent.current_tasks)
            }
            for agent in self.agents.values()
        ]
    
    async def start_all_agents(self):
        """Start all registered agents."""
        self.is_running = True
        tasks = [agent.start() for agent in self.agents.values()]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("All agents started")
    
    async def stop_all_agents(self):
        """Stop all registered agents."""
        self.is_running = False
        tasks = [agent.stop() for agent in self.agents.values()]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("All agents stopped")
    
    async def submit_task_to_agent(
        self,
        agent_id: str,
        task_type: str,
        input_data: Dict[str, Any],
        priority: int = 1
    ) -> str:
        """Submit a task to a specific agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        if not agent.is_running:
            raise ValueError(f"Agent not running: {agent_id}")
        
        return await agent.submit_task(task_type, input_data, priority)
    
    def get_task_status(self, agent_id: str, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a task."""
        agent = self.get_agent(agent_id)
        if not agent:
            return None
        
        return agent.get_task_status(task_id)
    
    def get_agent_metrics(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            return None
        
        return {
            "agent_id": agent.agent_id,
            "name": agent.name,
            "is_running": agent.is_running,
            "current_tasks": len(agent.current_tasks),
            "available_tools": len(agent.get_available_tools()),
            "task_history": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status,
                    "created_at": task.created_at.isoformat(),
                    "completed_at": task.completed_at.isoformat() if task.completed_at else None
                }
                for task in agent.current_tasks.values()
            ]
        }


# Global agent manager instance
agent_manager = AgentManager()