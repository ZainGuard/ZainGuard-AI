"""Task management endpoints."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
from loguru import logger

from ...core.agent_manager import agent_manager

router = APIRouter()


class SubmitTaskRequest(BaseModel):
    task_type: str
    input_data: Dict[str, Any]
    priority: int = 1


class TaskResponse(BaseModel):
    task_id: str
    agent_id: str
    task_type: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@router.post("/tasks/{agent_id}/submit", response_model=Dict[str, str])
async def submit_task(agent_id: str, request: SubmitTaskRequest):
    """Submit a task to an agent."""
    try:
        task_id = await agent_manager.submit_task_to_agent(
            agent_id=agent_id,
            task_type=request.task_type,
            input_data=request.input_data,
            priority=request.priority
        )
        
        return {
            "task_id": task_id,
            "agent_id": agent_id,
            "status": "submitted"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error submitting task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{agent_id}/{task_id}", response_model=TaskResponse)
async def get_task_status(agent_id: str, task_id: str):
    """Get task status."""
    try:
        task_status = agent_manager.get_task_status(agent_id, task_id)
        if not task_status:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return TaskResponse(**task_status)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{agent_id}", response_model=List[TaskResponse])
async def list_agent_tasks(agent_id: str):
    """List all tasks for an agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        tasks = []
        for task in agent.current_tasks.values():
            task_status = agent.get_task_status(task.task_id)
            if task_status:
                tasks.append(TaskResponse(**task_status))
        
        return tasks
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing agent tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks/batch")
async def submit_batch_tasks(
    agent_id: str,
    tasks: List[SubmitTaskRequest]
):
    """Submit multiple tasks to an agent."""
    try:
        results = []
        
        for task_request in tasks:
            try:
                task_id = await agent_manager.submit_task_to_agent(
                    agent_id=agent_id,
                    task_type=task_request.task_type,
                    input_data=task_request.input_data,
                    priority=task_request.priority
                )
                
                results.append({
                    "task_id": task_id,
                    "status": "submitted",
                    "success": True
                })
            except Exception as e:
                results.append({
                    "task_id": None,
                    "status": "failed",
                    "error": str(e),
                    "success": False
                })
        
        return {
            "total_tasks": len(tasks),
            "successful": len([r for r in results if r["success"]]),
            "failed": len([r for r in results if not r["success"]]),
            "results": results
        }
    except Exception as e:
        logger.error(f"Error submitting batch tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks")
async def list_all_tasks():
    """List all tasks across all agents."""
    try:
        all_tasks = []
        agents = agent_manager.list_agents()
        
        for agent_info in agents:
            agent = agent_manager.get_agent(agent_info["agent_id"])
            if agent:
                for task in agent.current_tasks.values():
                    task_status = agent.get_task_status(task.task_id)
                    if task_status:
                        all_tasks.append(TaskResponse(**task_status))
        
        return {
            "total_tasks": len(all_tasks),
            "tasks": all_tasks
        }
    except Exception as e:
        logger.error(f"Error listing all tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/stats")
async def get_task_statistics():
    """Get task statistics."""
    try:
        agents = agent_manager.list_agents()
        
        total_tasks = 0
        running_tasks = 0
        completed_tasks = 0
        failed_tasks = 0
        
        for agent_info in agents:
            agent = agent_manager.get_agent(agent_info["agent_id"])
            if agent:
                for task in agent.current_tasks.values():
                    total_tasks += 1
                    if task.status == "running":
                        running_tasks += 1
                    elif task.status == "completed":
                        completed_tasks += 1
                    elif task.status == "failed":
                        failed_tasks += 1
        
        return {
            "total_tasks": total_tasks,
            "running_tasks": running_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "pending_tasks": total_tasks - running_tasks - completed_tasks - failed_tasks
        }
    except Exception as e:
        logger.error(f"Error getting task statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))