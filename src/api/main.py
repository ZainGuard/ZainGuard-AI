"""Main FastAPI application for ZainGuard AI Platform."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import uvicorn
from loguru import logger

from .routes import agents, tasks, tools, health
from ..core.config import settings
from ..core.agent_manager import agent_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting ZainGuard AI Platform...")
    
    # Initialize database
    from ..core.database_connector import db_connector
    await db_connector._create_tables()
    
    # Register default agent types
    from ..agents.triage_agent import TriageAgent
    from ..agents.incident_response_agent import IncidentResponseAgent
    from ..agents.threat_intel_agent import ThreatIntelAgent
    
    agent_manager.register_agent_type("triage", TriageAgent)
    agent_manager.register_agent_type("incident_response", IncidentResponseAgent)
    agent_manager.register_agent_type("threat_intel", ThreatIntelAgent)
    
    # Start all agents
    await agent_manager.start_all_agents()
    
    logger.info("ZainGuard AI Platform started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down ZainGuard AI Platform...")
    await agent_manager.stop_all_agents()
    await db_connector.close()
    logger.info("ZainGuard AI Platform shut down")


# Create FastAPI application
app = FastAPI(
    title="ZainGuard AI Platform",
    description="An open-source Security Operations AI agent platform",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts
)

# Include routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(agents.router, prefix="/api/v1", tags=["agents"])
app.include_router(tasks.router, prefix="/api/v1", tags=["tasks"])
app.include_router(tools.router, prefix="/api/v1", tags=["tools"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to ZainGuard AI Platform",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_debug,
        log_level=settings.log_level.lower()
    )