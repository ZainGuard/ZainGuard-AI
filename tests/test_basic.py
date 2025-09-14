"""Basic tests for ZainGuard AI Platform."""

import pytest
from src.core.config import Settings
from src.core.agent_manager import AgentManager
from src.core.llm_interface import LLMProvider


def test_settings_loading():
    """Test that settings can be loaded."""
    settings = Settings()
    assert settings.api_host == "0.0.0.0"
    assert settings.api_port == 8000
    assert settings.log_level == "INFO"


def test_agent_manager_initialization():
    """Test that agent manager can be initialized."""
    manager = AgentManager()
    assert manager.agents == {}
    assert manager.agent_types == {}
    assert manager.is_running is False


def test_llm_provider_enum():
    """Test LLM provider enum values."""
    assert LLMProvider.OPENAI.value == "openai"
    assert LLMProvider.ANTHROPIC.value == "anthropic"
    assert LLMProvider.OLLAMA.value == "ollama"


@pytest.mark.asyncio
async def test_agent_manager_operations():
    """Test basic agent manager operations."""
    manager = AgentManager()
    
    # Test registering agent type
    from src.agents.triage_agent import TriageAgent
    manager.register_agent_type("triage", TriageAgent)
    assert "triage" in manager.agent_types
    
    # Test creating agent
    agent = manager.create_agent(
        agent_type="triage",
        agent_id="test-agent",
        name="Test Agent",
        description="Test agent for unit testing"
    )
    assert agent.agent_id == "test-agent"
    assert agent.name == "Test Agent"
    
    # Test getting agent
    retrieved_agent = manager.get_agent("test-agent")
    assert retrieved_agent is not None
    assert retrieved_agent.agent_id == "test-agent"


def test_import_structure():
    """Test that all main modules can be imported."""
    from src.core import AgentManager, LLMInterface, DatabaseConnector, Settings
    from src.agents import TriageAgent, IncidentResponseAgent, ThreatIntelAgent
    from src.tools import SIEMConnector, ThreatIntelAPI, JiraManager
    from src.api import app
    
    # Basic assertions to ensure imports work
    assert AgentManager is not None
    assert LLMInterface is not None
    assert DatabaseConnector is not None
    assert Settings is not None
    assert TriageAgent is not None
    assert IncidentResponseAgent is not None
    assert ThreatIntelAgent is not None
    assert SIEMConnector is not None
    assert ThreatIntelAPI is not None
    assert JiraManager is not None
    assert app is not None