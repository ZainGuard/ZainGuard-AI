# Getting Started with ZainGuard AI Platform

This guide will help you get up and running with the ZainGuard AI Platform quickly.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Platform](#running-the-platform)
- [Your First Agent](#your-first-agent)
- [API Usage](#api-usage)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.9 or higher**
- **Git**
- **Docker** (optional, for containerized deployment)
- **An LLM API key** (OpenAI, Anthropic, or local Ollama instance)

### System Requirements

- **Minimum**: 2 CPU cores, 4GB RAM, 10GB disk space
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB disk space
- **Operating System**: Linux, macOS, or Windows (with WSL2)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ZainGuard/ZainGuard-AI.git
cd ZainGuard-AI
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install the platform and development dependencies
pip install -e .[dev]

# Or install only runtime dependencies
pip install -e .
```

### 4. Verify Installation

```bash
# Check if the platform is properly installed
python -c "import src; print('ZainGuard AI Platform installed successfully!')"
```

## Configuration

### 1. Environment Setup

```bash
# Copy the example environment file
cp env.example .env

# Edit the configuration
nano .env  # or use your preferred editor
```

### 2. Configure LLM Provider

Choose one of the following LLM providers:

#### Option A: OpenAI (Recommended for beginners)

```bash
# Add to your .env file
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.1
```

#### Option B: Anthropic

```bash
# Add to your .env file
ANTHROPIC_API_KEY=your_anthropic_api_key_here
ANTHROPIC_MODEL=claude-3-sonnet-20240229
```

#### Option C: Local Ollama (Privacy-focused)

```bash
# Install Ollama first
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull qwen2.5:7b

# Add to your .env file
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
```

### 3. Configure Security Tools (Optional)

If you have access to security tools, configure them:

```bash
# SIEM Configuration
SIEM_BASE_URL=https://your-siem.com/api
SIEM_API_KEY=your_siem_api_key

# Jira Configuration
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@domain.com
JIRA_API_TOKEN=your_jira_api_token

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
```

## Running the Platform

### 1. Start the API Server

```bash
# Start the FastAPI server
python -m src.api.main

# Or using uvicorn directly
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/api/v1/health

### 2. Verify the Platform is Running

```bash
# Check health status
curl http://localhost:8000/api/v1/health

# Expected response:
{
  "status": "healthy",
  "service": "ZainGuard AI Platform",
  "version": "0.1.0"
}
```

## Your First Agent

### 1. Create a Triage Agent

```python
# Create a simple script: create_agent.py
import asyncio
from src.core.agent_manager import agent_manager
from src.agents.triage_agent import TriageAgent

async def main():
    # Register the triage agent type
    agent_manager.register_agent_type("triage", TriageAgent)
    
    # Create a triage agent
    agent = agent_manager.create_agent(
        agent_type="triage",
        agent_id="my-triage-agent",
        name="My First Triage Agent",
        description="A simple triage agent for testing"
    )
    
    # Start the agent
    await agent.start()
    
    print(f"Agent created and started: {agent.name}")
    
    # Submit a test task
    task_id = await agent_manager.submit_task_to_agent(
        agent_id="my-triage-agent",
        task_type="triage_alert",
        input_data={
            "alert_id": "test-alert-001",
            "event_type": "suspicious_login",
            "source_ip": "192.168.1.100",
            "severity": "medium",
            "description": "Multiple failed login attempts detected"
        }
    )
    
    print(f"Task submitted: {task_id}")
    
    # Wait a moment for processing
    await asyncio.sleep(2)
    
    # Check task status
    status = agent_manager.get_task_status("my-triage-agent", task_id)
    print(f"Task status: {status}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Run Your First Agent

```bash
python create_agent.py
```

## API Usage

### 1. List Available Agents

```bash
curl http://localhost:8000/api/v1/agents
```

### 2. Create an Agent via API

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_type": "triage",
    "agent_id": "api-triage-agent",
    "name": "API Triage Agent",
    "description": "Created via API"
  }'
```

### 3. Submit a Task

```bash
curl -X POST http://localhost:8000/api/v1/tasks/api-triage-agent/submit \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "triage_alert",
    "input_data": {
      "alert_id": "api-alert-001",
      "event_type": "malware_detected",
      "severity": "high",
      "description": "Malware detected on workstation"
    },
    "priority": 1
  }'
```

### 4. Check Task Status

```bash
curl http://localhost:8000/api/v1/tasks/api-triage-agent/{task_id}
```

## Using the Web Interface

### 1. Access the API Documentation

Open your browser and navigate to:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### 2. Interactive Testing

The Swagger UI allows you to:
- Test all API endpoints interactively
- View request/response schemas
- Try different parameters
- See real-time responses

## Troubleshooting

### Common Issues

#### 1. Import Errors

```bash
# If you get import errors, ensure you're in the correct directory
cd /path/to/ZainGuard-AI
source venv/bin/activate
pip install -e .
```

#### 2. LLM Connection Issues

```bash
# Test your LLM configuration
python -c "
from src.core.llm_interface import get_default_llm_interface
import asyncio

async def test():
    llm = get_default_llm_interface()
    response = await llm.generate_response([{'role': 'user', 'content': 'Hello'}])
    print('LLM working:', response)

asyncio.run(test())
"
```

#### 3. Database Issues

```bash
# Check if database files are created
ls -la data/
# Should see: vector_db/ directory and zain_guard.db file
```

#### 4. Port Already in Use

```bash
# Check what's using port 8000
lsof -i :8000

# Kill the process or use a different port
uvicorn src.api.main:app --port 8001
```

### Debug Mode

Enable debug logging:

```bash
# Set debug mode in .env
API_DEBUG=true
LOG_LEVEL=DEBUG

# Or run with debug
LOG_LEVEL=DEBUG python -m src.api.main
```

### Logs

Check the logs for detailed information:

```bash
# View logs
tail -f logs/zain_guard.log

# Or check console output when running the server
```

## Next Steps

### 1. Explore the Examples

Check out the `examples/` directory for:
- Sample agent implementations
- Common use cases
- Integration examples

### 2. Read the Documentation

- [Architecture Overview](architecture.md)
- [API Reference](api-reference.md)
- [Contributing Guide](../CONTRIBUTING.md)

### 3. Build Your First Custom Agent

```python
from src.core.agent_manager import BaseAgent, AgentTask
from typing import Dict, List, Any

class MyCustomAgent(BaseAgent):
    def __init__(self, agent_id: str, name: str, description: str):
        super().__init__(agent_id, name, description)
        # Add your custom tools here
    
    async def process_task(self, task: AgentTask) -> Dict[str, Any]:
        # Implement your custom logic here
        return {"status": "completed", "result": "Custom processing done"}
    
    def get_available_tools(self) -> List[str]:
        return ["my_custom_tool"]
```

### 4. Join the Community

- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs and request features
- **Discord**: Real-time community chat (coming soon)

### 5. Contribute

- Fork the repository
- Create a feature branch
- Make your changes
- Submit a pull request

## Getting Help

If you run into issues:

1. **Check the logs** for error messages
2. **Search existing issues** on GitHub
3. **Create a new issue** with detailed information
4. **Join discussions** for community help

## What's Next?

Now that you have the platform running, you can:

1. **Create custom agents** for your specific security needs
2. **Integrate with your security tools** using the provided connectors
3. **Build workflows** that automate your security operations
4. **Contribute back** to the open-source community

Welcome to the ZainGuard AI Platform! 🚀