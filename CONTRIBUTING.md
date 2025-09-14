# Contributing to ZainGuard AI Platform

Thank you for your interest in contributing to the ZainGuard AI Platform! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [Community Guidelines](#community-guidelines)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/ZainGuard-AI.git
   cd ZainGuard-AI
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/ZainGuard/ZainGuard-AI.git
   ```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- Docker (optional, for containerized development)

### Environment Setup

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -e .[dev]
   ```

3. **Set up pre-commit hooks**:
   ```bash
   pre-commit install
   ```

4. **Configure environment variables**:
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest -m unit
pytest -m integration
```

### Running the Application

```bash
# Start the API server
python -m src.api.main

# Or using uvicorn directly
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

## Contributing Process

### 1. Choose an Issue

- Look for issues labeled `good first issue` for beginners
- Check the [project board](https://github.com/ZainGuard/ZainGuard-AI/projects) for current priorities
- Comment on the issue to indicate you're working on it

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 3. Make Changes

- Write clean, well-documented code
- Follow the coding standards outlined below
- Add tests for new functionality
- Update documentation as needed

### 4. Test Your Changes

```bash
# Run the test suite
pytest

# Run linting
flake8 src tests
black --check src tests
isort --check-only src tests

# Run type checking
mypy src
```

### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: add new security agent for vulnerability scanning

- Implemented VulnerabilityScannerAgent class
- Added integration with Nessus API
- Created comprehensive test suite
- Updated documentation

Closes #123"
```

**Commit Message Format:**
- Use conventional commits format: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- Keep the first line under 50 characters
- Use the imperative mood ("add" not "added")

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear title and description
- Reference to related issues
- Screenshots for UI changes
- Testing instructions

## Coding Standards

### Python Style

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 88 characters (Black default)
- **Import sorting**: Use `isort` with Black profile
- **Type hints**: Required for all public functions
- **Docstrings**: Use Google style docstrings

### Code Formatting

We use automated formatting tools:

```bash
# Format code
black src tests
isort src tests

# Check formatting
black --check src tests
isort --check-only src tests
```

### Type Hints

All public functions and methods should have type hints:

```python
from typing import Dict, List, Optional

def process_alert(
    alert_data: Dict[str, Any],
    agent_id: str,
    priority: int = 1
) -> Optional[Dict[str, Any]]:
    """Process a security alert."""
    pass
```

### Error Handling

- Use specific exception types
- Log errors with appropriate levels
- Provide meaningful error messages
- Handle exceptions gracefully

```python
try:
    result = await some_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}")
    raise ProcessingError(f"Failed to process data: {e}") from e
```

## Testing

### Test Structure

```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
└── fixtures/       # Test fixtures and data
```

### Writing Tests

- Write tests for all new functionality
- Aim for high test coverage (>80%)
- Use descriptive test names
- Test both success and failure cases

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_agent_processes_alert_successfully():
    """Test that agent processes alert and returns correct result."""
    # Arrange
    agent = TriageAgent("test-agent", "Test Agent")
    alert_data = {"alert_id": "123", "severity": "high"}
    
    # Act
    result = await agent.process_task(AgentTask(
        task_id="test-task",
        agent_id="test-agent",
        task_type="triage_alert",
        input_data=alert_data
    ))
    
    # Assert
    assert result["status"] == "success"
    assert "triage_result" in result
```

### Test Categories

Use pytest markers to categorize tests:

```python
@pytest.mark.unit
def test_unit_functionality():
    pass

@pytest.mark.integration
def test_integration_with_external_api():
    pass

@pytest.mark.slow
def test_long_running_operation():
    pass
```

## Documentation

### Code Documentation

- Document all public classes, methods, and functions
- Use Google style docstrings
- Include examples for complex functions
- Document parameters, return values, and exceptions

```python
def analyze_threat_data(
    ioc_type: str,
    ioc_value: str,
    threat_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Analyze threat intelligence data for an IOC.
    
    Args:
        ioc_type: Type of indicator (ip, domain, hash)
        ioc_value: The actual indicator value
        threat_data: Raw threat intelligence data
        
    Returns:
        Dictionary containing analysis results with keys:
        - threat_level: Critical, high, medium, low, or benign
        - confidence: Confidence score (0.0 to 1.0)
        - recommendations: List of recommended actions
        
    Raises:
        ValueError: If ioc_type is not supported
        AnalysisError: If analysis fails
        
    Example:
        >>> threat_data = {"malicious": True, "confidence": 0.8}
        >>> result = analyze_threat_data("ip", "1.2.3.4", threat_data)
        >>> assert result["threat_level"] == "high"
    """
```

### API Documentation

- Update OpenAPI/Swagger documentation for API changes
- Include request/response examples
- Document error codes and responses

### README Updates

- Update README.md for significant changes
- Add new features to the features list
- Update installation and usage instructions

## Security

### Security Considerations

- Never commit API keys, passwords, or sensitive data
- Use environment variables for configuration
- Validate all inputs
- Follow secure coding practices
- Report security vulnerabilities responsibly

### Reporting Security Issues

If you discover a security vulnerability, please:

1. **DO NOT** create a public issue
2. Email security@zainguard.com with details
3. Include steps to reproduce
4. Wait for acknowledgment before public disclosure

## Community Guidelines

### Communication

- Be respectful and inclusive
- Use clear, constructive language
- Ask questions if you're unsure
- Help others when you can

### Pull Request Guidelines

- Keep PRs focused and atomic
- Write clear, descriptive titles
- Include comprehensive descriptions
- Link to related issues
- Request reviews from relevant maintainers

### Issue Guidelines

- Search existing issues before creating new ones
- Use clear, descriptive titles
- Provide reproduction steps for bugs
- Include environment details
- Use appropriate labels

## Getting Help

- **Documentation**: Check the [docs](docs/) directory
- **Issues**: Search existing [issues](https://github.com/ZainGuard/ZainGuard-AI/issues)
- **Discussions**: Use [GitHub Discussions](https://github.com/ZainGuard/ZainGuard-AI/discussions)
- **Email**: Contact team@zainguard.com

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Community highlights

Thank you for contributing to ZainGuard AI Platform! 🚀