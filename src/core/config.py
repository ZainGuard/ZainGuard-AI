"""Configuration management for ZainGuard AI Platform."""

from typing import List, Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_debug: bool = Field(default=False, env="API_DEBUG")
    
    # LLM Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", env="OPENAI_MODEL")
    openai_temperature: float = Field(default=0.1, env="OPENAI_TEMPERATURE")
    
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", env="ANTHROPIC_MODEL")
    
    ollama_base_url: str = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen2.5:7b", env="OLLAMA_MODEL")
    
    # Database Configuration
    database_url: str = Field(default="sqlite:///./zain_guard.db", env="DATABASE_URL")
    vector_db_path: str = Field(default="./data/vector_db", env="VECTOR_DB_PATH")
    
    # Security Tools Integration
    siem_base_url: Optional[str] = Field(default=None, env="SIEM_BASE_URL")
    siem_api_key: Optional[str] = Field(default=None, env="SIEM_API_KEY")
    siem_verify_ssl: bool = Field(default=True, env="SIEM_VERIFY_SSL")
    
    jira_base_url: Optional[str] = Field(default=None, env="JIRA_BASE_URL")
    jira_email: Optional[str] = Field(default=None, env="JIRA_EMAIL")
    jira_api_token: Optional[str] = Field(default=None, env="JIRA_API_TOKEN")
    
    # Threat Intelligence APIs
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="./logs/zain_guard.log", env="LOG_FILE")
    
    # Security Configuration
    secret_key: str = Field(default="your-secret-key-change-this", env="SECRET_KEY")
    allowed_hosts: List[str] = Field(default=["localhost", "127.0.0.1"], env="ALLOWED_HOSTS")
    
    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    # Agent Configuration
    max_agent_concurrent_tasks: int = Field(default=10, env="MAX_AGENT_CONCURRENT_TASKS")
    agent_timeout_seconds: int = Field(default=300, env="AGENT_TIMEOUT_SECONDS")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()