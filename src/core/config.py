"""Configuration management for ZainGuard AI Platform."""

from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False
    
    # LLM Configuration
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4"
    openai_temperature: float = 0.1
    
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-3-sonnet-20240229"
    
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b"
    
    # Database Configuration
    database_url: str = "sqlite:///./zain_guard.db"
    vector_db_path: str = "./data/vector_db"
    
    # Security Tools Integration
    siem_base_url: Optional[str] = None
    siem_api_key: Optional[str] = None
    siem_verify_ssl: bool = True
    
    jira_base_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    
    # Threat Intelligence APIs
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "./logs/zain_guard.log"
    
    # Security Configuration
    secret_key: str = "your-secret-key-change-this"
    allowed_hosts: str = "localhost,127.0.0.1"
    
    @property
    def allowed_hosts_list(self) -> List[str]:
        """Convert comma-separated allowed_hosts to list."""
        return [host.strip() for host in self.allowed_hosts.split(",")]
    
    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    
    # Agent Configuration
    max_agent_concurrent_tasks: int = 10
    agent_timeout_seconds: int = 300


# Global settings instance
settings = Settings()