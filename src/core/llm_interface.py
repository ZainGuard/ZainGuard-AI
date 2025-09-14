"""LLM interface for ZainGuard AI Platform."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from enum import Enum
import asyncio
from loguru import logger

from .config import settings


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class LLMInterface(ABC):
    """Abstract base class for LLM interfaces."""
    
    @abstractmethod
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response from the LLM."""
        pass
    
    @abstractmethod
    async def generate_streaming_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ):
        """Generate a streaming response from the LLM."""
        pass


class OpenAIInterface(LLMInterface):
    """OpenAI LLM interface."""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
        self._client = None
    
    async def _get_client(self):
        """Get OpenAI client, creating if necessary."""
        if self._client is None:
            try:
                import openai
                self._client = openai.AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("OpenAI package not installed. Run: pip install openai")
        return self._client
    
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response from OpenAI."""
        try:
            client = await self._get_client()
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    async def generate_streaming_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ):
        """Generate a streaming response from OpenAI."""
        try:
            client = await self._get_client()
            stream = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True,
                **kwargs
            )
            
            async for chunk in stream:
                if chunk.choices[0].delta.content is not None:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"OpenAI streaming API error: {e}")
            raise


class AnthropicInterface(LLMInterface):
    """Anthropic LLM interface."""
    
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key
        self.model = model
        self._client = None
    
    async def _get_client(self):
        """Get Anthropic client, creating if necessary."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("Anthropic package not installed. Run: pip install anthropic")
        return self._client
    
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response from Anthropic."""
        try:
            client = await self._get_client()
            response = await client.messages.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens or 4096,
                **kwargs
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise
    
    async def generate_streaming_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ):
        """Generate a streaming response from Anthropic."""
        try:
            client = await self._get_client()
            stream = await client.messages.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens or 4096,
                stream=True,
                **kwargs
            )
            
            async for chunk in stream:
                if chunk.type == "content_block_delta":
                    yield chunk.delta.text
        except Exception as e:
            logger.error(f"Anthropic streaming API error: {e}")
            raise


class OllamaInterface(LLMInterface):
    """Ollama LLM interface for local models."""
    
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url
        self.model = model
    
    async def generate_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response from Ollama."""
        try:
            import httpx
            
            # Convert messages to Ollama format
            prompt = self._format_messages(messages)
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "temperature": temperature,
                        "stream": False,
                        **kwargs
                    },
                    timeout=300
                )
                response.raise_for_status()
                return response.json()["response"]
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise
    
    async def generate_streaming_response(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
        **kwargs
    ):
        """Generate a streaming response from Ollama."""
        try:
            import httpx
            
            # Convert messages to Ollama format
            prompt = self._format_messages(messages)
            
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "temperature": temperature,
                        "stream": True,
                        **kwargs
                    },
                    timeout=300
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line:
                            try:
                                data = line.json()
                                if "response" in data:
                                    yield data["response"]
                            except:
                                continue
        except Exception as e:
            logger.error(f"Ollama streaming API error: {e}")
            raise
    
    def _format_messages(self, messages: List[Dict[str, str]]) -> str:
        """Convert messages to a single prompt string."""
        formatted = []
        for message in messages:
            role = message["role"]
            content = message["content"]
            if role == "system":
                formatted.append(f"System: {content}")
            elif role == "user":
                formatted.append(f"Human: {content}")
            elif role == "assistant":
                formatted.append(f"Assistant: {content}")
        return "\n\n".join(formatted)


def create_llm_interface(provider: LLMProvider) -> LLMInterface:
    """Create an LLM interface based on the provider."""
    if provider == LLMProvider.OPENAI:
        if not settings.openai_api_key:
            raise ValueError("OpenAI API key not configured")
        return OpenAIInterface(
            api_key=settings.openai_api_key,
            model=settings.openai_model
        )
    elif provider == LLMProvider.ANTHROPIC:
        if not settings.anthropic_api_key:
            raise ValueError("Anthropic API key not configured")
        return AnthropicInterface(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model
        )
    elif provider == LLMProvider.OLLAMA:
        return OllamaInterface(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")


def get_default_llm_interface() -> LLMInterface:
    """Get the default LLM interface based on configuration."""
    # Priority: OpenAI > Anthropic > Ollama
    if settings.openai_api_key:
        return create_llm_interface(LLMProvider.OPENAI)
    elif settings.anthropic_api_key:
        return create_llm_interface(LLMProvider.ANTHROPIC)
    else:
        return create_llm_interface(LLMProvider.OLLAMA)