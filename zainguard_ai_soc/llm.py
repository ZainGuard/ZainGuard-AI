"""
LLM client abstraction for ZainGuard AI.

Supports Anthropic (Claude), OpenAI, and Ollama (local) — provider is
auto-detected from the model name string. Claude is the default and
recommended for best results in security investigations.

Usage:
    from zainguard_ai_soc.llm import LLMClient

    llm = LLMClient(model="claude-opus-4-6")        # Anthropic
    llm = LLMClient(model="gpt-4o")                 # OpenAI
    llm = LLMClient(model="ollama:llama3.2")         # Local Ollama

    response = llm.complete(system="You are...", user="Investigate this alert...")

Environment variables:
    ANTHROPIC_API_KEY   — required for Claude models
    OPENAI_API_KEY      — required for OpenAI models
    OLLAMA_BASE_URL     — optional, defaults to http://localhost:11434
"""
from __future__ import annotations

import json
import os
import re


_ANTHROPIC_PREFIXES = ("claude",)
_OPENAI_PREFIXES = ("gpt-", "o1-", "o1-", "o3-", "o4-")
_OLLAMA_PREFIX = "ollama:"


def _detect_provider(model: str) -> str:
    if model.startswith(_ANTHROPIC_PREFIXES):
        return "anthropic"
    if model.startswith(_OPENAI_PREFIXES):
        return "openai"
    if model.startswith(_OLLAMA_PREFIX):
        return "ollama"
    raise ValueError(
        f"Cannot detect provider for model '{model}'. "
        "Supported prefixes: claude- (Anthropic), gpt-/o1-/o3-/o4- (OpenAI), ollama: (local Ollama). "
        "Example: model='claude-opus-4-6' or model='ollama:llama3.2'"
    )


class LLMClient:
    """
    Thin wrapper around LLM provider APIs.

    All agents use this class instead of calling provider SDKs directly.
    This keeps provider-specific code in one place and makes it trivial
    to support a new provider by adding one method.
    """

    def __init__(self, model: str = "claude-opus-4-6") -> None:
        self.model = model
        self.provider = _detect_provider(model)

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """
        Send a system + user message and return the text response.

        Args:
            system: The system prompt that defines agent behavior.
            user:   The user turn content (the actual task or data).
            max_tokens: Maximum tokens in the response.

        Returns:
            The model's text response as a plain string.
        """
        if self.provider == "anthropic":
            return self._anthropic(system, user, max_tokens)
        if self.provider == "openai":
            return self._openai(system, user, max_tokens)
        if self.provider == "ollama":
            return self._ollama(system, user, max_tokens)
        raise RuntimeError(f"Unhandled provider: {self.provider}")

    def complete_json(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """
        Like complete(), but strips markdown code fences before returning.

        LLMs sometimes wrap JSON output in ```json ... ``` blocks even when
        instructed not to. Use this method whenever the response will be
        passed to json.loads().
        """
        text = self.complete(system, user, max_tokens).strip()
        # Strip ```json ... ``` or ``` ... ``` wrappers
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text

    # ------------------------------------------------------------------ #
    # Provider implementations                                             #
    # ------------------------------------------------------------------ #

    def _anthropic(self, system: str, user: str, max_tokens: int) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        message = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text

    def _openai(self, system: str, user: str, max_tokens: int) -> str:
        import openai

        client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content

    def _ollama(self, system: str, user: str, max_tokens: int) -> str:
        import httpx

        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        # Strip the "ollama:" prefix to get the actual model name
        ollama_model = self.model[len(_OLLAMA_PREFIX):]

        response = httpx.post(
            f"{base_url}/api/chat",
            json={
                "model": ollama_model,
                "stream": False,
                "options": {"num_predict": max_tokens},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=120.0,
        )
        response.raise_for_status()
        return response.json()["message"]["content"]
