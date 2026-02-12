"""LLM provider abstraction for rampart-verify"""

import os
import logging
import httpx
from abc import ABC, abstractmethod

from prompt import get_system_prompt

logger = logging.getLogger(__name__)

# Timeout for all LLM calls — must fit within Rampart's webhook timeout (default 5s, max 30s).
REQUEST_TIMEOUT = 10.0

# Retry config for rate limits.
MAX_RETRIES = 2
RETRY_DELAY = 1.0


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        pass

    async def _retry_generate(self, fn) -> str:
        """Retry wrapper for rate-limited requests."""
        import asyncio
        last_err = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return await fn()
            except httpx.HTTPStatusError as e:
                last_err = e
                if e.response.status_code == 429 and attempt < MAX_RETRIES:
                    wait = RETRY_DELAY * (attempt + 1)
                    logger.warning(f"Rate limited (429), retrying in {wait}s (attempt {attempt + 1}/{MAX_RETRIES})")
                    await asyncio.sleep(wait)
                    continue
                raise
            except httpx.TimeoutException:
                raise
        raise last_err


class OpenAIProvider(LLMProvider):
    """Works with OpenAI and any OpenAI-compatible API (Together, Groq, local vLLM, etc.)"""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")

    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        async def _call():
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": get_system_prompt()},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": max_tokens,
                    },
                )
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]

        return await self._retry_generate(_call)


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str = "claude-3-haiku-20240307"):
        self.model = model
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")

    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        async def _call():
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "system": get_system_prompt(),
                        "max_tokens": max_tokens,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                response.raise_for_status()
                return response.json()["content"][0]["text"]

        return await self._retry_generate(_call)


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = "qwen2.5-coder:1.5b", url: str = "http://localhost:11434"):
        self.model = model
        self.url = url

    async def generate(self, prompt: str, max_tokens: int = 150) -> str:
        full_prompt = f"{get_system_prompt()}\n\n{prompt}"
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(
                f"{self.url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": max_tokens},
                },
            )
            response.raise_for_status()
            return response.json()["response"]


# Recommended models by tier (cheapest first).
RECOMMENDED_MODELS = {
    "free": "qwen2.5-coder:1.5b",          # Local Ollama, ~100-600ms, $0
    "budget": "gpt-4o-mini",                 # OpenAI, ~400ms, ~$0.0001/call
    "balanced": "claude-3-haiku-20240307",   # Anthropic, ~500ms, ~$0.0003/call
}


def get_provider(model: str) -> LLMProvider:
    """Get the appropriate provider based on model name and available API keys.

    Falls through gracefully: if no API key is configured for the requested
    model, falls back to Ollama (local, free) instead of erroring.
    """

    # Anthropic models
    if "claude" in model.lower():
        if os.getenv("ANTHROPIC_API_KEY"):
            return AnthropicProvider(model)
        logger.warning(f"No ANTHROPIC_API_KEY set for model {model}, falling back to Ollama")

    # OpenAI / OpenAI-compatible models
    elif "gpt" in model.lower():
        if os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(model)
        logger.warning(f"No OPENAI_API_KEY set for model {model}, falling back to Ollama")

    # Explicit Ollama model or fallback
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    fallback_model = model if "gpt" not in model.lower() and "claude" not in model.lower() else "qwen2.5-coder:1.5b"
    return OllamaProvider(fallback_model, ollama_url)
