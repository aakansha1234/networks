"""LLM provider abstraction.

A single minimal protocol (:class:`LLMClient`) plus one concrete implementation
that talks to any OpenAI-compatible Chat Completions endpoint (OpenAI itself,
OpenRouter, Together, vLLM, LM Studio, Ollama's OpenAI shim, ...). Uses only the
standard library so the project gains no hard dependency.

Configure at runtime with environment variables:

    SENTINEL_LLM_API_KEY   (or OPENAI_API_KEY)
    SENTINEL_LLM_BASE_URL  default https://api.openai.com/v1
    SENTINEL_LLM_MODEL     default gpt-4o-mini
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol


class LLMError(RuntimeError):
    """Raised when the LLM provider call fails."""


class LLMClient(Protocol):
    def complete(self, system: str, user: str, *,
                 temperature: float = 0.2, max_tokens: int = 1024) -> str: ...


class OpenAICompatible:
    """OpenAI Chat Completions client over stdlib urllib."""

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: float = 30.0) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def complete(self, system: str, user: str, *,
                 temperature: float = 0.2, max_tokens: int = 1024) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:  # pragma: no cover - network
            detail = exc.read().decode(errors="replace")[:300]
            raise LLMError(f"LLM provider returned HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise LLMError(f"LLM provider unreachable: {exc.reason}") from None
        try:
            return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError) as exc:  # pragma: no cover - bad provider
            raise LLMError(f"Unexpected LLM response shape: {data!r}") from exc


def get_client() -> LLMClient | None:
    """Return a configured client, or None if no API key is set.

    Code that needs the LLM should call this and gracefully degrade to the
    deterministic path when it returns None.
    """
    key = os.environ.get("SENTINEL_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    base = os.environ.get("SENTINEL_LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("SENTINEL_LLM_MODEL", "gpt-4o-mini")
    return OpenAICompatible(base, key, model)


def require_client() -> LLMClient:
    client = get_client()
    if client is None:
        raise LLMError(
            "No LLM configured. Set SENTINEL_LLM_API_KEY (or OPENAI_API_KEY) and "
            "optionally SENTINEL_LLM_BASE_URL / SENTINEL_LLM_MODEL."
        )
    return client
