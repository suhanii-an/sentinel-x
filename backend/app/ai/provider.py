"""Provider-agnostic LLM access.

The AI layer is an *optional external dependency*, and the architecture treats it
as one: a narrow interface, an explicit null implementation, bounded timeouts, and
no path by which a provider outage can affect detection, correlation or incident
creation.  Detection works without AI; AI improves investigation.

Adding a provider means implementing one method.  Nothing above this module knows
which vendor is configured.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings
from app.core.errors import AIUnavailableError
from app.core.logging import get_logger

logger = get_logger("sentinelx.ai.provider")


@dataclass(slots=True)
class LLMResponse:
    text: str
    model: str
    provider: str
    latency_ms: int
    usage: dict[str, Any]


class ProviderError(RuntimeError):
    """The provider failed. Never surfaced verbatim to API clients."""


class LLMProvider(ABC):
    name: str = "none"
    available: bool = False

    @abstractmethod
    def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float = 0.0,
    ) -> LLMResponse:
        ...


class NullProvider(LLMProvider):
    """Used when no API key is configured.

    Raising a typed error here rather than returning canned text is deliberate:
    a plausible-looking fake answer would be indistinguishable from a real one in
    the UI, which is precisely the failure mode this project exists to avoid.
    """

    name = "none"
    available = False

    def complete(self, **kwargs: Any) -> LLMResponse:
        raise AIUnavailableError(
            "No AI provider is configured. Detection, correlation, incidents, hunting, "
            "response simulation and reporting all continue to work; only the "
            "investigation assistant is unavailable."
        )


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    available = True
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str, model: str, base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")

    def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float = 0.0,
    ) -> LLMResponse:
        started = time.monotonic()
        try:
            response = httpx.post(
                f"{self.base_url}/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": self.API_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
                timeout=settings.AI_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"anthropic request failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            # The body may echo request content; log the status only.
            logger.error("ai_provider_error", extra={"provider": self.name,
                                                     "status": response.status_code})
            raise ProviderError(f"anthropic returned HTTP {response.status_code}")

        payload = response.json()
        blocks = payload.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return LLMResponse(
            text=text,
            model=payload.get("model", self.model),
            provider=self.name,
            latency_ms=int((time.monotonic() - started) * 1000),
            usage=payload.get("usage", {}),
        )


class OpenAIProvider(LLMProvider):
    name = "openai"
    available = True

    def __init__(self, api_key: str, model: str, base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://api.openai.com").rstrip("/")

    def complete(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        temperature: float = 0.0,
    ) -> LLMResponse:
        started = time.monotonic()
        try:
            response = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {self.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
                timeout=settings.AI_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"openai request failed: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            logger.error("ai_provider_error", extra={"provider": self.name,
                                                     "status": response.status_code})
            raise ProviderError(f"openai returned HTTP {response.status_code}")

        payload = response.json()
        choices = payload.get("choices") or []
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        return LLMResponse(
            text=text,
            model=payload.get("model", self.model),
            provider=self.name,
            latency_ms=int((time.monotonic() - started) * 1000),
            usage=payload.get("usage", {}),
        )


def build_provider() -> LLMProvider:
    if not settings.ai_enabled:
        return NullProvider()
    if settings.AI_PROVIDER == "anthropic":
        return AnthropicProvider(settings.AI_API_KEY, settings.AI_MODEL, settings.AI_BASE_URL)
    if settings.AI_PROVIDER == "openai":
        return OpenAIProvider(settings.AI_API_KEY, settings.AI_MODEL, settings.AI_BASE_URL)
    return NullProvider()


_provider: LLMProvider | None = None


def get_provider() -> LLMProvider:
    global _provider
    if _provider is None:
        _provider = build_provider()
    return _provider


def set_provider(provider: LLMProvider | None) -> None:
    """Override the provider. Used by tests to exercise the AI pipeline
    deterministically, without network access or an API key."""
    global _provider
    _provider = provider
