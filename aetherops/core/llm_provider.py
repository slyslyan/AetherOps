"""
AetherOps — LLM Provider Abstraction.

Supports multiple LLM backends behind a common interface:
- DeepSeek (current default)
- OpenAI / compatible (Azure, vLLM, etc.)
- Anthropic
- Ollama (local models, no API key needed)

Usage:
    provider = ProviderFactory.from_env()
    report = provider.diagnose(system_prompt, user_message)
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from aetherops.core.config import AetherOpsConfig

logger = logging.getLogger(__name__)


# ---------- shared types ----------

@dataclass
class DiagnosisReport:
    root_cause: str
    confidence: float
    explanation: str
    affected_services: List[str]
    recommended_actions: List[dict]
    raw_llm_response: str = ""


def parse_llm_response(raw: str) -> DiagnosisReport:
    """Parse LLM response into a structured DiagnosisReport.

    Shared across all providers since the response format is the same.
    """
    try:
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()
        else:
            json_str = raw[raw.find("{") : raw.rfind("}") + 1]

        data = json.loads(json_str)
        return DiagnosisReport(
            root_cause=data.get("root_cause", "unknown"),
            confidence=data.get("confidence", 0.5),
            explanation=data.get("explanation", ""),
            affected_services=data.get("affected_services", []),
            recommended_actions=data.get("recommended_actions", []),
            raw_llm_response=raw,
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("Failed to parse LLM response as JSON: %s", e)
        return DiagnosisReport(
            root_cause="unknown",
            confidence=0.0,
            explanation=raw,
            affected_services=[],
            recommended_actions=[],
            raw_llm_response=raw,
        )


# ---------- provider interface ----------

class LLMProvider(ABC):
    """Abstract LLM diagnosis provider."""

    @abstractmethod
    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        """Run diagnosis and return a structured report, or None on failure."""
        ...

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 1024,
        temperature: float = 0.2,
        timeout: int = 30,
    ) -> Optional[str]:
        """Generic chat completion (free-form text, not diagnosis-specific).

        Default implementation delegates to _chat_impl() which each provider
        must override.  Returns raw response text, or None on failure.
        """
        return self._chat_impl(system_prompt, user_message, max_tokens, temperature, timeout)

    @abstractmethod
    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        """Provider-specific chat implementation."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name for logging/metrics."""
        ...


# ---------- concrete providers ----------

class DeepSeekProvider(LLMProvider):
    """DeepSeek API (compatible with OpenAI format)."""

    def __init__(
        self,
        api_key: str,
        model: str = "deepseek-v4-flash",
        base_url: str = "https://api.deepseek.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return f"DeepSeek({self.model})"

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
            "temperature": 0.3,
        }

        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            raw = result["choices"][0]["message"]["content"]
            return parse_llm_response(raw)
        except httpx.TimeoutException:
            logger.error("DeepSeek request timed out after %ds", timeout)
        except Exception as e:
            logger.error("DeepSeek diagnosis failed: %s", e)
        return None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error("DeepSeek chat failed: %s", e)
            return None


class OpenAIProvider(LLMProvider):
    """Generic OpenAI-compatible provider (works with Azure, vLLM, etc.)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return f"OpenAI({self.model})"

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
            "temperature": 0.3,
        }

        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            raw = result["choices"][0]["message"]["content"]
            return parse_llm_response(raw)
        except httpx.TimeoutException:
            logger.error("OpenAI request timed out after %ds", timeout)
        except Exception as e:
            logger.error("OpenAI diagnosis failed: %s", e)
        return None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error("OpenAI chat failed: %s", e)
            return None


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        base_url: str = "https://api.anthropic.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return f"Anthropic({self.model})"

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
            "temperature": 0.3,
        }

        try:
            resp = httpx.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            raw = result["content"][0]["text"]
            return parse_llm_response(raw)
        except httpx.TimeoutException:
            logger.error("Anthropic request timed out after %ds", timeout)
        except Exception as e:
            logger.error("Anthropic diagnosis failed: %s", e)
        return None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
        except Exception as e:
            logger.error("Anthropic chat failed: %s", e)
            return None


class OllamaProvider(LLMProvider):
    """Local Ollama inference (no API key required)."""

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return f"Ollama({self.model})"

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 180,
    ) -> Optional[DiagnosisReport]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_message,
            "stream": False,
            "options": {
                "num_predict": 4096,
                "temperature": 0.3,
            },
        }

        try:
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            result = resp.json()
            raw = result.get("response", "")
            return parse_llm_response(raw)
        except httpx.TimeoutException:
            logger.error("Ollama request timed out after %ds", timeout)
        except Exception as e:
            logger.error("Ollama diagnosis failed: %s", e)
        return None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_message,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response")
        except Exception as e:
            logger.error("Ollama chat failed: %s", e)
            return None


# ---------- factory ----------

def get_default_system_prompt() -> str:
    """Return the default diagnosis system prompt with known fault patterns."""
    from aetherops.core.llm_diagnosis import DIAGNOSIS_SYSTEM_PROMPT
    return DIAGNOSIS_SYSTEM_PROMPT


class ProviderFactory:
    """Create an LLMProvider from environment configuration."""

    PROVIDER_MAP: Dict[str, type] = {
        "deepseek": DeepSeekProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }

    @classmethod
    def from_env(cls) -> Optional[LLMProvider]:
        """Read LLM_PROVIDER and associated env vars, return a provider or None."""
        provider_type = os.getenv("LLM_PROVIDER", "deepseek").lower()
        api_key = os.getenv("LLM_API_KEY", "")
        model = os.getenv("LLM_MODEL", "")
        base_url = os.getenv("LLM_BASE_URL", "")

        if provider_type == "ollama":
            model = model or "llama3"
            base_url = base_url or "http://localhost:11434"
            return OllamaProvider(model=model, base_url=base_url)

        if not api_key:
            logger.warning(
                "LLM_PROVIDER=%s but LLM_API_KEY not set, cannot create provider",
                provider_type,
            )
            return None

        provider_cls = cls.PROVIDER_MAP.get(provider_type)
        if not provider_cls:
            logger.warning("Unknown LLM_PROVIDER=%s, falling back to DeepSeek", provider_type)
            provider_cls = DeepSeekProvider

        if provider_type == "deepseek":
            model = model or "deepseek-v4-flash"
            base_url = base_url or "https://api.deepseek.com/v1"
        elif provider_type == "openai":
            model = model or "gpt-4o"
            base_url = base_url or "https://api.openai.com/v1"
        elif provider_type == "anthropic":
            model = model or "claude-sonnet-4-6"
            base_url = base_url or "https://api.anthropic.com/v1"

        return provider_cls(api_key=api_key, model=model, base_url=base_url)

    @classmethod
    def create(
        cls,
        provider_type: str,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> Optional[LLMProvider]:
        """Create a provider from explicit parameters (bypasses env)."""
        provider_type = provider_type.lower()

        if provider_type == "ollama":
            return OllamaProvider(model=model or "llama3", base_url=base_url or "http://localhost:11434")

        if not api_key:
            return None

        provider_cls = cls.PROVIDER_MAP.get(provider_type)
        if not provider_cls:
            return None

        return provider_cls(api_key=api_key, model=model, base_url=base_url)
