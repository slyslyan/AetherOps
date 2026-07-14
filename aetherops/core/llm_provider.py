"""
AetherOps — LLM Provider Abstraction.

Supports multiple LLM backends behind a common interface:
- OpenAI-compatible (DeepSeek, OpenAI, Azure, vLLM, etc.)
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

    Attempts three strategies in order:
    1. Extract JSON from ```json or ``` code blocks
    2. Extract JSON from bare {...} in the text
    3. Regex fallback for natural language responses
    """
    data = None

    # Strategy 1 & 2: JSON extraction from code blocks or bare braces
    json_str = None
    try:
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()
        else:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                json_str = raw[start : end + 1]

        if json_str:
            data = json.loads(json_str)
    except (json.JSONDecodeError, KeyError, ValueError):
        pass

    if data:
        return DiagnosisReport(
            root_cause=data.get("root_cause", "unknown"),
            confidence=data.get("confidence", 0.5),
            explanation=data.get("explanation", raw),
            affected_services=data.get("affected_services", []),
            recommended_actions=data.get("recommended_actions", []),
            raw_llm_response=raw,
        )

    # Strategy 3: Regex fallback for natural language
    try:
        extracted = _extract_fields_from_text(raw)
        if extracted and extracted.get("root_cause"):
            return DiagnosisReport(
                root_cause=extracted["root_cause"],
                confidence=extracted.get("confidence", 0.5),
                explanation=raw,
                affected_services=extracted.get("affected_services", []),
                recommended_actions=extracted.get("recommended_actions", []),
                raw_llm_response=raw,
            )
    except Exception:
        pass

    # Everything failed — return raw text as explanation
    logger.warning("Failed to parse LLM response as JSON or text, falling back")
    return DiagnosisReport(
        root_cause="unknown",
        confidence=0.0,
        explanation=raw,
        affected_services=[],
        recommended_actions=[],
        raw_llm_response=raw,
    )


def _extract_fields_from_text(text: str) -> dict:
    """Extract structured diagnosis fields from natural language text via regex.

    Handles responses like 'root cause: redis-cache:6379, confidence: 0.72'
    where the LLM did not produce JSON.
    """
    import re

    result: dict = {}

    # Root cause: "root cause: service-name" or "root cause is service-name"
    m = re.search(
        r"(?:root[_\s]cause)\s*(?::|=|is\s+)\s*[`\"']?([\w\-]+(?:[:\/][\w\-]+)*)",
        text,
        re.IGNORECASE,
    )
    if m:
        result["root_cause"] = m.group(1)

    # Confidence: "confidence: 0.85" or "confidence: 85%"
    m = re.search(r"confidence\s*[:\s]\s*([0-9.]+)", text, re.IGNORECASE)
    if m:
        val = float(m.group(1))
        if val > 1:
            val = val / 100.0
        result["confidence"] = max(0.0, min(val, 1.0))

    # Affected services: bullet list or comma list after "affected services"
    m = re.search(
        r"affected[_\s]services\s*[:\s](.*?)(?:\n\n|\Z)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        services = re.findall(
            r"[`\"']?([\w\-]+(?:[:\/][\w\-]+)*)[`\"']?", m.group(1)
        )
        result["affected_services"] = [
            s for s in services if s and not s.isspace() and len(s) > 1
        ]

    # Recommended actions: look for known action keywords in the text
    actions = []
    action_keywords = {
        "TC_DROP",
        "POD_RESTART",
        "SCALE_UP",
        "CONFIG_CHANGE",
        "IMAGE_ROLLBACK",
    }
    for kw in action_keywords:
        if kw.lower() in text.lower() or kw.replace("_", " ") in text.lower():
            actions.append(
                {
                    "action": kw,
                    "target": result.get("root_cause", "unknown"),
                    "risk": "MEDIUM",
                    "rationale": "",
                }
            )
    if actions:
        result["recommended_actions"] = actions

    return result


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
        ...

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 1024,
        temperature: float = 0.2,
        timeout: int = 30,
    ) -> Optional[str]:
        """Generic chat completion. Returns raw text or None on failure."""
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
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


# ---------- concrete providers ----------

class OpenAICompatibleProvider(LLMProvider):
    """For any OpenAI-compatible chat completions API (DeepSeek, OpenAI, Azure, vLLM, etc.)."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        provider_label: str = "OpenAI",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._label = provider_label

    @property
    def name(self) -> str:
        return f"{self._label}({self.model})"

    def _request(
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
        except httpx.TimeoutException:
            logger.error("%s request timed out after %ds", self._label, timeout)
        except Exception as e:
            logger.error("%s request failed: %s", self._label, e)
        return None

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        raw = self._request(system_prompt, user_message, 4096, 0.3, timeout)
        return parse_llm_response(raw) if raw else None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        return self._request(system_prompt, user_message, max_tokens, temperature, timeout)


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API (uses /v1/messages)."""

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

    def _request(
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
        except httpx.TimeoutException:
            logger.error("Anthropic request timed out after %ds", timeout)
        except Exception as e:
            logger.error("Anthropic request failed: %s", e)
        return None

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 120,
    ) -> Optional[DiagnosisReport]:
        raw = self._request(system_prompt, user_message, 4096, 0.3, timeout)
        return parse_llm_response(raw) if raw else None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        return self._request(system_prompt, user_message, max_tokens, temperature, timeout)


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

    def _request(
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
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response")
        except httpx.TimeoutException:
            logger.error("Ollama request timed out after %ds", timeout)
        except Exception as e:
            logger.error("Ollama request failed: %s", e)
        return None

    def diagnose(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 180,
    ) -> Optional[DiagnosisReport]:
        raw = self._request(system_prompt, user_message, 4096, 0.3, timeout)
        return parse_llm_response(raw) if raw else None

    def _chat_impl(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
        timeout: int,
    ) -> Optional[str]:
        return self._request(system_prompt, user_message, max_tokens, temperature, timeout)


# ---------- factory ----------

def get_default_system_prompt() -> str:
    from aetherops.core.llm_diagnosis import DIAGNOSIS_SYSTEM_PROMPT
    return DIAGNOSIS_SYSTEM_PROMPT


_PROVIDER_ALIASES: Dict[str, tuple] = {
    "deepseek": (OpenAICompatibleProvider, "deepseek-v4-flash", "https://api.deepseek.com/v1", "DeepSeek"),
    "openai":   (OpenAICompatibleProvider, "gpt-4o",             "https://api.openai.com/v1",    "OpenAI"),
    "anthropic": (AnthropicProvider,       "claude-sonnet-4-6",  "https://api.anthropic.com/v1",  None),
    "ollama":    (OllamaProvider,          "llama3",              "http://localhost:11434",        None),
}


class ProviderFactory:
    """Create an LLMProvider from environment configuration."""

    @classmethod
    def from_env(cls) -> Optional[LLMProvider]:
        provider_type = os.getenv("LLM_PROVIDER", "deepseek").lower()
        api_key = os.getenv("LLM_API_KEY", "")
        model = os.getenv("LLM_MODEL", "")
        base_url = os.getenv("LLM_BASE_URL", "")

        info = _PROVIDER_ALIASES.get(provider_type)
        if not info:
            logger.warning("Unknown LLM_PROVIDER=%s, falling back to DeepSeek", provider_type)
            info = _PROVIDER_ALIASES["deepseek"]

        provider_cls, default_model, default_url, label = info

        model = model or default_model
        base_url = base_url or default_url

        if provider_type == "ollama":
            return provider_cls(model=model, base_url=base_url)

        if not api_key:
            logger.warning("LLM_PROVIDER=%s but LLM_API_KEY not set", provider_type)
            return None

        if provider_cls is OpenAICompatibleProvider:
            return provider_cls(api_key=api_key, model=model, base_url=base_url, provider_label=label)

        return provider_cls(api_key=api_key, model=model, base_url=base_url)

    @classmethod
    def create(
        cls,
        provider_type: str,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> Optional[LLMProvider]:
        provider_type = provider_type.lower()
        info = _PROVIDER_ALIASES.get(provider_type)
        if not info:
            return None

        provider_cls, default_model, default_url, label = info
        model = model or default_model
        base_url = base_url or default_url

        if provider_type == "ollama":
            return provider_cls(model=model, base_url=base_url)
        if not api_key:
            return None
        if provider_cls is OpenAICompatibleProvider:
            return provider_cls(api_key=api_key, model=model, base_url=base_url, provider_label=label)
        return provider_cls(api_key=api_key, model=model, base_url=base_url)
