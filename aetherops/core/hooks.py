"""
AetherOps — Workflow Hook System.

Provides lifecycle event hooks for the LangGraph workflow.
Allows external code to observe and react to workflow events
without modifying the workflow internals.

Usage:
    from aetherops.core.hooks import HookEvent, register_hook, trigger_hook

    def on_diagnosis(event, ctx):
        print(f"Diagnosis complete: {ctx.get('root_cause')}")

    register_hook(HookEvent.DIAGNOSIS_COMPLETE, on_diagnosis)
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class HookEvent(str, Enum):
    """Lifecycle events in the AetherOps workflow."""

    WORKFLOW_START = "workflow.start"
    WORKFLOW_END = "workflow.end"
    WORKFLOW_ERROR = "workflow.error"

    BEFORE_AGENT = "before.agent"
    AFTER_AGENT = "after.agent"

    PLAN_GENERATED = "plan.generated"
    DIAGNOSIS_COMPLETE = "diagnosis.complete"
    CRITIC_REVIEWED = "critic.reviewed"
    REMEDIATION_START = "remediation.start"
    REMEDIATION_COMPLETE = "remediation.complete"
    RECOVERY_VERIFIED = "recovery.verified"
    RAG_STORED = "rag.stored"


HookFunc = Callable[[HookEvent, Dict[str, Any]], None]
"""Signature: (event, context_dict) -> None. Raise is caught and logged."""


class HookRegistry:
    """Thread-safe-ish hook registry with register/unregister/trigger."""

    def __init__(self) -> None:
        self._hooks: Dict[HookEvent, List[HookFunc]] = {
            event: [] for event in HookEvent
        }

    def register(self, event: HookEvent, func: HookFunc) -> None:
        self._hooks[event].append(func)
        logger.debug("Hook registered: %s -> %s", event, func.__name__)

    def unregister(self, event: HookEvent, func: HookFunc) -> None:
        self._hooks[event] = [f for f in self._hooks[event] if f != func]

    def trigger(self, event: HookEvent, **context: Any) -> None:
        for func in self._hooks[event]:
            try:
                func(event, context)
            except Exception:
                logger.exception("Hook %s -> %s failed", event, func.__name__)

    def clear(self) -> None:
        for event in HookEvent:
            self._hooks[event] = []


# Global default registry — used by the workflow unless overridden.
_default_registry = HookRegistry()


def get_registry() -> HookRegistry:
    """Return the global default HookRegistry."""
    return _default_registry


def register_hook(event: HookEvent, func: HookFunc) -> None:
    """Register a callback on the default registry."""
    _default_registry.register(event, func)


def trigger_hook(event: HookEvent, **context: Any) -> None:
    """Trigger a hook event on the default registry."""
    _default_registry.trigger(event, **context)
