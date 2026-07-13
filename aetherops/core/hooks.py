"""
AetherOps — Workflow Hook System.

Provides lifecycle event hooks for the LangGraph workflow.
Allows external code to observe and react to workflow events
without modifying the workflow internals.

Usage:
    from aetherops.core.hooks import HookEvent, trigger_hook

    trigger_hook(HookEvent.DIAGNOSIS_COMPLETE, root_cause=...)
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Callable, Dict

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


_hooks: Dict[HookEvent, list[HookFunc]] = {event: [] for event in HookEvent}


def register_hook(event: HookEvent, func: HookFunc) -> None:
    """Register a callback on the default registry."""
    _hooks[event].append(func)
    logger.debug("Hook registered: %s -> %s", event, func.__name__)


def trigger_hook(event: HookEvent, **context: Any) -> None:
    """Trigger all callbacks registered for the given event."""
    for func in _hooks[event]:
        try:
            func(event, context)
        except Exception:
            logger.exception("Hook %s -> %s failed", event, func.__name__)
