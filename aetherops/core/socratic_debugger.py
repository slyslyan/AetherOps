"""
AetherOps — Socratic Debugger Cognitive Agent.

Pydantic-structured diagnostic agent for the JudgeX online judge system.
Called by the Go Reflective Controller when a submission verdict requires
LLM-powered analysis (CE, TLE, WA, RE).

Two diagnosis modes:
  - Static (TLE):        algorithmic complexity analysis only, no code execution
  - Dynamic (WA/RE):     trace-based causal analysis from instrumented execution

Output structure (Pydantic):
  - observation: what the code actually does vs what it should do
  - question:    pointed Socratic question leading to the bug
  - hint:        gentle nudge if the student is stuck (anti-leakage constrained)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Pydantic Structured Output Models
# ============================================================================


class SocraticDiagnosis(BaseModel):
    """Structured output from the Socratic Debugger agent.

    All three fields are required. The agent fills them based on the
    diagnosis mode and the evidence available in the prompt context.
    """

    observation: str = Field(
        ...,
        description="Concrete observation of what the code does vs what it should do. "
        "Must reference specific variable values, line numbers, or trace output. "
        "Max 300 characters.",
        max_length=300,
    )
    question: str = Field(
        ...,
        description="A single pointed Socratic question that leads the student to "
        "the exact root cause. Must not reveal the fix directly. Max 200 characters.",
        max_length=200,
    )
    hint: str = Field(
        ...,
        description="Gentle nudge about the pattern, edge case, or concept the student "
        "may have missed. Only provided if the question alone is insufficient. Max 150 characters.",
        max_length=150,
    )


# ============================================================================
# Professor Persona — System Prompt Template
# ============================================================================

PROFESSOR_SYSTEM_PROMPT = """You are a world-class programming professor at a top-tier university. \
Your teaching philosophy is Socratic: you never give answers, you guide students to discover them.

## Your Persona
- You have 20+ years of teaching algorithms and data structures.
- You can spot a bug or suboptimal pattern at a glance.
- You believe struggle is essential to learning — so you never reveal the fix.
- You are encouraging but precise: no vague "think about it" — your questions force \
the student to confront the exact flaw in their reasoning.

## Output Rules (NEVER Violate)
1. **NO complete solutions.** You must never output working code that solves the problem.
2. **NO algorithm names.** Don't say "use Dijkstra's" — say "think about shortest paths in a weighted graph."
3. **NO hidden test data.** Never reveal the content of hidden test cases.
4. **observation** must reference specific evidence from the code or trace.
5. **question** must be answerable in 1-2 sentences of thought.
6. **hint** is optional — leave it empty if the question is sufficient.

## Probe Delay Compensation
If you are analyzing an instrumented trace (dynamic mode), note that print statements \
inserted by the instrumenter add artificial delay. The relative order of prints is \
accurate, but absolute timings may be inflated. Do NOT attribute the TLE to the \
instrumentation overhead — focus on algorithmic issues.

## Anti-Leakage Safeguards
- Never produce a code block in your output — you are outputting structured JSON only.
- Never write more than 3 lines of code even as illustration.
- If the student's code is nearly correct, ask "what if input X happens?" rather than \
showing the fix.
"""


# ============================================================================
# Diagnosis Logic
# ============================================================================


def diagnose_static(
    code: str,
    language: str,
    problem_title: str,
    problem_description: str,
    time_limit_ms: int,
    memory_limit_mb: int,
    time_used_ms: Optional[int] = None,
    model: str = "deepseek-v4-flash",
) -> SocraticDiagnosis:
    """Static diagnosis mode — algorithmic complexity analysis for TLE verdicts.

    Args:
        code: The student's submitted source code.
        language: Programming language (cpp, python, go, java, rust).
        problem_title: Title of the problem.
        problem_description: Full problem description.
        time_limit_ms: Problem time limit in milliseconds.
        memory_limit_mb: Problem memory limit in megabytes.
        time_used_ms: How long the code actually ran before timeout (if known).
        model: LLM model identifier.

    Returns:
        SocraticDiagnosis with observation/question/hint focused on complexity.
    """
    user_message = _build_static_prompt(
        code, language, problem_title, problem_description,
        time_limit_ms, memory_limit_mb, time_used_ms,
    )
    return _call_llm(user_message, model, mode="static")


def diagnose_dynamic(
    code: str,
    language: str,
    problem_title: str,
    problem_description: str,
    time_limit_ms: int,
    memory_limit_mb: int,
    trace_output: str,
    failed_input: Optional[str] = None,
    failed_expected: Optional[str] = None,
    failed_actual: Optional[str] = None,
    verdict: str = "WA",
    model: str = "deepseek-v4-flash",
) -> SocraticDiagnosis:
    """Dynamic diagnosis mode — trace-based causal analysis for WA/RE verdicts.

    Args:
        code: The student's submitted source code.
        language: Programming language.
        problem_title: Title of the problem.
        problem_description: Full problem description.
        time_limit_ms: Problem time limit in milliseconds.
        memory_limit_mb: Problem memory limit in megabytes.
        trace_output: Instrumented execution trace (DEBUG_VAR_TRACE / DEBUG_LOOP_ENTER lines).
        failed_input: The test case input that caused the failure.
        failed_expected: Expected output for the failed test case.
        failed_actual: Actual output produced by the student's code.
        verdict: WA or RE.
        model: LLM model identifier.

    Returns:
        SocraticDiagnosis with observation/question/hint referencing specific trace lines.
    """
    user_message = _build_dynamic_prompt(
        code, language, problem_title, problem_description,
        time_limit_ms, memory_limit_mb, trace_output,
        failed_input, failed_expected, failed_actual, verdict,
    )
    return _call_llm(user_message, model, mode="dynamic")


# ============================================================================
# Prompt Builders
# ============================================================================


def _build_static_prompt(
    code: str,
    language: str,
    problem_title: str,
    problem_description: str,
    time_limit_ms: int,
    memory_limit_mb: int,
    time_used_ms: Optional[int] = None,
) -> str:
    lines = [
        "## Mode: STATIC DIAGNOSIS (TLE)",
        "",
        f"## Problem",
        f"- Title: {problem_title}",
        f"- Description: {_truncate(problem_description, 2000)}",
        f"- Time Limit: {time_limit_ms} ms",
        f"- Memory Limit: {memory_limit_mb} MB",
        "",
        f"## Student's Code ({language})",
        "```",
        code,
        "```",
        "",
    ]
    if time_used_ms is not None and time_used_ms > 0:
        lines.append(f"## Execution Context")
        lines.append(f"- Time Used: {time_used_ms} ms (limit: {time_limit_ms} ms)")
        lines.append("")

    lines += [
        "## Task",
        "Analyze the time complexity of the student's code. Identify:",
        "1. What is the Big-O complexity of the submitted code?",
        "2. Which specific lines or structures cause the bottleneck? (reference line numbers)",
        "3. What complexity is required to pass within the time limit?",
        "4. Ask a Socratic question that points toward the optimization direction.",
        "",
        "## Output",
        'Return a JSON object with "observation", "question", and "hint" fields.',
        "observation should reference specific loops, recursion depth, or data structures.",
    ]
    return "\n".join(lines)


def _build_dynamic_prompt(
    code: str,
    language: str,
    problem_title: str,
    problem_description: str,
    time_limit_ms: int,
    memory_limit_mb: int,
    trace_output: str,
    failed_input: Optional[str] = None,
    failed_expected: Optional[str] = None,
    failed_actual: Optional[str] = None,
    verdict: str = "WA",
) -> str:
    lines = [
        f"## Mode: DYNAMIC DIAGNOSIS ({verdict})",
        "",
        f"## Problem",
        f"- Title: {problem_title}",
        f"- Description: {_truncate(problem_description, 2000)}",
        f"- Time Limit: {time_limit_ms} ms",
        f"- Memory Limit: {memory_limit_mb} MB",
        "",
        f"## Student's Code ({language})",
        "```",
        code,
        "```",
        "",
    ]

    if failed_input or failed_expected or failed_actual:
        lines.append("## Failed Test Case")
        if failed_input:
            lines.append(f"- Input: {_truncate(failed_input, 500)}")
        if failed_expected:
            lines.append(f"- Expected: {_truncate(failed_expected, 500)}")
        if failed_actual:
            lines.append(f"- Actual: {_truncate(failed_actual, 500)}")
        lines.append("")

    if trace_output:
        lines.append("## Instrumented Execution Trace")
        lines.append("```")
        lines.append(_truncate(trace_output, 8000))
        lines.append("```")
        lines.append("")
        lines.append(
            "Note: DEBUG_VAR_TRACE lines show variable values after each assignment. "
            "DEBUG_LOOP_ENTER lines mark loop iterations. "
            "The relative order is accurate but absolute timings include instrumentation overhead."
        )
        lines.append("")

    lines += [
        "## Task",
        f"Analyze why this code produced a {verdict}. Follow these steps:",
        "1. Look at the DEBUG_VAR_TRACE lines — do variable values match expectations?",
        "2. Compare the trace against the expected output — where does the divergence start?",
        "3. Identify the root cause: off-by-one, wrong condition, missing edge case, etc.",
        "4. Formulate a pointed Socratic question about the exact line or logic at fault.",
        "",
        "## Output",
        'Return a JSON object with "observation", "question", and "hint" fields.',
        "observation MUST reference specific DEBUG_VAR_TRACE line numbers and variable values.",
    ]
    return "\n".join(lines)


# ============================================================================
# LLM Call & Response Parsing
# ============================================================================


def _call_llm(user_message: str, model: str, mode: str, max_retries: int = 2) -> SocraticDiagnosis:
    """Call the LLM with retry + exponential backoff, parse response.

    Args:
        user_message: The fully assembled prompt for the LLM.
        model: LLM model identifier.
        mode: "static" or "dynamic" (for logging & fallback).
        max_retries: Number of retries on transient errors (timeout, 5xx).

    Returns:
        Parsed SocraticDiagnosis, or a fallback diagnosis when all retries fail.
    """
    api_key = os.environ.get("LLM_API_KEY")
    api_url = os.environ.get("LLM_API_URL", "https://api.deepseek.com/v1/chat/completions")

    if not api_key:
        logger.warning("LLM_API_KEY not set, returning fallback diagnosis")
        return _fallback_diagnosis(mode)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": PROFESSOR_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": 1024,
        "temperature": 0.3,
        "response_format": {"type": "json_object"},
    }

    last_error: Optional[str] = None
    parse_attempted = False

    for attempt in range(max_retries + 1):
        if attempt > 0:
            wait = min(2 ** attempt, 15)
            logger.info("LLM retry %d/%d after %ds (mode=%s)", attempt, max_retries, wait, mode)
            time.sleep(wait)

        try:
            resp = httpx.post(
                api_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=90,
            )
            resp.raise_for_status()
            result = resp.json()
            raw = result["choices"][0]["message"]["content"]

            parsed = _parse_response(raw)
            if parsed is not None:
                return parsed
            parse_attempted = True
            last_error = "response did not contain valid JSON fields"
            logger.warning("LLM response parse failed (attempt %d, mode=%s): %s", attempt, mode, raw[:200])

        except httpx.TimeoutException:
            last_error = "timeout"
            logger.warning("LLM timeout (attempt %d, mode=%s)", attempt + 1, mode)
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 429 or status >= 500:
                last_error = f"HTTP {status}"
                logger.warning("LLM HTTP %s (attempt %d, mode=%s)", status, attempt + 1, mode)
                continue
            last_error = f"HTTP {status} (non-retriable)"
            logger.error("LLM non-retriable HTTP error (mode=%s): %s", mode, e)
            break
        except (KeyError, json.JSONDecodeError, ValueError) as e:
            last_error = str(e)
            logger.warning("LLM response decode error (attempt %d, mode=%s): %s", attempt + 1, mode, e)
            continue

    logger.error("LLM call failed after %d retries (mode=%s): %s", max_retries, mode, last_error)

    if parse_attempted and last_error:
        partial = _extract_partial_diagnosis(last_error)
        if partial is not None:
            return partial

    return _fallback_diagnosis(mode)


def _parse_response(raw: str) -> SocraticDiagnosis | None:
    """Parse LLM JSON response into SocraticDiagnosis.

    Returns None if parsing fails entirely (triggers retry or fallback).

    Resilience strategy:
    1. Strip markdown code fences
    2. Extract outermost JSON object
    3. Validate required fields exist
    4. Field-level fallback defaults
    """
    text = raw.strip()
    if not text:
        logger.warning("_parse_response: empty response")
        return None

    if text.startswith("```"):
        end = text.find("```", 3)
        if end > 3:
            text = text[3:end]
        else:
            text = text[3:]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        logger.warning("_parse_response: no JSON object found in: %s", raw[:200])
        return None

    text = text[start : end + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("_parse_response: JSON decode error: %s", e)
        return None

    obs = data.get("observation") or data.get("analysis") or data.get("diagnosis")
    q = data.get("question") or data.get("root_cause_question")
    h = data.get("hint") or ""

    if not obs or not q:
        logger.warning("_parse_response: missing required fields")
        return None

    return SocraticDiagnosis(
        observation=str(obs)[:300],
        question=str(q)[:200],
        hint=str(h)[:150],
    )


def _extract_partial_diagnosis(text: str) -> SocraticDiagnosis | None:
    """Last-resort heuristic: extract observation/question from unstructured text."""
    obs_match = re.search(r'(?:observation|观察)[：:]\s*(.+?)(?:\n|$)', text)
    q_match = re.search(r'(?:question|问题)[：:]\s*(.+?)(?:\n|$)', text)

    if obs_match and q_match:
        return SocraticDiagnosis(
            observation=obs_match.group(1).strip()[:300],
            question=q_match.group(1).strip()[:200],
            hint="",
        )
    return None


def _fallback_diagnosis(mode: str) -> SocraticDiagnosis:
    """Return a safe fallback when the LLM is unavailable."""
    if mode == "static":
        return SocraticDiagnosis(
            observation="代码运行超时。请分析算法的时间复杂度。",
            question="你的算法在最坏情况下的时间复杂度是多少？是否满足题目限制？",
            hint="检查是否存在嵌套循环或低效的数据结构操作。",
        )
    return SocraticDiagnosis(
        observation="代码未能通过测试。请检查边界条件处理。",
        question="你是否考虑了所有边界情况？（空输入、最大/最小值、特殊字符等）",
        hint="尝试在关键位置打印中间变量值，观察是否符合预期。",
    )


# ============================================================================
# Helpers
# ============================================================================


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters, appending truncation notice."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n...(truncated)"
