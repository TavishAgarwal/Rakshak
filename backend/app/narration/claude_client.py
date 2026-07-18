"""RAKSHAK — Claude API client for narration.

LLM is only called here and in the AI Query Bar endpoint.
Never in scoring, fusion, or matching — those stay deterministic Python.

The client receives the **real structured evidence** (scores, fusion triple,
campaign state, graph context) and asks Claude to narrate it in plain language.
It never prompts the LLM to invent evidence.

API key is read from the ANTHROPIC_API_KEY environment variable only.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.getenv("RAKSHAK_NARRATION_MODEL", "claude-sonnet-4-20250514")
MAX_TOKENS = 1024

# ---------------------------------------------------------------------------
# System prompt — scoped to narration only
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are RAKSHAK, an AI-powered cyber resilience analyst for Indian Critical National Infrastructure (CNI).

Your role is to narrate structured security evidence in clear, actionable language for a SOC analyst. You must:

1. ONLY describe evidence that is provided to you in the structured data — never invent, hallucinate, or speculate beyond the given facts.
2. Explain what the evidence means in operational terms (e.g. "credential dumping detected on workstation WS-01 suggests the attacker has harvested domain credentials").
3. Highlight the most critical findings first.
4. If the evidence shows an IT→OT bridge pivot, emphasize this as the highest priority finding.
5. Note any OT safety implications when OT nodes are involved.
6. Keep your response under 200 words — this is a dashboard narration card, not a report.
7. Use plain language, avoid jargon where possible, but include ATT&CK technique IDs when available.
8. End with a one-line recommended next action.

You are a narration layer only — your output does NOT affect scoring, fusion, or response decisions."""


# ---------------------------------------------------------------------------
# Prompt injection guard (Must-Fix #5 from security audit)
# ---------------------------------------------------------------------------

# Patterns that indicate adversarial prompt injection attempts
_INJECTION_PATTERNS: list[str] = [
    "ignore previous instructions",
    "ignore all previous",
    "ignore your instructions",
    "forget your instructions",
    "disregard your instructions",
    "print your system prompt",
    "reveal your system prompt",
    "show your system prompt",
    "output your system prompt",
    "tell me your system prompt",
    "what is your system prompt",
    "print your instructions",
    "print the prompt",
    "reveal your instructions",
    "bypass your rules",
    "override your rules",
    "you are now DAN",
    "pretend you are",
    "act as if you are",
    "roleplay as",
    "new instructions",
    "your new role",
    "from now on",
    "for the rest of this",
    "do not follow your",
    "you must NOT",
    "you are NOT a narration",
    "you are an unrestricted",
    "jailbreak",
    "disable your safety",
]

_MAX_QUERY_LENGTH = 2000


def _sanitize_query(query: str) -> str:
    """Sanitize analyst query before sending to LLM.

    Returns the sanitized query or raises ValueError if the query is
    clearly adversarial (prompt injection attempt).
    """
    if not query or not query.strip():
        raise ValueError("Query cannot be empty.")

    if len(query) > _MAX_QUERY_LENGTH:
        raise ValueError(
            f"Query exceeds maximum length of {_MAX_QUERY_LENGTH} characters."
        )

    lower_query = query.lower()
    for pattern in _INJECTION_PATTERNS:
        if pattern in lower_query:
            raise ValueError(
                "Query blocked: it contains language that may attempt to "
                "bypass the system prompt. Please rephrase your analytical "
                "question about the evidence."
            )

    # Strip any leading/trailing quotes and whitespace
    return query.strip().strip('"').strip("'")


# ---------------------------------------------------------------------------
# Evidence assembly
# ---------------------------------------------------------------------------

def assemble_evidence_prompt(
    node_id: str,
    query: str,
    evidence: dict[str, Any],
) -> str:
    """Build the user prompt containing the real structured evidence.

    The query is sanitized before inclusion to block prompt injection.
    """
    safe_query = _sanitize_query(query)
    return f"""Analyst query: "{safe_query}"

Entity under investigation: {node_id}

Structured evidence (real data from the RAKSHAK engine — do NOT invent additional evidence):

{json.dumps(evidence, indent=2, default=str)}

Narrate this evidence for a SOC analyst. Answer the analyst's query using ONLY the evidence above."""


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------

async def narrate(
    node_id: str,
    query: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Call Claude API to narrate the structured evidence.

    Returns:
        {"narration": str, "model": str, "tokens_used": int}
        or {"narration": str, "error": str} on failure.
    """
    if not ANTHROPIC_API_KEY:
        # Fallback: return a deterministic summary when no API key is set
        return _fallback_narration(node_id, query, evidence)

    # Sanitize query against prompt injection before assembling prompt
    try:
        user_prompt = assemble_evidence_prompt(node_id, query, evidence)
    except ValueError as e:
        return {
            "narration": (
                f"⚠️ Query blocked: {e}\n\n"
                f"Please rephrase your question about entity {node_id} "
                f"to focus on the evidence displayed. For example:\n"
                f'  • "What does the evidence show for this entity?"\n'
                f'  • "What actions are recommended?"\n'
                f'  • "How confident is the threat assessment?"'
            ),
            "model": "injection-blocked",
            "tokens_used": 0,
        }

    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    payload = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": user_prompt},
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(ANTHROPIC_API_URL, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

            narration_text = data["content"][0]["text"]
            tokens = data.get("usage", {}).get("output_tokens", 0)

            return {
                "narration": narration_text,
                "model": MODEL,
                "tokens_used": tokens,
            }

    except httpx.HTTPStatusError as e:
        return {
            "narration": _fallback_narration(node_id, query, evidence)["narration"],
            "error": f"Claude API returned {e.response.status_code}",
        }
    except Exception as e:
        return {
            "narration": _fallback_narration(node_id, query, evidence)["narration"],
            "error": str(e),
        }


# ---------------------------------------------------------------------------
# Fallback — deterministic narration when no API key
# ---------------------------------------------------------------------------

def _fallback_narration(
    node_id: str,
    query: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Generate a deterministic narration from the structured evidence.

    Used when ANTHROPIC_API_KEY is not set (dev/demo mode).
    """
    fusion = evidence.get("fusion", {})
    belief = fusion.get("belief", 0)
    campaign = evidence.get("campaign_state", {})
    dominant = campaign.get("dominant_phase", "unknown")
    gate = evidence.get("response_gate", {})
    risk_tier = gate.get("risk_tier", "unknown")
    domain = evidence.get("graph_domain", "unknown")
    escalation = gate.get("requires_human_escalation", False)
    blocked = gate.get("blocked_actions", [])
    criticality = evidence.get("mission_criticality", {})
    safety = criticality.get("safety_impact", 0)

    # Build evidence summary
    sources = fusion.get("sources", [])
    active_sources = [s for s in sources if s.get("raw_score", 0) > 0.1]
    source_summary = ", ".join(
        (
            f"{s.get('scorer_class') or s.get('source_name') or s.get('name') or s.get('source', 'source')}"
            f"({s['raw_score']:.2f})"
        )
        for s in active_sources
    ) or "no active indicators"

    lines = [
        f"**Entity {node_id}** ({domain} domain) — Risk tier: **{risk_tier.upper()}**",
        "",
        f"Dempster-Shafer fusion yields belief={belief:.2f}, indicating "
        f"{'high confidence of malicious activity' if belief > 0.7 else 'moderate suspicion' if belief > 0.3 else 'low suspicion'}.",
        "",
        f"Active evidence sources: {source_summary}.",
        "",
        f"Campaign analysis places this entity in the **{dominant.replace('_', ' ')}** phase "
        f"(probability {campaign.get('dominant_probability', 0):.0%}).",
    ]

    if safety > 0.3:
        lines.append(f"\n⚠️ **Safety Impact**: {safety:.0%} — this entity affects physical processes.")

    if escalation:
        lines.append(f"\n🚨 **Human escalation required** — {gate.get('escalation_reason', 'OT/Bridge asset')}.")

    if blocked:
        lines.append(f"\n🛑 Blocked actions: {', '.join(blocked)}.")

    lines.append(f"\n**Recommended**: {'Escalate to OT safety team immediately' if safety > 0.5 else 'Investigate ' + dominant.replace('_', ' ') + ' indicators and correlate with adjacent nodes'}.")

    return {
        "narration": "\n".join(lines),
        "model": "fallback-deterministic",
        "tokens_used": 0,
    }
