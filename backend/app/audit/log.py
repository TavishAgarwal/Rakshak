"""Hash-chained audit helpers for fusion, gate, and resilience events."""

from __future__ import annotations

from typing import Any

from app.audit.chain import append_audit_entry, clear_audit_chain, get_audit_chain


def log_fusion_event(
    node_id: str,
    belief: float,
    plausibility: float,
    uncertainty: float,
    conflict: float,
    sources: list[dict[str, Any]],
    scorer_scores: dict[str, float] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Log a fused score event with all contributing sources."""
    return append_audit_entry(
        entity_id=node_id,
        evidence_sources=sources,
        alternatives_considered=[],
        human_approval={"approved_by": "system", "timestamp": None},
        action_taken="fusion_result",
        event_type="fusion",
        metadata={
            "belief": belief,
            "plausibility": plausibility,
            "uncertainty": uncertainty,
            "conflict": conflict,
            "raw_scores": scorer_scores or {},
        },
        **(context or {}),
    )


def log_gate_decision(
    node_id: str,
    asset_type: str,
    confidence: float,
    criticality: float,
    risk_tier: str,
    allowed_actions: list[str],
    blocked_actions: list[str],
    requires_escalation: bool,
    escalation_reason: str | None,
    rationale: list[str],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Log a response gate decision with full reasoning chain."""
    return append_audit_entry(
        entity_id=node_id,
        evidence_sources=[],
        alternatives_considered=blocked_actions,
        human_approval={"approved_by": None if requires_escalation else "system", "timestamp": None},
        action_taken="gate_decision",
        event_type="gate_decision",
        metadata={
            "asset_type": asset_type,
            "confidence": confidence,
            "criticality": criticality,
            "risk_tier": risk_tier,
            "allowed_actions": allowed_actions,
            "blocked_actions": blocked_actions,
            "requires_human_escalation": requires_escalation,
            "escalation_reason": escalation_reason,
            "rationale": rationale,
        },
        **(context or {}),
    )


def log_resilience_event(
    headline_score: float,
    components: dict[str, Any],
    assessment: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Log a resilience score computation."""
    return append_audit_entry(
        entity_id="resilience-score",
        evidence_sources=[],
        alternatives_considered=[],
        human_approval={"approved_by": "system", "timestamp": None},
        action_taken="resilience_score",
        event_type="resilience",
        metadata={
            "headline_score": headline_score,
            "components": components,
            "assessment": assessment,
        },
        **(context or {}),
    )


def get_audit_log(
    limit: int = 100,
    event_type: str | None = None,
    node_id: str | None = None,
) -> list[dict[str, Any]]:
    """Read recent hash-chain audit entries, most recent first."""
    return get_audit_chain(entity_id=node_id, event_type=event_type, limit=limit)


def clear_audit_log() -> None:
    """Clear the hash-chain audit log for tests/demo startup."""
    clear_audit_chain()
