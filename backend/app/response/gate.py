"""RAKSHAK — Safety-gated response decision logic.

decision = f(confidence, mission_criticality, asset_type) → allowed actions.

OT active disruption is **hard-blocked in code** (not just in the UI),
with a mandatory human-escalation flag on any OT-adjacent action.
This satisfies rules.md: "OT nodes: active disruption actions must be
hard-blocked in code, with a mandatory human-escalation flag."

Deterministic logic only — no LLM (per rules.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Action types
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """Available containment / response actions."""

    # IT actions — may be gated by confidence/criticality
    ISOLATE_ENDPOINT = "isolate_endpoint"
    REVOKE_CREDENTIAL = "revoke_credential"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    INCREASE_MONITORING = "increase_monitoring"
    ALERT_SOC = "alert_soc"

    # OT actions — disruption is hard-blocked
    OT_ISOLATE_SEGMENT = "ot_isolate_segment"
    OT_SHUTDOWN_PLC = "ot_shutdown_plc"
    OT_DISABLE_ACTUATOR = "ot_disable_actuator"
    OT_INCREASE_MONITORING = "ot_increase_monitoring"
    OT_ALERT_OPERATOR = "ot_alert_operator"
    OT_SWITCH_MANUAL_MODE = "ot_switch_manual_mode"


# Actions that constitute "active disruption" in OT context
OT_ACTIVE_DISRUPTION: set[ActionType] = {
    ActionType.OT_ISOLATE_SEGMENT,
    ActionType.OT_SHUTDOWN_PLC,
    ActionType.OT_DISABLE_ACTUATOR,
}

# Non-disruptive OT actions (always allowed for OT)
OT_SAFE_ACTIONS: set[ActionType] = {
    ActionType.OT_INCREASE_MONITORING,
    ActionType.OT_ALERT_OPERATOR,
    ActionType.OT_SWITCH_MANUAL_MODE,
}

# IT actions — tiered by confidence
IT_LOW_CONFIDENCE: set[ActionType] = {
    ActionType.INCREASE_MONITORING,
    ActionType.ALERT_SOC,
}
IT_MEDIUM_CONFIDENCE: set[ActionType] = IT_LOW_CONFIDENCE | {
    ActionType.BLOCK_IP,
    ActionType.QUARANTINE_FILE,
}
IT_HIGH_CONFIDENCE: set[ActionType] = IT_MEDIUM_CONFIDENCE | {
    ActionType.ISOLATE_ENDPOINT,
    ActionType.REVOKE_CREDENTIAL,
    ActionType.DISABLE_ACCOUNT,
}


# ---------------------------------------------------------------------------
# Gate decision result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GateDecision:
    """Response gate output for an entity."""

    node_id: str
    asset_type: str
    confidence: float
    criticality_composite: float
    allowed_actions: list[str]
    blocked_actions: list[str]
    requires_human_escalation: bool
    escalation_reason: str | None
    risk_tier: str                    # low / medium / high / critical
    rationale: list[str]


# ---------------------------------------------------------------------------
# Gate logic
# ---------------------------------------------------------------------------

def _risk_tier(confidence: float, criticality: float) -> str:
    """Map (confidence, criticality) to a risk tier."""
    combined = confidence * 0.6 + criticality * 0.4
    if combined < 0.25:
        return "low"
    if combined < 0.50:
        return "medium"
    if combined < 0.75:
        return "high"
    return "critical"


def evaluate_gate(
    node_id: str,
    asset_type: str,
    confidence: float,
    criticality_composite: float,
    safety_impact: float,
) -> GateDecision:
    """Evaluate the response gate for a single entity.

    Args:
        node_id: Graph node identifier.
        asset_type: "IT", "OT", or "IT_OT_BRIDGE".
        confidence: DS-fused belief score (0-1).
        criticality_composite: Mission criticality composite (0-1).
        safety_impact: Safety impact dimension from criticality vector (0-1).

    Returns:
        GateDecision with allowed/blocked actions and escalation flags.
    """
    allowed: list[str] = []
    blocked: list[str] = []
    rationale: list[str] = []
    requires_escalation = False
    escalation_reason: str | None = None
    tier = _risk_tier(confidence, criticality_composite)

    is_ot = asset_type in ("OT", "IT_OT_BRIDGE")

    # ── IT action gating (confidence-tiered) ─────────────────────
    if confidence >= 0.70:
        it_allowed = IT_HIGH_CONFIDENCE
        rationale.append(f"High confidence ({confidence:.2f}) → full IT action set")
    elif confidence >= 0.40:
        it_allowed = IT_MEDIUM_CONFIDENCE
        rationale.append(f"Medium confidence ({confidence:.2f}) → partial IT action set")
    else:
        it_allowed = IT_LOW_CONFIDENCE
        rationale.append(f"Low confidence ({confidence:.2f}) → monitoring-only IT actions")

    # High criticality nodes get an extra gate: require escalation even for IT
    if criticality_composite >= 0.70 and confidence < 0.80:
        requires_escalation = True
        escalation_reason = (
            f"High-criticality asset (composite={criticality_composite:.2f}) "
            f"with sub-0.80 confidence ({confidence:.2f}) requires human review"
        )
        rationale.append(escalation_reason)

    for action in sorted(it_allowed, key=lambda a: a.value):
        allowed.append(action.value)

    # ── OT action gating (hard-block disruption) ──────────────────
    if is_ot:
        # Safe OT actions always allowed
        for action in sorted(OT_SAFE_ACTIONS, key=lambda a: a.value):
            allowed.append(action.value)
            rationale.append(f"OT safe action '{action.value}' → allowed")

        # HARD-BLOCK: OT active disruption — always blocked in code
        for action in sorted(OT_ACTIVE_DISRUPTION, key=lambda a: a.value):
            blocked.append(action.value)

        rationale.append(
            "OT active disruption HARD-BLOCKED (rules.md): "
            f"{[a.value for a in sorted(OT_ACTIVE_DISRUPTION, key=lambda x: x.value)]}"
        )

        # Mandatory human escalation for ALL OT-adjacent actions
        requires_escalation = True
        escalation_reason = (
            f"OT/Bridge asset ({asset_type}) — mandatory human escalation "
            f"per rules.md (safety_impact={safety_impact:.2f})"
        )
        rationale.append(escalation_reason)

    return GateDecision(
        node_id=node_id,
        asset_type=asset_type,
        confidence=round(confidence, 4),
        criticality_composite=round(criticality_composite, 4),
        allowed_actions=allowed,
        blocked_actions=blocked,
        requires_human_escalation=requires_escalation,
        escalation_reason=escalation_reason,
        risk_tier=tier,
        rationale=rationale,
    )


# ---------------------------------------------------------------------------
# Dynamic Response Agent (New)
# ---------------------------------------------------------------------------

@dataclass
class ResponseDecision:
    action: str
    tier: str
    reason: str
    requires_human_approval: bool
    status: str = "Allowed" # "Allowed", "Needs Approval", "Blocked"


from app.audit.chain import append_audit_entry


def _is_ot_entity(entity: dict[str, Any]) -> bool:
    node_type = entity.get("node_type") or entity.get("type") or ""
    asset_type = entity.get("graph_domain") or entity.get("domain") or ""
    return asset_type in ("OT", "IT_OT_BRIDGE") or node_type in {
        "OTDevice", "PLC", "RTU", "HMI", "SENSOR", "ACTUATOR", "SCADA_SERVER", "IT_OT_BRIDGE", "ITOTBridge"
    }


def assert_action_allowed(entity: dict[str, Any], action: str) -> None:
    """Raise if an action is structurally unreachable for this entity."""
    active_disruptions = {
        "isolate_endpoint", "isolate", "snapshot", "revoke", "revoke_credential",
        "disable_account", "ot_isolate_segment", "ot_shutdown_plc", "ot_disable_actuator"
    }
    if _is_ot_entity(entity) and action in active_disruptions:
        raise ValueError(
            f"CRITICAL SAFETY VIOLATION: Active disruption action '{action}' "
            "is structurally unreachable for OT entities."
        )

def decide_response(
    entity: dict[str, Any], 
    confidence: float, 
    mission_criticality_vector: dict[str, Any],
    evidence_sources: list[dict[str, Any]] = None,
    audit: bool = True,
    auto_execute_threshold: float = 0.9,
    context: dict[str, Any] | None = None,
) -> ResponseDecision:
    """Decide the response action and tier based on confidence and criticality."""
    
    # Handle defaults
    evidence_sources = evidence_sources or []
    alternatives = []
    
    # Hard OT Rule
    if _is_ot_entity(entity):
        # OT entities restricted to monitoring/airgap
        action = "gateway_air_gap" if confidence > 0.7 else "passive_monitoring"
        status = "Blocked" if confidence > 0.7 else "Allowed"
        try:
            assert_action_allowed(entity, "isolate_endpoint")
            block_reason = "OT entity restricted to passive monitoring"
        except ValueError as exc:
            block_reason = str(exc)
        
        alternatives = ["ot_isolate_segment (Blocked by Safety Engine)", "ot_shutdown_plc (Blocked by Safety Engine)"]
        
        if audit:
            append_audit_entry(
                entity_id=entity.get("id", "unknown"),
                evidence_sources=evidence_sources,
                alternatives_considered=alternatives,
                human_approval={"approved_by": None, "timestamp": None} if status == "Blocked" else {"approved_by": "auto_executed", "timestamp": None},
                action_taken=action,
                **(context or {}),
            )
        
        return ResponseDecision(
            action=action,
            tier="analyst_alert",
            reason=block_reason,
            requires_human_approval=True,
            status=status
        )
    
    # IT entities: tiered response
    if confidence < 0.5:
        tier = "log_only"
        action = "increase_monitoring"
        requires_approval = False
        reason = "Confidence < 0.5 (log_only)"
    elif confidence < 0.7:
        tier = "analyst_alert"
        action = "alert_soc"
        requires_approval = True
        reason = "Confidence 0.5-0.7 (analyst_alert)"
    elif confidence < auto_execute_threshold:
        tier = "recommend_playbook"
        action = "quarantine_file"
        requires_approval = True
        reason = f"Confidence 0.7-{auto_execute_threshold:.2f} (recommend_playbook)"
    else:
        tier = "auto_execute"
        action = "isolate_endpoint"
        requires_approval = False
        reason = f"Confidence >= {auto_execute_threshold:.2f} (auto_execute)"
        
        # Downgrade logic for safety
        pub_safety = mission_criticality_vector.get("public_safety_impact", "low")
        human_dep = mission_criticality_vector.get("human_dependency", "low")
        
        # In numerical model it might be floats, check accordingly
        is_high_safety = (isinstance(pub_safety, float) and pub_safety > 0.7) or str(pub_safety).lower() == "high"
        is_high_human = (isinstance(human_dep, float) and human_dep > 0.7) or str(human_dep).lower() == "high"
        
        if is_high_safety or is_high_human:
            tier = "recommend_playbook"
            requires_approval = True
            reason = "Auto-execute downgraded to recommend_playbook due to high safety/human dependency"

    status = "Needs Approval" if requires_approval else "Allowed"

    # Write to append-only chain
    human_approval = {"approved_by": None, "timestamp": None}
    if not requires_approval:
        human_approval = {"approved_by": "auto_executed", "timestamp": None}

    if audit:
        append_audit_entry(
            entity_id=entity.get("id", "unknown"),
            evidence_sources=evidence_sources,
            alternatives_considered=alternatives,
            human_approval=human_approval,
            action_taken=action,
            **(context or {}),
        )

    return ResponseDecision(
        action=action,
        tier=tier,
        reason=reason,
        requires_human_approval=requires_approval,
        status=status
    )


def execute_response_action(entity: dict[str, Any], action: str) -> bool:
    """Execute the response action, structurally rejecting active OT disruption."""
    assert_action_allowed(entity, action)
    return True
