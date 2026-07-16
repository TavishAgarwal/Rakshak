"""RAKSHAK — Kill-chain probabilistic state machine.

Computes a **campaign state distribution** per entity — a probability
vector over ATT&CK-aligned kill-chain phases.  Each phase has graph-based
preconditions that must be satisfied before it can be hypothesized.

This is deterministic graph logic, NOT an LLM call (per rules.md).

Kill-chain phases (simplified ATT&CK):
    benign → initial_access → execution → discovery →
    credential_access → lateral_movement → persistence →
    collection → command_and_control → exfiltration →
    ot_pivot → impact
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx


# ---------------------------------------------------------------------------
# Kill-chain phase definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KillChainPhase:
    """A single kill-chain phase with scoring and precondition metadata."""

    name: str
    display_name: str
    required_prior_phases: list[str]       # phases that must have non-zero prob
    indicator_flags: dict[str, list[str]]  # flag_attr → flags that evidence this phase
    scorer_weights: dict[str, float]       # which scorer classes contribute, and how much
    min_score_threshold: float             # minimum fused score to activate


KILL_CHAIN: list[KillChainPhase] = [
    KillChainPhase(
        name="initial_access",
        display_name="Initial Access",
        required_prior_phases=[],
        indicator_flags={
            "network_flags": ["inbound_phishing"],
            "identity_flags": ["phishing_target"],
        },
        scorer_weights={"network": 0.5, "identity": 0.3, "dns": 0.2},
        min_score_threshold=0.05,
    ),
    KillChainPhase(
        name="execution",
        display_name="Execution",
        required_prior_phases=[],
        indicator_flags={
            "process_flags": ["suspicious_executable", "code_injection"],
        },
        scorer_weights={"process": 0.7, "network": 0.2, "dns": 0.1},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="discovery",
        display_name="Discovery",
        required_prior_phases=[],
        indicator_flags={
            "network_flags": ["port_scan_outbound", "smb_enumeration",
                              "recon_activity", "unauthorized_scan"],
            "process_flags": ["reconnaissance_tool"],
            "ot_physics_flags": ["reconnaissance_detected", "ot_network_scan"],
        },
        scorer_weights={"network": 0.6, "process": 0.2, "ot_physics": 0.2},
        min_score_threshold=0.05,
    ),
    KillChainPhase(
        name="credential_access",
        display_name="Credential Access",
        required_prior_phases=[],
        indicator_flags={
            "credential_flags": ["credential_dump", "credential_compromised",
                                 "pass_the_hash", "credential_reuse"],
        },
        scorer_weights={"credential": 0.8, "identity": 0.2},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="lateral_movement",
        display_name="Lateral Movement",
        required_prior_phases=["credential_access"],  # PRECONDITION: needs credential_access first
        indicator_flags={
            "network_flags": ["unexpected_rdp", "unusual_smb_session",
                              "cross_zone_traffic", "unusual_opc_ua"],
            "credential_flags": ["pass_the_hash", "credential_reuse"],
            "process_flags": ["remote_service_execution"],
        },
        scorer_weights={"network": 0.4, "credential": 0.3, "process": 0.2, "identity": 0.1},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="persistence",
        display_name="Persistence",
        required_prior_phases=["execution"],
        indicator_flags={
            "process_flags": ["new_local_account", "scheduled_task"],
            "identity_flags": ["new_admin_account"],
        },
        scorer_weights={"process": 0.5, "identity": 0.4, "credential": 0.1},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="collection",
        display_name="Collection",
        required_prior_phases=["discovery"],
        indicator_flags={
            "cloud_api_flags": ["unusual_data_query", "bulk_export"],
            "network_flags": ["large_data_transfer"],
        },
        scorer_weights={"cloud_api": 0.6, "network": 0.3, "process": 0.1},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="command_and_control",
        display_name="Command & Control",
        required_prior_phases=["execution"],
        indicator_flags={
            "dns_flags": ["c2_callback"],
            "network_flags": ["c2_communication"],
        },
        scorer_weights={"dns": 0.5, "network": 0.4, "process": 0.1},
        min_score_threshold=0.10,
    ),
    KillChainPhase(
        name="exfiltration",
        display_name="Exfiltration",
        required_prior_phases=["collection"],
        indicator_flags={
            "network_flags": ["large_data_transfer"],
            "cloud_api_flags": ["bulk_export"],
        },
        scorer_weights={"network": 0.5, "cloud_api": 0.4, "dns": 0.1},
        min_score_threshold=0.15,
    ),
    KillChainPhase(
        name="ot_pivot",
        display_name="IT→OT Pivot",
        required_prior_phases=["lateral_movement"],  # PRECONDITION: must have laterally moved
        indicator_flags={
            "network_flags": ["cross_zone_traffic", "unusual_opc_ua"],
            "identity_flags": ["unauthorized_bridge_access", "unauthorized_access"],
            "cloud_api_flags": ["historian_api_abuse"],
        },
        scorer_weights={"network": 0.3, "identity": 0.3, "cloud_api": 0.2, "ot_physics": 0.2},
        min_score_threshold=0.15,
    ),
    KillChainPhase(
        name="impact",
        display_name="Impact",
        required_prior_phases=["lateral_movement"],
        indicator_flags={
            "ot_physics_flags": ["unauthorized_setpoint_change",
                                 "parameter_modification", "reading_deviation"],
            "process_flags": ["unauthorized_plc_write"],
        },
        scorer_weights={"ot_physics": 0.7, "process": 0.2, "network": 0.1},
        min_score_threshold=0.15,
    ),
]


# ---------------------------------------------------------------------------
# Graph precondition checks
# ---------------------------------------------------------------------------

def _has_indicator_evidence(
    node: dict[str, Any],
    indicator_flags: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    """Check if a node has any of the indicator flags for a phase.

    Returns (has_evidence, list_of_matched_flags).
    """
    matched: list[str] = []
    for attr, flags in indicator_flags.items():
        node_flags = node.get(attr, [])
        for flag in flags:
            if flag in node_flags:
                matched.append(f"{attr}:{flag}")
    return len(matched) > 0, matched


def _check_preconditions_via_graph(
    node_id: str,
    phase: KillChainPhase,
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
    phase_scores: dict[str, float],
) -> bool:
    """Check if a phase's graph-based preconditions are met.

    For lateral_movement: requires that a credential_access indicator
    exists on the node OR on a predecessor in the graph.

    For persistence: requires execution evidence on this node or a neighbor.

    General rule: required_prior_phases must have non-zero probability
    somewhere in the node's neighborhood (self + predecessors).
    """
    if not phase.required_prior_phases:
        return True

    for req_phase in phase.required_prior_phases:
        # Check if the required phase has been scored > 0 on this node
        if phase_scores.get(req_phase, 0.0) > 0:
            continue

        # Check predecessors in the graph for evidence of the required phase
        req_phase_def = _get_phase(req_phase)
        if req_phase_def is None:
            return False

        found_in_predecessor = False
        
        for graph in [it_graph, ot_graph]:
            if node_id in graph:
                for pred in graph.predecessors(node_id):
                    pred_node = graph.nodes.get(pred, {})
                    has_ev, _ = _has_indicator_evidence(
                        pred_node, req_phase_def.indicator_flags
                    )
                    if has_ev:
                        found_in_predecessor = True
                        break
            if found_in_predecessor:
                break

        if not found_in_predecessor:
            return False

    return True


def _get_phase(name: str) -> KillChainPhase | None:
    """Look up a kill-chain phase by name."""
    for p in KILL_CHAIN:
        if p.name == name:
            return p
    return None


# ---------------------------------------------------------------------------
# Campaign state distribution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CampaignStateDistribution:
    """Probability distribution over kill-chain phases for an entity."""

    node_id: str
    distribution: dict[str, float]   # phase_name → probability (sums to 1.0)
    evidence: list[dict[str, Any]]   # per-phase evidence details
    dominant_phase: str              # highest-probability phase
    dominant_probability: float


def compute_campaign_state(
    node_id: str,
    scorer_results: dict[str, float],
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> CampaignStateDistribution:
    """Compute the kill-chain state distribution for a single entity.

    Args:
        node_id: The graph node to analyze.
        scorer_results: Dict of scorer_class → score, e.g. {"identity": 0.95, ...}
        it_graph: IT-domain graph.
        ot_graph: OT-domain graph.

    Returns:
        CampaignStateDistribution with normalized probabilities and evidence.
    """
    # Find which graph(s) contain this node
    graph = it_graph if node_id in it_graph else ot_graph
    node = graph.nodes.get(node_id, {})

    # Phase 1: compute raw phase scores with precondition gating
    raw_scores: dict[str, float] = {}
    evidence: list[dict[str, Any]] = []

    # First pass — compute raw scores for phases without preconditions
    for phase in KILL_CHAIN:
        if phase.required_prior_phases:
            continue
        has_ev, matched = _has_indicator_evidence(node, phase.indicator_flags)
        if not has_ev:
            raw_scores[phase.name] = 0.0
            continue
        weighted = sum(
            scorer_results.get(sc, 0.0) * w
            for sc, w in phase.scorer_weights.items()
        )
        raw_scores[phase.name] = weighted if weighted >= phase.min_score_threshold else 0.0
        if raw_scores[phase.name] > 0:
            evidence.append({
                "phase": phase.name,
                "display_name": phase.display_name,
                "raw_score": round(weighted, 4),
                "matched_indicators": matched,
                "scorer_contributions": {
                    sc: round(scorer_results.get(sc, 0.0) * w, 4)
                    for sc, w in phase.scorer_weights.items()
                    if scorer_results.get(sc, 0.0) > 0
                },
            })

    # Second pass — compute scores for phases WITH preconditions
    for phase in KILL_CHAIN:
        if not phase.required_prior_phases:
            continue
        has_ev, matched = _has_indicator_evidence(node, phase.indicator_flags)
        if not has_ev:
            raw_scores[phase.name] = 0.0
            continue

        # Check graph preconditions
        precondition_met = _check_preconditions_via_graph(
            node_id, phase, it_graph, ot_graph, raw_scores
        )
        if not precondition_met:
            raw_scores[phase.name] = 0.0
            evidence.append({
                "phase": phase.name,
                "display_name": phase.display_name,
                "raw_score": 0.0,
                "matched_indicators": matched,
                "precondition_blocked": True,
                "required_prior": phase.required_prior_phases,
            })
            continue

        weighted = sum(
            scorer_results.get(sc, 0.0) * w
            for sc, w in phase.scorer_weights.items()
        )
        raw_scores[phase.name] = weighted if weighted >= phase.min_score_threshold else 0.0
        if raw_scores[phase.name] > 0:
            evidence.append({
                "phase": phase.name,
                "display_name": phase.display_name,
                "raw_score": round(weighted, 4),
                "matched_indicators": matched,
                "preconditions_satisfied": phase.required_prior_phases,
                "scorer_contributions": {
                    sc: round(scorer_results.get(sc, 0.0) * w, 4)
                    for sc, w in phase.scorer_weights.items()
                    if scorer_results.get(sc, 0.0) > 0
                },
            })

    # Add benign as a residual
    total_active = sum(raw_scores.values())
    if total_active <= 0:
        distribution = {"benign": 1.0}
        for phase in KILL_CHAIN:
            distribution[phase.name] = 0.0
        return CampaignStateDistribution(
            node_id=node_id,
            distribution=distribution,
            evidence=evidence,
            dominant_phase="benign",
            dominant_probability=1.0,
        )

    # Normalize: benign gets a share inversely proportional to total evidence
    benign_weight = max(0.0, 1.0 - total_active)
    all_weights = {"benign": benign_weight}
    all_weights.update(raw_scores)
    weight_sum = sum(all_weights.values())

    distribution = {k: round(v / weight_sum, 4) for k, v in all_weights.items()}

    # Find dominant phase
    dominant = max(distribution, key=lambda k: distribution[k])

    return CampaignStateDistribution(
        node_id=node_id,
        distribution=distribution,
        evidence=evidence,
        dominant_phase=dominant,
        dominant_probability=distribution[dominant],
    )
