"""RAKSHAK — Seven independent behavior-class scorers.

Each scorer examines node indicator attributes (set by the synthetic
incident) and produces an independent labeled score (0–1).  Scores are
**deterministic and rule-based** — no ML, no LLM (per rules.md).

Every score transparently logs which indicators contributed and by how
much, satisfying the "no silent scores" rule.

Scorer classes (per architecture.md §1):
    identity · credential · process · network · dns · cloud_api · ot_physics
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from app.simulation_state import get_active_simulation


# ---------------------------------------------------------------------------
# Scored result container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BehaviorScore:
    """Result from a single behavior scorer."""

    scorer_class: str
    node_id: str
    score: float                     # 0.0 – 1.0
    label: str                       # normal / suspicious / elevated / critical
    contributing_factors: list[str]   # ["flag_name:weight", …]


def _severity_label(score: float) -> str:
    """Map a raw score to a human-readable severity band."""
    if score < 0.15:
        return "normal"
    if score < 0.40:
        return "suspicious"
    if score < 0.70:
        return "elevated"
    return "critical"


# ---------------------------------------------------------------------------
# Shared scoring helpers
# ---------------------------------------------------------------------------

def _flag_score(
    node: dict[str, Any],
    flag_attr: str,
    weights: dict[str, float],
) -> tuple[float, list[str]]:
    """Sum weighted flags found in *node[flag_attr]*.

    Returns (partial_score, contributing_factors).
    """
    total = 0.0
    factors: list[str] = []
    for flag in node.get(flag_attr, []):
        w = weights.get(flag, 0.0)
        if w > 0:
            total += w
            factors.append(f"{flag}:{w:.2f}")
    return total, factors


def _count_score(
    node: dict[str, Any],
    attr: str,
    per_unit: float,
    cap: float,
    label: str,
) -> tuple[float, list[str]]:
    """Score based on a count attribute, capped at *cap*.

    Returns (partial_score, contributing_factors).
    """
    count = node.get(attr, 0)
    if count <= 0:
        return 0.0, []
    contribution = min(count * per_unit, cap)
    return contribution, [f"{label}({count}):{contribution:.2f}"]


def _compute_mad_score(
    node: dict[str, Any],
    baselines: dict[str, Any] | None,
    feature: str,
    cap: float = 1.0,
) -> tuple[float, list[str]]:
    """Score based on Median Absolute Deviation from a baseline.

    Returns (partial_score, contributing_factors).
    """
    if not baselines or feature not in baselines or feature not in node:
        return 0.0, []
    med, scale = baselines[feature]
    val = float(node[feature])
    deviation = abs(val - med) / scale if scale > 0 else 0
    
    # Sigmoid-like scaling or linear clipping for the Z-score.
    # Deviation of 3 = 0.3, 10 = 1.0.
    score = min((deviation / 10.0), cap)
    if score > 0.05:
        return score, [f"mad_dev({feature}={val:.2f}):{score:.2f}"]
    return 0.0, []


# ---------------------------------------------------------------------------
# Weight tables — each flag maps to its contribution towards the 0-1 score
# ---------------------------------------------------------------------------

IDENTITY_WEIGHTS: dict[str, float] = {
    "unusual_login":              0.25,
    "privilege_escalation":       0.40,
    "role_mismatch":              0.20,
    "unauthorized_access":        0.35,
    "new_admin_account":          0.30,
    "phishing_target":            0.15,
    "credential_theft_victim":    0.10,
    "unauthorized_bridge_access": 0.45,
}

CREDENTIAL_WEIGHTS: dict[str, float] = {
    "credential_dump":            0.50,
    "pass_the_hash":              0.45,
    "credential_compromised":     0.35,
    "unusual_auth":               0.20,
    "credential_reuse":           0.30,
    "brute_force":                0.25,
}

PROCESS_WEIGHTS: dict[str, float] = {
    "suspicious_executable":      0.35,
    "code_injection":             0.40,
    "remote_service_execution":   0.30,
    "new_local_account":          0.25,
    "scheduled_task":             0.20,
    "unauthorized_plc_write":     0.50,
    "reconnaissance_tool":        0.20,
}

NETWORK_WEIGHTS: dict[str, float] = {
    "port_scan_outbound":         0.30,
    "c2_communication":           0.45,
    "cross_zone_traffic":         0.35,
    "unexpected_rdp":             0.25,
    "smb_enumeration":            0.20,
    "unusual_smb_session":        0.20,
    "large_data_transfer":        0.30,
    "recon_activity":             0.15,
    "inbound_phishing":           0.20,
    "unusual_opc_ua":             0.40,
    "unauthorized_scan":          0.30,
    "protocol_anomaly":           0.25,
}

DNS_WEIGHTS: dict[str, float] = {
    "c2_callback":                0.45,
    "dns_tunneling":              0.50,
    "dga_detected":               0.40,
    "unusual_txt_query":          0.20,
}

CLOUD_API_WEIGHTS: dict[str, float] = {
    "unusual_data_query":         0.25,
    "bulk_export":                0.35,
    "api_enumeration":            0.20,
    "schema_discovery":           0.15,
    "historian_api_abuse":        0.40,
    "permission_escalation":      0.45,
}

OT_PHYSICS_WEIGHTS: dict[str, float] = {
    "unauthorized_setpoint_change": 0.50,
    "firmware_query":               0.25,
    "parameter_modification":       0.35,
    "reading_deviation":            0.30,
    "reconnaissance_detected":      0.20,
    "ot_network_scan":              0.25,
    "safety_limit_breach":          0.50,
}


# ---------------------------------------------------------------------------
# Individual scorers
# ---------------------------------------------------------------------------

def score_identity(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """Identity behavior scorer — unusual logins, privilege changes, role anomalies."""
    node = graph.nodes.get(node_id, {})
    total, factors = _flag_score(node, "identity_flags", IDENTITY_WEIGHTS)
    
    score = min(total, 1.0)
    return BehaviorScore(
        scorer_class="identity",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_credential(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """Credential behavior scorer — dumps, pass-the-hash, reuse."""
    node = graph.nodes.get(node_id, {})
    total, factors = _flag_score(node, "credential_flags", CREDENTIAL_WEIGHTS)
    
    mad_s, mad_f = _compute_mad_score(node, baselines, "auth_failures", cap=0.50)
    total += mad_s
    factors.extend(mad_f)

    score = min(total, 1.0)
    return BehaviorScore(
        scorer_class="credential",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_process(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """Process behavior scorer — suspicious executables, injections, PLC writes."""
    node = graph.nodes.get(node_id, {})
    flag_total, factors = _flag_score(node, "process_flags", PROCESS_WEIGHTS)

    # Bonus for number of distinct suspicious processes
    procs = node.get("suspicious_processes", [])
    proc_bonus = 0.0
    if procs:
        proc_bonus = min(len(procs) * 0.05, 0.15)
        factors.append(f"suspicious_process_count({len(procs)}):{proc_bonus:.2f}")

    mad_s, mad_f = _compute_mad_score(node, baselines, "process_rarity", cap=0.40)
    flag_total += mad_s
    factors.extend(mad_f)

    score = min(flag_total + proc_bonus, 1.0)
    return BehaviorScore(
        scorer_class="process",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_network(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """Network behavior scorer — port scans, C2, lateral, exfil, cross-zone."""
    node = graph.nodes.get(node_id, {})
    flag_total, factors = _flag_score(node, "network_flags", NETWORK_WEIGHTS)

    # Count-based: unusual connections
    conn_s, conn_f = _count_score(
        node, "unusual_connection_count",
        per_unit=0.04, cap=0.25, label="unusual_connections",
    )
    flag_total += conn_s
    factors.extend(conn_f)

    # Count-based: data exfil volume (normalized to 100 MB)
    exfil = node.get("data_exfil_bytes", 0.0)
    if exfil > 0:
        exfil_s = min(exfil / 100_000_000, 0.40)
        factors.append(f"data_exfil({exfil / 1e6:.1f}MB):{exfil_s:.2f}")
        flag_total += exfil_s

    mad_s1, mad_f1 = _compute_mad_score(node, baselines, "conn_rate", cap=0.40)
    mad_s2, mad_f2 = _compute_mad_score(node, baselines, "bytes_out", cap=0.40)
    flag_total += mad_s1 + mad_s2
    factors.extend(mad_f1 + mad_f2)

    score = min(flag_total, 1.0)
    return BehaviorScore(
        scorer_class="network",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_dns(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """DNS behavior scorer — C2 callbacks, DGA domains, tunneling."""
    node = graph.nodes.get(node_id, {})
    flag_total, factors = _flag_score(node, "dns_flags", DNS_WEIGHTS)

    # Count-based: DGA domain count
    dga_s, dga_f = _count_score(
        node, "dga_domain_count",
        per_unit=0.12, cap=0.50, label="dga_domains",
    )
    flag_total += dga_s
    factors.extend(dga_f)

    mad_s, mad_f = _compute_mad_score(node, baselines, "dns_entropy", cap=0.40)
    flag_total += mad_s
    factors.extend(mad_f)

    score = min(flag_total, 1.0)
    return BehaviorScore(
        scorer_class="dns",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_cloud_api(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """Cloud-API behavior scorer — unusual queries, bulk exports, API abuse."""
    node = graph.nodes.get(node_id, {})
    flag_total, factors = _flag_score(node, "cloud_api_flags", CLOUD_API_WEIGHTS)

    # Count-based: unusual API call count
    api_s, api_f = _count_score(
        node, "unusual_api_call_count",
        per_unit=0.04, cap=0.25, label="unusual_api_calls",
    )
    flag_total += api_s
    factors.extend(api_f)

    mad_s, mad_f = _compute_mad_score(node, baselines, "api_burst", cap=0.40)
    flag_total += mad_s
    factors.extend(mad_f)

    score = min(flag_total, 1.0)
    return BehaviorScore(
        scorer_class="cloud_api",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


def score_ot_physics(node_id: str, graph: nx.DiGraph, baselines: dict[str, Any] | None = None) -> BehaviorScore:
    """OT-physics behavior scorer — setpoint changes, sensor deviations, interlocks."""
    node = graph.nodes.get(node_id, {})
    flag_total, factors = _flag_score(node, "ot_physics_flags", OT_PHYSICS_WEIGHTS)

    # Count-based: unauthorized command count
    cmd_s, cmd_f = _count_score(
        node, "unauthorized_command_count",
        per_unit=0.12, cap=0.35, label="unauthorized_cmds",
    )
    flag_total += cmd_s
    factors.extend(cmd_f)

    # Continuous: sensor deviation percentage
    deviation = node.get("sensor_deviation_pct", 0.0)
    if deviation > 0:
        dev_s = min(deviation * 0.60, 0.50)
        factors.append(f"sensor_deviation({deviation:.0%}):{dev_s:.2f}")
        flag_total += dev_s

    mad_s, mad_f = _compute_mad_score(node, baselines, "ot_deviation", cap=0.40)
    flag_total += mad_s
    factors.extend(mad_f)

    score = min(flag_total, 1.0)
    return BehaviorScore(
        scorer_class="ot_physics",
        node_id=node_id,
        score=round(score, 4),
        label=_severity_label(score),
        contributing_factors=factors,
    )


# ---------------------------------------------------------------------------
# Registry — ordered list for convenient iteration
# ---------------------------------------------------------------------------

ALL_SCORERS = [
    score_identity,
    score_credential,
    score_process,
    score_network,
    score_dns,
    score_cloud_api,
    score_ot_physics,
]


# ---------------------------------------------------------------------------
# Aggregate helper
# ---------------------------------------------------------------------------

def score_all(
    node_id: str,
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
    baselines: dict[str, Any] | None = None
) -> list[BehaviorScore]:
    """Run all 7 scorers for *node_id*.

    The node is looked up in both graphs.  If it exists in both (bridge
    nodes), each graph's instance is scored and the per-class **maximum**
    is taken so no signal is lost.
    """
    in_it = node_id in it_graph
    in_ot = node_id in ot_graph

    if not in_it and not in_ot:
        # Unknown node — return zeros
        return [
            BehaviorScore(
                scorer_class=fn.__name__.removeprefix("score_"),
                node_id=node_id,
                score=0.0,
                label="normal",
                contributing_factors=[],
            )
            for fn in ALL_SCORERS
        ]

    # For testing and scenarios where active simulation might not be present, wrap in try/except or fallback
    try:
        intensity_multiplier = max(0.2, get_active_simulation().attack_intensity / 5.0)
    except Exception:
        intensity_multiplier = 1.0

    results: list[BehaviorScore] = []
    for scorer_fn in ALL_SCORERS:
        candidates: list[BehaviorScore] = []
        if in_it:
            candidates.append(scorer_fn(node_id, it_graph, baselines))
        if in_ot:
            candidates.append(scorer_fn(node_id, ot_graph, baselines))
        # Take the highest score across graph instances
        best = max(candidates, key=lambda s: s.score)
        
        # Apply attack intensity scaling before capping at 1.0
        # Rebuild the BehaviorScore with the scaled score and updated label
        scaled_score = min(best.score * intensity_multiplier, 1.0)
        best = BehaviorScore(
            scorer_class=best.scorer_class,
            node_id=best.node_id,
            score=round(scaled_score, 4),
            label=_severity_label(scaled_score),
            contributing_factors=best.contributing_factors + [f"intensity_scaling(x{intensity_multiplier:.1f})"] if best.score > 0 and intensity_multiplier != 1.0 else best.contributing_factors
        )
        results.append(best)

    return results
