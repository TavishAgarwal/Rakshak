"""RAKSHAK — Resilience score formula.

headline_metric = f(redundancy_coverage, degraded_mode_availability,
                     mean_recovery_time, service_continuity_last_N)

Pure, unit-testable function (per rules.md).  Shown continuously on the
dashboard, not just post-incident.

Each component is 0-100 (higher = more resilient).  The composite is a
weighted combination that produces the headline metric.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from datetime import datetime

import networkx as nx

from app.audit.log import get_audit_log

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WEIGHTS = {
    "redundancy_coverage": 0.25,
    "degraded_mode_availability": 0.25,
    "mean_recovery_time": 0.20,
    "service_continuity": 0.30,
}

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResilienceResult:
    """Resilience score breakdown — 0-100 values."""

    score: float                          # weighted composite 0-100
    breakdown: dict[str, float]           # individual components for UI
    assessment: str                       # healthy / degraded / at_risk / critical


# ---------------------------------------------------------------------------
# Component calculators
# ---------------------------------------------------------------------------

def _compute_redundancy_coverage(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> float:
    """% of critical services that have a registered degraded-mode fallback path."""
    
    total_critical = 0
    redundant_critical = 0

    all_nodes = list(it_graph.nodes(data=True)) + list(ot_graph.nodes(data=True))
    
    for _, data in all_nodes:
        is_critical = (
            data.get("human_dependency") == "high" 
            or data.get("public_safety_impact") == "high"
        )
        if is_critical:
            total_critical += 1
            if data.get("has_fallback_path", False) or data.get("fallback_path"):
                redundant_critical += 1

    if total_critical == 0:
        return 100.0

    return (redundant_critical / total_critical) * 100.0


def _compute_degraded_mode_availability(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> float:
    """% of currently-flagged/impacted services that CAN run in degraded mode right now."""
    
    impacted = 0
    impacted_with_degraded = 0

    flag_attributes = [
        "identity_flags", "credential_flags", "process_flags",
        "network_flags", "dns_flags", "cloud_api_flags",
        "ot_physics_flags", "anomaly_score"
    ]

    all_nodes = list(it_graph.nodes(data=True)) + list(ot_graph.nodes(data=True))

    for _, data in all_nodes:
        # Check if node has any active incident flags or non-zero anomaly score
        is_impacted = any(data.get(attr) for attr in flag_attributes)
        
        if is_impacted:
            impacted += 1
            if data.get("has_fallback_path", False) or data.get("fallback_path"):
                impacted_with_degraded += 1

    if impacted == 0:
        return 100.0

    return (impacted_with_degraded / impacted) * 100.0


def _compute_mean_recovery_time(last_n: int = 10) -> float:
    """Average time from AuditEntry.action_taken=="contain" to the matching "verified" entry.
    
    Returns a score mapped to 0-100 (100 = fast recovery).
    """
    entries = get_audit_log(limit=1000)
    
    # We will try to match 'contain' and 'verified' events for the same node_id
    contain_times: dict[str, datetime] = {}
    recovery_durations: list[float] = []

    for entry in entries:
        action = entry.get("action_taken")
        if not action:
            continue
            
        node_id = entry.get("node_id")
        ts_str = entry.get("timestamp")
        
        if not node_id or not ts_str:
            continue
            
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            continue

        if action == "contain":
            # If there's an older contain, we might want the first one or latest, let's keep the earliest
            if node_id not in contain_times or ts < contain_times[node_id]:
                contain_times[node_id] = ts
                
        elif action == "verified":
            if node_id in contain_times:
                diff = (ts - contain_times[node_id]).total_seconds()
                # If diff is negative (logs out of order or multiple incidents), take abs
                recovery_durations.append(abs(diff))

    # Take the last N incidents
    recent_durations = recovery_durations[-last_n:] if recovery_durations else []
    
    if not recent_durations:
        return 75.0  # No incident recovery data yet — assume moderate capability

    mean_duration_sec = sum(recent_durations) / len(recent_durations)
    mean_duration_min = mean_duration_sec / 60.0

    # Mapping: <10m = 100%, <30m = 80%, <60m = 50%, >60m = decays to 0
    if mean_duration_min <= 10:
        return 100.0
    elif mean_duration_min <= 30:
        return 100.0 - ((mean_duration_min - 10) / 20.0) * 20.0 # 80 to 100
    elif mean_duration_min <= 60:
        return 80.0 - ((mean_duration_min - 30) / 30.0) * 30.0 # 50 to 80
    else:
        # decays from 50 to 0
        return max(0.0, 50.0 - ((mean_duration_min - 60) / 60.0) * 50.0)


def _compute_service_continuity(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> float:
    """% uptime maintained (not fully down) during last incidents.
    
    We map "not fully down" as critical services avoiding full outage.
    Since uptime history might not exist purely in graphs, we evaluate
    current active services vs total critical services.
    """
    all_nodes = list(it_graph.nodes(data=True)) + list(ot_graph.nodes(data=True))
    
    critical_total = 0
    critical_serving = 0
    
    flag_attributes = [
        "identity_flags", "credential_flags", "process_flags",
        "network_flags", "dns_flags", "cloud_api_flags",
        "ot_physics_flags", "anomaly_score"
    ]

    for _, data in all_nodes:
        is_critical = (
            data.get("human_dependency") == "high" 
            or data.get("public_safety_impact") == "high"
        )
        if is_critical:
            critical_total += 1
            
            is_impacted = any(data.get(attr) for attr in flag_attributes)
            has_fallback = data.get("has_fallback_path", False) or data.get("fallback_path")
            
            # Explicit down status takes precedence
            is_down = data.get("status") == "down" or data.get("is_down", False)
            
            # If it's down, OR it's impacted and lacks a fallback, it's not serving
            if is_down or (is_impacted and not has_fallback):
                pass
            else:
                critical_serving += 1

    if critical_total == 0:
        return 100.0

    return (critical_serving / critical_total) * 100.0


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def compute_resilience_score(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> ResilienceResult:
    """Compute the headline resilience score and all components.

    Formula: headline = w₁·redundancy + w₂·degraded_mode + w₃·recovery + w₄·continuity
    All outputs are 0-100 metrics.
    """
    red = _compute_redundancy_coverage(it_graph, ot_graph)
    deg = _compute_degraded_mode_availability(it_graph, ot_graph)
    rec = _compute_mean_recovery_time()
    cont = _compute_service_continuity(it_graph, ot_graph)

    headline = (
        red * WEIGHTS["redundancy_coverage"]
        + deg * WEIGHTS["degraded_mode_availability"]
        + rec * WEIGHTS["mean_recovery_time"]
        + cont * WEIGHTS["service_continuity"]
    )

    # Assessment bands based on 0-100 scale
    if headline >= 80.0:
        assessment = "healthy"
    elif headline >= 60.0:
        assessment = "degraded"
    elif headline >= 40.0:
        assessment = "at_risk"
    else:
        assessment = "critical"

    return ResilienceResult(
        score=round(headline, 1),
        breakdown={
            "redundancy_coverage": round(red, 1),
            "degraded_mode_availability": round(deg, 1),
            "mean_recovery_time": round(rec, 1),
            "service_continuity": round(cont, 1),
        },
        assessment=assessment,
    )
