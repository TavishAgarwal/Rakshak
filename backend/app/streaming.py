"""RAKSHAK — WebSocket streaming for incident replay.

Replays the Phase 2 synthetic incident over a compressed ~90-second timeline,
pushing graph deltas and updated entity scores as each event occurs.

Protocol:
    1. Client connects to WS /stream
    2. Server sends a "stream_start" message with timeline metadata
    3. For each event in the incident timeline:
       a. Wait the appropriate compressed interval
       b. Apply the event to the graph
       c. Compute updated scores/fusion/gate for all affected nodes
       d. Push an "event" message with the delta
    4. After the last event, send "stream_end" with final resilience score

Message format (JSON):
    {
        "type": "stream_start" | "event" | "resilience_update" | "stream_end",
        "timestamp": <float>,         # incident timeline position (0-90s)
        "wall_clock": <ISO string>,   # actual UTC time
        "data": { ... }
    }
"""

from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone
from typing import Any

import networkx as nx
from fastapi import WebSocket, WebSocketDisconnect

from app.graph import (
    get_it_graph, get_ot_graph, initialize_graphs, reset_graphs,
    build_steady_state_it_graph, build_steady_state_ot_graph,
    save_graph, _IT_GRAPH_PATH, _OT_GRAPH_PATH,
)
from app.data.synthetic_incident import (
    get_incident_timeline, apply_single_event, init_defaults_only,
    apply_incident,
)
from app.simulation_state import get_active_simulation
from app.scoring.behavior_classes import score_all
from app.scoring.mission_criticality import compute_criticality
from app.fusion.dempster_shafer import fuse_scores
from app.campaign.state_machine import compute_campaign_state
from app.response.gate import evaluate_gate
from app.resilience.score import compute_resilience_score
from app.audit.log import log_fusion_event, log_gate_decision, log_resilience_event


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resilience_payload(score_result) -> dict[str, Any]:
    """Frontend contract for resilience updates."""
    return {
        "score": score_result.score,
        "headline_score": score_result.score,
        "assessment": score_result.assessment,
        "breakdown": score_result.breakdown,
        "components": score_result.breakdown,
    }


def _compute_node_snapshot(
    node_id: str,
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
    stealth_dampener: float = 0.8,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Compute the full scoring snapshot for a single node."""
    in_it = node_id in it_graph
    in_ot = node_id in ot_graph
    if not in_it and not in_ot:
        return {"node_id": node_id, "error": "not_found"}

    scores = score_all(node_id, it_graph, ot_graph)
    scorer_dict = {s.scorer_class: s.score for s in scores}

    ds = fuse_scores([(s.scorer_class, s.score) for s in scores], default_reliability=stealth_dampener)
    crit = compute_criticality(node_id, it_graph, ot_graph)
    campaign = compute_campaign_state(node_id, scorer_dict, it_graph, ot_graph)
    gate = evaluate_gate(
        node_id=node_id,
        asset_type=crit.asset_type,
        confidence=ds.belief,
        criticality_composite=crit.composite_score,
        safety_impact=crit.safety_impact,
    )

    # Audit log
    log_fusion_event(
        node_id=node_id,
        belief=ds.belief, plausibility=ds.plausibility,
        uncertainty=ds.uncertainty, conflict=ds.conflict,
        sources=ds.sources, scorer_scores=scorer_dict,
        context={"run_id": run_id} if run_id else None,
    )
    log_gate_decision(
        node_id=node_id, asset_type=crit.asset_type,
        confidence=ds.belief, criticality=crit.composite_score,
        risk_tier=gate.risk_tier,
        allowed_actions=gate.allowed_actions,
        blocked_actions=gate.blocked_actions,
        requires_escalation=gate.requires_human_escalation,
        escalation_reason=gate.escalation_reason,
        rationale=gate.rationale,
        context={"run_id": run_id} if run_id else None,
    )

    return {
        "node_id": node_id,
        "graph_domain": "IT+OT" if (in_it and in_ot) else ("IT" if in_it else "OT"),
        "scores": {s.scorer_class: s.score for s in scores},
        "fusion": {
            "belief": ds.belief,
            "plausibility": ds.plausibility,
            "uncertainty": ds.uncertainty,
            "conflict": ds.conflict,
        },
        "criticality": {
            "composite_score": crit.composite_score,
            "safety_impact": crit.safety_impact,
            "asset_type": crit.asset_type,
        },
        "campaign": {
            "dominant_phase": campaign.dominant_phase,
            "dominant_probability": campaign.dominant_probability,
        },
        "gate": {
            "risk_tier": gate.risk_tier,
            "requires_human_escalation": gate.requires_human_escalation,
            "blocked_actions": gate.blocked_actions,
        },
    }


async def stream_incident(websocket: WebSocket) -> None:
    """Main WebSocket handler — replays the scripted incident.

    Query params:
        speed: float — compression factor (default 1.0 = ~90s real-time).
               Use speed=10 for ~9s fast-forward, speed=0.5 for ~180s slow-mo.
    """
    await websocket.accept()

    # Parse speed from query string
    speed_str = websocket.query_params.get("speed", "1.0")
    try:
        speed = float(speed_str)
        speed = max(0.1, min(speed, 100.0))
    except ValueError:
        speed = 1.0

    timeline = get_incident_timeline()

    # --- Build fresh graphs for this stream session ---
    # We work on copies so the main server graphs stay intact
    it_fresh = build_steady_state_it_graph()
    ot_fresh = build_steady_state_ot_graph()
    init_defaults_only(it_fresh, ot_fresh)

    run_id = f"sim_{int(datetime.now(timezone.utc).timestamp())}"
    sim = get_active_simulation()
    stealth_dampener = max(0.1, min(1.0, 0.8 - (sim.stealth_vector - 5.0) * 0.1))
    cadence_multiplier = max(0.2, min(2.0, 1.0 - (sim.attack_intensity - 5.0) * 0.15))
    intensity_multiplier = max(0.2, sim.attack_intensity / 5.0)

    try:
        # ── stream_start ─────────────────────────────────────────
        initial_resilience = compute_resilience_score(it_fresh, ot_fresh)
        await websocket.send_json({
            "type": "stream_start",
            "timestamp": 0.0,
            "wall_clock": _now_iso(),
            "data": {
                "total_events": len(timeline),
                "timeline_duration_s": timeline[-1].timestamp if timeline else 0,
                "speed_factor": speed,
                "estimated_wall_time_s": round(
                    (timeline[-1].timestamp if timeline else 0) / speed * cadence_multiplier, 1
                ),
                "run_id": run_id,
                "config": sim.dict(),
                "initial_resilience": {
                    "headline_score": initial_resilience.score,
                    "assessment": initial_resilience.assessment,
                    "breakdown": initial_resilience.breakdown,
                },
            },
        })

        # ── Event replay loop ────────────────────────────────────
        prev_ts = 0.0
        current_resilience = initial_resilience
        for idx, event in enumerate(timeline):
            # Wait compressed interval
            delay = (event.timestamp - prev_ts) / speed * cadence_multiplier
            if delay > 0:
                await asyncio.sleep(delay)
            prev_ts = event.timestamp

            # Apply this event
            affected_nodes = apply_single_event(event, it_fresh, ot_fresh, intensity_multiplier=intensity_multiplier)

            # Compute snapshots for all affected nodes
            node_updates: list[dict[str, Any]] = []
            for nid in affected_nodes:
                snap = _compute_node_snapshot(nid, it_fresh, ot_fresh, stealth_dampener=stealth_dampener, run_id=run_id)
                node_updates.append(snap)
                
            # Recompute resilience
            new_resilience = compute_resilience_score(it_fresh, ot_fresh)
            resilience_payload = None
            if new_resilience.score != current_resilience.score or new_resilience.breakdown != current_resilience.breakdown:
                resilience_payload = {
                    "before": {
                        "score": current_resilience.score,
                        "assessment": current_resilience.assessment,
                        "breakdown": current_resilience.breakdown,
                    },
                    "after": {
                        "score": new_resilience.score,
                        "assessment": new_resilience.assessment,
                        "breakdown": new_resilience.breakdown,
                    },
                }
                current_resilience = new_resilience
                log_resilience_event(
                    headline_score=new_resilience.score,
                    components=new_resilience.breakdown,
                    assessment=new_resilience.assessment,
                    context={"run_id": run_id},
                )

            # Push event message
            await websocket.send_json({
                "type": "event",
                "timestamp": event.timestamp,
                "wall_clock": _now_iso(),
                "data": {
                    "event_index": idx + 1,
                    "total_events": len(timeline),
                    "source_node": event.source_node,
                    "target_node": event.target_node,
                    "event_type": event.event_type,
                    "mitre_tactic": event.mitre_tactic,
                    "mitre_technique": event.mitre_technique,
                    "description": event.description,
                    "graph_domain": event.graph_domain,
                    "run_id": run_id,
                    "affected_nodes": node_updates,
                    "resilience_update": resilience_payload,
                },
            })

            # Push resilience update every 3 events or on the last event
            if (idx + 1) % 3 == 0 or idx == len(timeline) - 1:
                res = compute_resilience_score(it_fresh, ot_fresh)
                log_resilience_event(
                    headline_score=res.score,
                    components=res.breakdown,
                    assessment=res.assessment,
                )
                await websocket.send_json({
                    "type": "resilience_update",
                    "timestamp": event.timestamp,
                    "wall_clock": _now_iso(),
                    "data": _resilience_payload(res),
                })

        # ── stream_end ───────────────────────────────────────────
        final_resilience = compute_resilience_score(it_fresh, ot_fresh)
        await websocket.send_json({
            "type": "stream_end",
            "timestamp": timeline[-1].timestamp if timeline else 0,
            "wall_clock": _now_iso(),
            "data": {
                "events_delivered": len(timeline),
                "final_resilience": _resilience_payload(final_resilience),
            },
        })

    except WebSocketDisconnect:
        pass  # Client disconnected — clean exit
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "wall_clock": _now_iso(),
                "data": {"message": str(e)},
            })
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
