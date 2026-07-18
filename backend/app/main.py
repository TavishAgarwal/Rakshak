"""RAKSHAK — FastAPI application entry point.

WS + REST routes will be registered here in later phases.
"""

from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
from hmac import compare_digest
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, Depends
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.graph import initialize_graphs, combined_snapshot, get_it_graph, get_ot_graph
from app.data.synthetic_incident import init_defaults_only
from app.demo_data import (
    advance_demo,
    get_entity as get_demo_entity,
    get_entity_events,
    init_demo_db,
    list_entities as list_demo_entities,
)
from app.scoring.baseline import BaselineScore, overall_anomaly, score_entity
from app.scoring.behavior_classes import score_all
from app.scoring.mission_criticality import compute_criticality
from app.campaign.state_machine import compute_campaign_state
from app.attck.mapper import match_campaign
from app.response.gate import evaluate_gate
from app.response.gate import decide_response, execute_response_action
from app.response.playbooks import run_mock_playbook
from app.response.policy_engine import get_policy, list_policies, policy_adjusted_threshold
from app.response.soar_state import get_soar_state
from app.resilience.score import compute_resilience_score
from app.audit.log import (
    log_fusion_event, log_gate_decision, log_resilience_event,
    get_audit_log, clear_audit_log,
)
from app.audit.chain import append_audit_entry, get_audit_chain, verify_audit_chain
from app.streaming import stream_incident
from app.narration.claude_client import narrate
from app.fusion.dempster_shafer import fuse_scores, to_bpa, ds_combine, belief_plausibility
from app.evaluation import compute_ps7_summary
from app.threat_intel import load_advisories, load_scenarios, match_advisories
from app.simulation_state import SimulationConfig, get_active_simulation, set_active_simulation
from app.auth import (
    get_current_active_user, require_analyst, require_operator, require_admin, require_viewer,
    UserRole, verify_password, authenticate_user, create_access_token,
    FAKE_USERS_DB, JWTError, jwt, SECRET_KEY, ALGORITHM
)
import time


def _authorize_response_execution(authorization: str | None) -> None:
    """Require an env-configured bearer token before response actions can run."""
    expected_token = os.getenv("RAKSHAK_RESPONSE_API_TOKEN")
    if not expected_token:
        raise HTTPException(
            status_code=403,
            detail="Response execution is disabled until RAKSHAK_RESPONSE_API_TOKEN is configured.",
        )

    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(
            status_code=401,
            detail="Missing bearer token for response execution.",
        )

    provided_token = authorization[len(prefix):]
    if not compare_digest(provided_token, expected_token):
        raise HTTPException(
            status_code=403,
            detail="Invalid bearer token for response execution.",
        )


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle — initialize graphs and apply incident."""
    initialize_graphs(force=True)
    init_defaults_only(get_it_graph(), get_ot_graph())
    init_demo_db(reset=True)
    # Clear stale audit log from previous runs, then log initial resilience
    clear_audit_log()
    _log_initial_resilience()
    yield


def _log_initial_resilience() -> None:
    """Compute and audit-log the initial resilience score at startup."""
    result = compute_resilience_score(get_it_graph(), get_ot_graph())
    log_resilience_event(
        headline_score=result.score,
        components=result.breakdown,
        assessment=result.assessment,
    )


app = FastAPI(
    title="RAKSHAK",
    description="AI-Driven Cyber Resilience Intelligence Platform for Indian CNI",
    version="0.1.0",
    lifespan=lifespan,
)

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/token")
async def login(form_data: LoginRequest):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# Add rate limiting middleware
app.add_middleware(SlowAPIMiddleware)

# ═══════════════════════════════════════════════════════════════════
# Security headers middleware (Must-Fix #7 from security audit)
# ═══════════════════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security-hardening HTTP headers on every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        headers = {
            # Prevent MIME-type sniffing
            "X-Content-Type-Options": "nosniff",
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            # Enable browser XSS filter
            "X-XSS-Protection": "1; mode=block",
            # Restrict referrer information
            "Referrer-Policy": "strict-origin-when-cross-origin",
            # Only allow this origin to embed (enforced by browsers)
            "X-Permitted-Cross-Domain-Policies": "none",
            # Prevent Flash / cross-domain requests
            "Cross-Origin-Resource-Policy": "same-origin",
        }

        # HSTS: only set on HTTPS connections (skip during local dev)
        if request.url.scheme == "https":
            headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # CSP: restrict script/style sources to self + inline (for D3/plots).
        # In production, tighten `script-src` by removing 'unsafe-inline'.
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws://localhost:* http://localhost:*; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )

        for header_name, header_value in headers.items():
            response.headers.setdefault(header_name, header_value)

        return response


app.add_middleware(SecurityHeadersMiddleware)

# Load environment variables
load_dotenv()

# Get allowed origins from environment, default to localhost for development
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001,http://localhost:3002,http://localhost:3010")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from app.simulation_state import session_id_var
import threading
import uuid

_demo_contexts: dict[str, dict[str, Any]] = {}
_demo_lock = threading.RLock()

def get_demo_context() -> dict[str, Any]:
    sid = session_id_var.get()
    with _demo_lock:
        if sid not in _demo_contexts:
            _demo_contexts[sid] = {
                "org_id": "national-grid-cni",
                "facility_id": "grid-west-01",
                "sector": "power",
                "policy_id": "power_grid",
                "scenario_id": "power_grid_ot_pivot",
            }
        return _demo_contexts[sid]

class SessionContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        session_id = request.cookies.get("rakshak_session")
        if not session_id:
            session_id = str(uuid.uuid4())
        session_id_var.set(session_id)
        response: Response = await call_next(request)
        response.set_cookie("rakshak_session", session_id, httponly=True, samesite="lax")
        return response

app.add_middleware(SessionContextMiddleware)


class LimitRequestSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Set limit to 5 MB
        max_content_length = 5 * 1024 * 1024  # 5 MB
        if request.headers.get("content-length"):
            content_length = int(request.headers.get("content-length"))
            if content_length > max_content_length:
                return Response(
                    content="Request body too large",
                    status_code=413,
                    media_type="text/plain",
                )
        # If no content-length header, we could read the body but that would consume it.
        # For simplicity, we rely on content-length; chunked transfers without content-length
        # will be accepted but limited by server's read limits.
        return await call_next(request)


app.add_middleware(LimitRequestSizeMiddleware)



def _node_payload(node_id: str, data: dict[str, Any], graph_domain: str) -> dict[str, Any]:
    payload = dict(data)
    payload["id"] = node_id
    payload["graph_domain"] = graph_domain
    for key in ("org_id", "facility_id", "sector", "policy_id"):
        payload.setdefault(key, get_demo_context()[key])
    return payload


def _audit_sources_from_scores(ds_result: Any, scores: list[Any]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for src in getattr(ds_result, "sources", []):
        sources.append({
            "source": src.get("scorer_class", "unknown"),
            "weight": src.get("raw_score", 0.0),
            "mass_malicious": src.get("mass_malicious"),
            "mass_theta": src.get("mass_theta"),
        })
    if not sources:
        sources = [{"source": s.scorer_class, "weight": s.score} for s in scores if s.score > 0]
    return sources


def _current_policy() -> dict[str, Any]:
    return get_policy(get_demo_context()["policy_id"])


def _current_scenario() -> dict[str, Any]:
    return next(
        (scenario for scenario in load_scenarios() if scenario["id"] == get_demo_context()["scenario_id"]),
        load_scenarios()[0],
    )


def _audit_context() -> dict[str, str]:
    ctx = {
        "org_id": get_demo_context()["org_id"],
        "facility_id": get_demo_context()["facility_id"],
        "policy_id": get_demo_context()["policy_id"],
    }
    sim = get_active_simulation()
    if hasattr(sim, 'run_id') and sim.run_id:
        ctx["run_id"] = sim.run_id
    return ctx


def _iter_graph_nodes() -> list[tuple[str, dict[str, Any], str, bool]]:
    """Return IT nodes plus OT-only nodes; bridge nodes exist in both graphs."""
    it = get_it_graph()
    ot = get_ot_graph()
    nodes = [(node_id, data, "IT", False) for node_id, data in it.nodes.items()]
    nodes.extend((node_id, data, "OT", True) for node_id, data in ot.nodes.items() if node_id not in it)
    seen = {node_id for node_id, _data, _domain, _is_ot in nodes}
    for entity in list_demo_entities():
        if entity["id"] in seen:
            continue
        domain = "OT" if entity["domain"] == "OT" else "IT"
        nodes.append((
            entity["id"],
            {"id": entity["id"], "label": entity["label"], "node_type": entity["type"], "mission_criticality": entity["mission_criticality"]},
            domain,
            domain == "OT",
        ))
    return nodes


def _fused_scores(node_id: str) -> tuple[list[Any], Any]:
    demo_entity = get_demo_entity(node_id)
    if demo_entity:
        scores = score_entity(node_id)
        return scores, _fuse_baseline_scores(scores)
    it = get_it_graph()
    ot = get_ot_graph()
    scores = score_all(node_id, it, ot)
    
    # Calculate reliability dampening from stealth_vector
    # stealth_vector = 5 -> reliability = 0.8
    # stealth_vector = 10 -> reliability = 0.3
    # stealth_vector = 0 -> reliability = 1.0 (min 0.1, max 1.0)
    stealth_dampener = max(0.1, min(1.0, 0.8 - (get_active_simulation().stealth_vector - 5.0) * 0.1))
    
    return scores, fuse_scores([(s.scorer_class, s.score) for s in scores], default_reliability=stealth_dampener)


def _level_score(value: str) -> float:
    return {"low": 0.2, "medium": 0.55, "high": 0.9}.get(str(value).lower(), 0.2)


def _mission_from_demo_entity(entity: dict[str, Any]) -> dict[str, Any]:
    safety = _level_score(entity["public_safety_impact"])
    human = _level_score(entity["human_dependency"])
    composite = float(entity["mission_criticality"])
    return {
        "operational_importance": human,
        "data_sensitivity": 0.7 if entity["domain"] != "OT" else 0.45,
        "connectivity_risk": 0.85 if entity["domain"] in ("IT_OT_BRIDGE", "OT") else 0.65,
        "safety_impact": safety,
        "recovery_difficulty": composite,
        "composite_score": composite,
        "asset_type": "OT" if entity["domain"] == "OT" else ("IT_OT_BRIDGE" if entity["domain"] == "IT_OT_BRIDGE" else "IT"),
        "public_safety_impact": entity["public_safety_impact"],
        "human_dependency": entity["human_dependency"],
    }


def _fuse_baseline_scores(scores: list[BaselineScore]) -> dict[str, Any]:
    # Calculate reliability dampening from stealth_vector
    stealth_dampener = max(0.1, min(1.0, 0.8 - (get_active_simulation().stealth_vector - 5.0) * 0.1))

    bpas: list[dict[str, float]] = []
    per_source: list[dict[str, Any]] = []
    for score in scores:
        reliability = 0.0 if score.status != "computed" else stealth_dampener
        bpa = to_bpa(score.raw_score, reliability)
        bpas.append(bpa)
        per_source.append({
            "source": score.behavior_class,
            "scorer_class": score.behavior_class,
            "raw_score": score.raw_score,
            "status": score.status,
            "detail": score.detail,
            "bpa": bpa,
            "mass_malicious": round(bpa["Malicious"], 4),
            "mass_benign": round(bpa["Benign"], 4),
            "mass_theta": round(bpa["Uncertain"], 4),
            "weight": score.raw_score,
        })
    combined = ds_combine(bpas)
    metrics = belief_plausibility(combined)
    return {
        "per_source_bpa": per_source,
        "sources": per_source,
        "belief": round(metrics["belief"], 4),
        "plausibility": round(metrics["plausibility"], 4),
        "uncertainty": round(metrics["uncertainty"], 4),
        "conflict": round(metrics["conflict"], 4),
    }


def _demo_entity_payload(node_id: str) -> dict[str, Any] | None:
    entity = get_demo_entity(node_id)
    if not entity:
        return None
    scores = score_entity(node_id)
    fusion = _fuse_baseline_scores(scores)
    mission = _mission_from_demo_entity(entity)
    campaign = match_campaign(get_entity_events(node_id))
    gate = evaluate_gate(
        node_id=node_id,
        asset_type=mission["asset_type"],
        confidence=fusion["belief"],
        criticality_composite=mission["composite_score"],
        safety_impact=mission["safety_impact"],
    )
    evidence_log = [
        {
            "source": score.behavior_class,
            "raw_score": score.raw_score,
            "label": score.status,
            "contributing_factors": [score.detail],
        }
        for score in scores
    ]
    distribution = campaign.get("campaign_state", {"benign": 1.0})
    dominant_phase = campaign.get("dominant_phase") or max(distribution, key=distribution.get)
    return {
        "node_id": node_id,
        "graph_domain": entity["domain"],
        "mission_criticality": mission,
        "campaign_state": {
            "status": campaign["status"],
            "distribution": distribution,
            "dominant_phase": dominant_phase,
            "dominant_probability": campaign.get("dominant_probability", distribution.get(dominant_phase, 0.0)),
            "matched_techniques": campaign.get("matched_techniques", []),
            "raw_evidence": campaign.get("raw_evidence", []),
            "phase_evidence": [],
        },
        "fusion": {
            "belief": fusion["belief"],
            "plausibility": fusion["plausibility"],
            "uncertainty": fusion["uncertainty"],
            "conflict": fusion["conflict"],
            "sources": fusion["sources"],
            "per_source_bpa": fusion["per_source_bpa"],
        },
        "response_gate": {
            "risk_tier": gate.risk_tier,
            "allowed_actions": gate.allowed_actions,
            "blocked_actions": gate.blocked_actions,
            "requires_human_escalation": gate.requires_human_escalation,
            "escalation_reason": gate.escalation_reason,
            "rationale": gate.rationale,
        },
        "policy": _current_policy(),
        "evidence_log": evidence_log,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check(_: dict = Depends(require_viewer)) -> dict[str, str]:
    """Health check endpoint — confirms the backend is running."""
    return {"status": "ok", "service": "rakshak-backend"}


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

@app.get("/graph")
async def get_graph(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the combined IT+OT graph snapshot.

    Each node includes a `graph_domain` field ("IT" or "OT") so the
    frontend can distinguish them visually.
    """
    return combined_snapshot()


# ---------------------------------------------------------------------------
# WebSocket Stream  (architecture.md §4: WS /stream)
# ---------------------------------------------------------------------------

@app.websocket("/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    """Replay the scripted APT incident over a compressed timeline.

    Pushes graph deltas and updated entity scores as events occur.
    Query param: ?speed=N (default 1.0 = ~90s, use 10 for ~9s fast-forward).
    """
    # Auth bypassed for MVP

    # Set session ID from cookie for demo context (optional, but keep existing behavior)
    session_id = websocket.cookies.get("rakshak_session", "default")
    session_id_var.set(session_id)
    await stream_incident(websocket)


# ---------------------------------------------------------------------------
# AI Query Bar  (architecture.md §4: POST /query)
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    node_id: str
    query: str


@app.post("/query")
async def ai_query(req: QueryRequest, _: dict = Depends(require_analyst)) -> dict[str, Any]:
    """AI Query Bar endpoint.

    Assembles the real structured evidence for the given entity, then calls
    the narration service (Claude API) to narrate it in plain language.
    The LLM receives the actual evidence object — never invents one.
    """
    try:
        # Use the same comprehensive sanitization as the narration service
        from app.narration.claude_client import _sanitize_query
        sanitized_query = _sanitize_query(req.query)
    except ValueError as e:
        return {
            "node_id": req.node_id,
            "query": req.query,
            "narration": f"Security violation detected: {str(e)}",
            "model": "rakshak-guardrail",
            "tokens_used": 0,
            "error": "Invalid query",
        }

    evidence = _demo_entity_payload(req.node_id)
    if evidence:
        result = await narrate(req.node_id, sanitized_query, evidence)
        return {
            "node_id": req.node_id,
            "query": req.query,
            "narration": result["narration"],
            "model": result.get("model", "unknown"),
            "tokens_used": result.get("tokens_used", 0),
            "error": result.get("error"),
        }

    it = get_it_graph()
    ot = get_ot_graph()

    in_it = req.node_id in it
    in_ot = req.node_id in ot
    if not in_it and not in_ot:
        raise HTTPException(status_code=404, detail=f"Node '{req.node_id}' not found")
    graph_domain = "IT+OT" if (in_it and in_ot) else ("IT" if in_it else "OT")
    node_data = _node_payload(req.node_id, it.nodes[req.node_id] if in_it else ot.nodes[req.node_id], graph_domain)

    # Assemble the full evidence object (same as GET /entity/{id})
    scores = score_all(req.node_id, it, ot)
    scorer_dict = {s.scorer_class: s.score for s in scores}
    stealth_dampener = max(0.1, min(1.0, 0.8 - (get_active_simulation().stealth_vector - 5.0) * 0.1))
    ds = fuse_scores([(s.scorer_class, s.score) for s in scores], default_reliability=stealth_dampener)
    crit = compute_criticality(req.node_id, it, ot, _current_policy())
    campaign = compute_campaign_state(req.node_id, scorer_dict, it, ot)
    gate = evaluate_gate(
        node_id=req.node_id,
        asset_type=crit.asset_type,
        confidence=ds.belief,
        criticality_composite=crit.composite_score,
        safety_impact=crit.safety_impact,
    )
    advisory_matches = match_advisories(req.node_id, graph_domain, node_data, scorer_dict)

    evidence = {
        "node_id": req.node_id,
        "graph_domain": graph_domain,
        "mission_criticality": {
            "operational_importance": crit.operational_importance,
            "data_sensitivity": crit.data_sensitivity,
            "connectivity_risk": crit.connectivity_risk,
            "safety_impact": crit.safety_impact,
            "recovery_difficulty": crit.recovery_difficulty,
            "composite_score": crit.composite_score,
            "asset_type": crit.asset_type,
        },
        "fusion": {
            "belief": ds.belief,
            "plausibility": ds.plausibility,
            "uncertainty": ds.uncertainty,
            "conflict": ds.conflict,
            "sources": [
                {
                    "scorer_class": s["scorer_class"],
                    "raw_score": s["raw_score"],
                    "mass_malicious": s["mass_malicious"],
                    "mass_benign": s["mass_benign"],
                    "mass_theta": s["mass_theta"],
                }
                for s in ds.sources
            ],
        },
        "campaign_state": {
            "dominant_phase": campaign.dominant_phase,
            "dominant_probability": campaign.dominant_probability,
            "distribution": campaign.distribution,
        },
        "response_gate": {
            "risk_tier": gate.risk_tier,
            "allowed_actions": gate.allowed_actions,
            "blocked_actions": gate.blocked_actions,
            "requires_human_escalation": gate.requires_human_escalation,
            "escalation_reason": gate.escalation_reason,
        },
        "threat_intel_matches": advisory_matches,
        "evidence_log": [
            {
                "source": s.scorer_class,
                "raw_score": s.score,
                "label": s.label,
                "contributing_factors": s.contributing_factors,
            }
            for s in scores
            if s.score > 0
        ],
    }

    # Call narration service (Claude or fallback) with sanitized query
    result = await narrate(req.node_id, sanitized_query, evidence)

    return {
        "node_id": req.node_id,
        "query": req.query,
        "narration": result["narration"],
        "model": result.get("model", "unknown"),
        "tokens_used": result.get("tokens_used", 0),
        "error": result.get("error"),
    }


# ---------------------------------------------------------------------------
# Entity Inspector  (architecture.md §4: GET /entity/{id})
# ---------------------------------------------------------------------------

@app.get("/entity/{node_id}")
async def get_entity(node_id: str, _: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the full entity profile for the Selected-Entity Inspector.

    Includes mission criticality vector, campaign state distribution,
    DS fusion triple, evidence log, and response gate decision.
    All deterministic — no LLM calls.
    """
    demo_payload = _demo_entity_payload(node_id)
    if demo_payload:
        return demo_payload

    it = get_it_graph()
    ot = get_ot_graph()

    in_it = node_id in it
    in_ot = node_id in ot

    if not in_it and not in_ot:
        raise HTTPException(
            status_code=404,
            detail=f"Node '{node_id}' not found in IT or OT graph",
        )
    graph_domain = "IT+OT" if (in_it and in_ot) else ("IT" if in_it else "OT")
    node_data = _node_payload(node_id, it.nodes[node_id] if in_it else ot.nodes[node_id], graph_domain)

    # 1. Behavior scores (7 independent classes)
    behavior_scores = score_all(node_id, it, ot)
    scorer_dict = {s.scorer_class: s.score for s in behavior_scores}

    # 2. Evidence fusion (Dempster-Shafer)
    stealth_dampener = max(0.1, min(1.0, 0.8 - (get_active_simulation().stealth_vector - 5.0) * 0.1))
    ds_result = fuse_scores(
        [(s.scorer_class, s.score) for s in behavior_scores],
        default_reliability=stealth_dampener
    )

    # 3. Mission criticality vector
    criticality = compute_criticality(node_id, it, ot, _current_policy())

    # 4. Campaign state distribution
    campaign_state = compute_campaign_state(node_id, scorer_dict, it, ot)
    advisory_matches = match_advisories(node_id, graph_domain, node_data, scorer_dict)

    # 5. Response gate
    gate = evaluate_gate(
        node_id=node_id,
        asset_type=criticality.asset_type,
        confidence=ds_result.belief,
        criticality_composite=criticality.composite_score,
        safety_impact=criticality.safety_impact,
    )

    # 6. Evidence log
    evidence_log: list[dict[str, Any]] = []
    for s in behavior_scores:
        entry: dict[str, Any] = {
            "source": s.scorer_class,
            "raw_score": s.score,
            "label": s.label,
        }
        if s.contributing_factors:
            entry["contributing_factors"] = s.contributing_factors
        evidence_log.append(entry)

    # 7. Audit — log fusion + gate decision
    log_fusion_event(
        node_id=node_id,
        belief=ds_result.belief,
        plausibility=ds_result.plausibility,
        uncertainty=ds_result.uncertainty,
        conflict=ds_result.conflict,
        sources=ds_result.sources,
        scorer_scores=scorer_dict,
        context=_audit_context(),
    )
    log_gate_decision(
        node_id=node_id,
        asset_type=criticality.asset_type,
        confidence=ds_result.belief,
        criticality=criticality.composite_score,
        risk_tier=gate.risk_tier,
        allowed_actions=gate.allowed_actions,
        blocked_actions=gate.blocked_actions,
        requires_escalation=gate.requires_human_escalation,
        escalation_reason=gate.escalation_reason,
        rationale=gate.rationale,
        context=_audit_context(),
    )
    audit_sources = _audit_sources_from_scores(ds_result, behavior_scores)
    append_audit_entry(
        entity_id=node_id,
        evidence_sources=audit_sources,
        alternatives_considered=[],
        human_approval={"approved_by": "system", "timestamp": None},
        action_taken="fusion_result",
        event_type="fusion_result",
        metadata={
            "belief": ds_result.belief,
            "plausibility": ds_result.plausibility,
            "uncertainty": ds_result.uncertainty,
            "conflict": ds_result.conflict,
        },
        **_audit_context(),
    )
    append_audit_entry(
        entity_id=node_id,
        evidence_sources=audit_sources,
        alternatives_considered=[],
        human_approval={"approved_by": "system", "timestamp": None},
        action_taken="attack_mapping",
        event_type="attack_mapping",
        technique_id=campaign_state.dominant_phase,
        metadata={
            "dominant_phase": campaign_state.dominant_phase,
            "dominant_probability": campaign_state.dominant_probability,
        },
        **_audit_context(),
    )
    if advisory_matches:
        append_audit_entry(
            entity_id=node_id,
            evidence_sources=audit_sources,
            alternatives_considered=[],
            human_approval={"approved_by": "system", "timestamp": None},
            action_taken="threat_intel_match",
            event_type="threat_intel_match",
            source_refs=[m["advisory_id"] for m in advisory_matches],
            metadata={"matches": advisory_matches[:3]},
            **_audit_context(),
        )

    return {
        "node_id": node_id,
        "graph_domain": graph_domain,

        "mission_criticality": {
            "operational_importance": criticality.operational_importance,
            "data_sensitivity": criticality.data_sensitivity,
            "connectivity_risk": criticality.connectivity_risk,
            "safety_impact": criticality.safety_impact,
            "recovery_difficulty": criticality.recovery_difficulty,
            "composite_score": criticality.composite_score,
            "asset_type": criticality.asset_type,
        },

        "campaign_state": {
            "distribution": campaign_state.distribution,
            "dominant_phase": campaign_state.dominant_phase,
            "dominant_probability": campaign_state.dominant_probability,
            "phase_evidence": campaign_state.evidence,
        },

        "fusion": {
            "belief": ds_result.belief,
            "plausibility": ds_result.plausibility,
            "uncertainty": ds_result.uncertainty,
            "conflict": ds_result.conflict,
            "sources": ds_result.sources,
        },

        "response_gate": {
            "risk_tier": gate.risk_tier,
            "allowed_actions": gate.allowed_actions,
            "blocked_actions": gate.blocked_actions,
            "requires_human_escalation": gate.requires_human_escalation,
            "escalation_reason": gate.escalation_reason,
            "rationale": gate.rationale,
        },
        "threat_intel_matches": advisory_matches,
        "policy": _current_policy(),

        "evidence_log": evidence_log,
    }


# ---------------------------------------------------------------------------
# Resilience Score  (PRD.md §4.7: GET /api/resilience-score)
# ---------------------------------------------------------------------------

@app.get("/api/resilience-score")
async def get_resilience_score(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the headline resilience score and component breakdown.

    Formula: f(redundancy_coverage, degraded_mode_availability,
               mean_recovery_time, service_continuity_last_N)

    Shown continuously, not just post-incident.
    """
    it = get_it_graph()
    ot = get_ot_graph()
    result = compute_resilience_score(it, ot)

    # Audit log the computation
    log_resilience_event(
        headline_score=result.score,
        components=result.breakdown,
        assessment=result.assessment,
        context=_audit_context(),
    )

    return {
        "score": result.score,
        "assessment": result.assessment,
        "breakdown": result.breakdown,
    }


# ---------------------------------------------------------------------------
# Judge Evidence Pack
# ---------------------------------------------------------------------------

class DemoContextRequest(BaseModel):
    policy_id: str | None = None
    scenario_id: str | None = None
    facility_id: str | None = None


@app.get("/api/evaluation/summary")
async def get_evaluation_summary(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return reproducible PS7 evaluation metrics and evidence."""
    return compute_ps7_summary(audit_verification=verify_audit_chain(), context=get_demo_context())


@app.get("/api/threat-intel/advisories")
async def get_threat_intel_advisories(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return India-CNI advisory and scenario fixtures used by the demo."""
    return {
        "advisories": load_advisories(),
        "scenarios": load_scenarios(),
    }


@app.get("/api/policies")
async def get_policies(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return response policy packs and current demo selection."""
    return {
        "current_policy_id": get_demo_context()["policy_id"],
        "current_facility_id": get_demo_context()["facility_id"],
        "policies": list_policies(),
    }


@app.get("/api/demo/context")
async def get_api_demo_context(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the active judge-demo scenario and policy."""
    return {
        **get_demo_context(),
        "policy": _current_policy(),
        "scenario": _current_scenario(),
        "scenarios": load_scenarios(),
    }


@app.post("/api/demo/context")
async def set_demo_context(
    req: DemoContextRequest,
    _: dict = Depends(require_admin)
) -> dict[str, Any]:
    """Switch active demo scenario/policy without changing code."""
    if req.policy_id:
        known = {policy["policy_id"] for policy in list_policies()}
        if req.policy_id not in known:
            raise HTTPException(status_code=404, detail=f"Policy '{req.policy_id}' not found")
        get_demo_context()["policy_id"] = req.policy_id
    if req.scenario_id:
        scenario = next((item for item in load_scenarios() if item["id"] == req.scenario_id), None)
        if scenario is None:
            raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found")
        get_demo_context()["scenario_id"] = req.scenario_id
        get_demo_context()["org_id"] = scenario["org_id"]
        get_demo_context()["facility_id"] = scenario["facility_id"]
        get_demo_context()["sector"] = scenario["sector"]
        if not req.policy_id:
            get_demo_context()["policy_id"] = scenario["default_policy"]
    if req.facility_id:
        scenario = next((item for item in load_scenarios() if item["facility_id"] == req.facility_id), None)
        if scenario is None:
            raise HTTPException(status_code=404, detail=f"Facility '{req.facility_id}' not found")
        get_demo_context()["scenario_id"] = scenario["id"]
        get_demo_context()["org_id"] = scenario["org_id"]
        get_demo_context()["facility_id"] = scenario["facility_id"]
        get_demo_context()["sector"] = scenario["sector"]
        if not req.policy_id:
            get_demo_context()["policy_id"] = scenario["default_policy"]
    return await get_demo_context()


@app.post("/api/demo/advance")
async def advance_demo_endpoint(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Release the next scripted APT batch into SQLite-backed entity history."""
    return advance_demo()


# ---------------------------------------------------------------------------
# Simulation Endpoints
# ---------------------------------------------------------------------------

@app.post("/simulation/configure")
async def configure_simulation(
    config: SimulationConfig,
    current_user: dict = Depends(require_operator)
) -> dict[str, Any]:
    # Thread-safe write via set_active_simulation
    set_active_simulation(config)

    sim = get_active_simulation()

    # Update demo context to match scenario
    scenario = next((item for item in load_scenarios() if item["id"] == config.scenario_id), None)
    if scenario:
        get_demo_context()["scenario_id"] = scenario["id"]
        get_demo_context()["org_id"] = scenario["org_id"]
        get_demo_context()["facility_id"] = scenario["facility_id"]
        get_demo_context()["sector"] = scenario["sector"]
        get_demo_context()["policy_id"] = scenario.get("default_policy", "power_grid")
        if config.target_node_ids:
            get_demo_context()["target_node_ids"] = config.target_node_ids

    return {"status": "armed", "config": sim.dict()}


@app.post("/simulation/deploy")
async def deploy_simulation(_: dict = Depends(require_operator)) -> dict[str, Any]:
    # Reset the demo environment so it starts from scratch
    init_demo_db(reset=True)
    clear_audit_log()
    _log_initial_resilience()

    # The synthetic_incident will be driven by /stream or /api/demo/advance
    # We return a run_id so the frontend can initiate streaming.
    run_id = f"run_{int(time.time())}"
    return {"status": "deployed", "run_id": run_id}


MOCK_API_CALLS: list[dict[str, Any]] = []
_MAX_MOCK_API_CALLS = 200


@app.post("/mock-api/{action_name}")
async def mock_action_endpoint(
    action_name: str,
    payload: dict[str, Any] | None = None,
    _: dict = Depends(require_operator)
) -> dict[str, Any]:
    """Local mock target-system endpoint used by response demos."""
    from datetime import datetime, timezone

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action_name,
        "payload": payload or {},
        "status": "fake_success",
    }
    MOCK_API_CALLS.append(entry)
    if len(MOCK_API_CALLS) > _MAX_MOCK_API_CALLS:
        MOCK_API_CALLS[:] = MOCK_API_CALLS[-_MAX_MOCK_API_CALLS:]
    return entry


# ---------------------------------------------------------------------------
# Red Team Interactive Mode  (judge-branching demo layer)
# ---------------------------------------------------------------------------

from app.data.redteam_scenarios import (
    get_state as get_redteam_state,
    apply_choice as apply_redteam_choice,
    reset_session as reset_redteam,
    available_stages as list_redteam_stages,
    find_choice,
)


class ChoiceRequest(BaseModel):
    choice_id: str


@app.get("/redteam/state")
async def redteam_get_state(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return current red-team session state: stage, choices, history."""
    state = get_redteam_state()
    if not state["active"]:
        # Return default unstarted state
        return {
            "active": False,
            "current_stage": 0,
            "stage_info": list_redteam_stages()[0] if list_redteam_stages() else None,
            "choices": _redteam_choices_for(0),
            "history": [],
            "finished": False,
        }
    return state


@app.post("/redteam/choose")
async def redteam_choose(req: ChoiceRequest, _: dict = Depends(require_operator)) -> dict[str, Any]:
    """Apply a branch choice through the scoring→fusion→campaign→gate pipeline.

    Returns updated entity/graph/score deltas and gate evaluation.
    """
    choice = find_choice(req.choice_id)
    if choice is None:
        raise HTTPException(status_code=404, detail=f"Choice '{req.choice_id}' not found")

    # Apply the choice — mutates the graph
    result = apply_redteam_choice(req.choice_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    node_id = result["applied_event"]["affected_node"]
    it = get_it_graph()
    ot = get_ot_graph()

    # Score the affected node through the existing pipeline
    behavior_scores = score_all(node_id, it, ot)
    scorer_dict = {s.scorer_class: s.score for s in behavior_scores}
    ds_result = fuse_scores([(s.scorer_class, s.score) for s in behavior_scores])

    # Mission criticality
    from app.scoring.mission_criticality import compute_criticality as compute_mc
    criticality = compute_mc(node_id, it, ot, _current_policy())

    # Campaign state
    campaign_state = compute_campaign_state(node_id, scorer_dict, it, ot)

    # Response gate — this surfaces any blocked actions for OT entities
    gate = evaluate_gate(
        node_id=node_id,
        asset_type=criticality.asset_type,
        confidence=ds_result.belief,
        criticality_composite=criticality.composite_score,
        safety_impact=criticality.safety_impact,
    )

    # Audit log the event via the existing audit chain
    audit_sources = [
        {"source": s.scorer_class, "weight": s.score}
        for s in behavior_scores if s.score > 0
    ]
    append_audit_entry(
        entity_id=node_id,
        evidence_sources=audit_sources,
        alternatives_considered=[],
        human_approval={"approved_by": "system", "timestamp": None},
        action_taken=f"redteam_choice:{req.choice_id}",
        event_type="redteam_choice",
        metadata={
            "choice_id": req.choice_id,
            "choice_label": choice.label,
            "event_type": result["applied_event"]["event_type"],
            "mitre_technique": result["applied_event"]["mitre_technique"],
            "mitre_tactic": result["applied_event"]["mitre_tactic"],
            "affected_node": node_id,
            "belief": ds_result.belief,
            "plausibility": ds_result.plausibility,
            "unceratinty": ds_result.uncertainty,
            "risk_tier": gate.risk_tier,
            "gate_allowed": gate.allowed_actions,
            "gate_blocked": gate.blocked_actions,
        },
        **_audit_context(),
    )

    # Build updated state for the affected node
    node_state = {
        "node_id": node_id,
        "graph_domain": criticality.asset_type,
        "scores": {
            s.scorer_class: s.score for s in behavior_scores
        },
        "fusion": {
            "belief": round(ds_result.belief, 4),
            "plausibility": round(ds_result.plausibility, 4),
            "uncertainty": round(ds_result.uncertainty, 4),
            "conflict": round(ds_result.conflict, 4),
        },
        "campaign_state": {
            "dominant_phase": campaign_state.dominant_phase,
            "dominant_probability": campaign_state.dominant_probability,
            "distribution": campaign_state.distribution,
        },
        "response_gate": {
            "risk_tier": gate.risk_tier,
            "allowed_actions": gate.allowed_actions,
            "blocked_actions": gate.blocked_actions,
            "requires_human_escalation": gate.requires_human_escalation,
            "escalation_reason": gate.escalation_reason,
            "rationale": gate.rationale,
        },
    }

    return {
        **result,
        "node_state": node_state,
        "updated_state": get_redteam_state(),
    }


@app.post("/redteam/reset")
async def redteam_reset(
    current_user: dict = Depends(require_operator)
) -> dict[str, Any]:
    """Reset the red-team session to starting state."""
    state = reset_redteam()
    clear_audit_log()
    _log_initial_resilience()
    return state


def _redteam_choices_for(stage: int) -> list[dict[str, Any]]:
    """Helper to get choices for a stage."""
    from app.data.redteam_scenarios import available_choices as get_choices
    return get_choices(stage)


# ---------------------------------------------------------------------------
# Audit Trail  (PRD.md §4.9: GET /audit)
# ---------------------------------------------------------------------------


@app.get("/audit")
async def get_audit(
    limit: int = Query(default=50, ge=1, le=500),
    event_type: str | None = Query(default=None),
    node_id: str | None = Query(default=None),
    current_user: dict = Depends(require_analyst)
) -> dict[str, Any]:
    """Return the audit trail — every fused score and gate decision logged.

    Filterable by event_type (fusion, gate_decision, resilience)
    and by node_id. Most recent entries first.
    """
    entries = get_audit_log(limit=limit, event_type=event_type, node_id=node_id)
    return {
        "total": len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Direct Dempster-Shafer Fusion Endpoint (Phase 3 addition)
# ---------------------------------------------------------------------------

class EvidenceSource(BaseModel):
    source_name: str
    raw_score: float
    source_reliability: float = 0.9

class FusionRequest(BaseModel):
    sources: list[EvidenceSource]

@app.get("/api/entities/{entity_id}/scores")
async def get_entity_scores(entity_id: str, _: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return live rolling-baseline scores for the entity."""
    if not get_demo_entity(entity_id):
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found in telemetry DB")
    scores = score_entity(entity_id)
    fusion = _fuse_baseline_scores(scores)
    return {
        "entity_id": entity_id,
        "overall_score": fusion["belief"],
        "scores": [
            {
                "behavior_class": score.behavior_class,
                "raw_score": score.raw_score,
                "status": score.status,
                "detail": score.detail,
            }
            for score in scores
        ],
    }

@app.post("/api/entities/{entity_id}/fuse")
async def manual_fusion(entity_id: str, req: FusionRequest | None = None, _: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Manually fuse an arbitrary set of evidence sources for an entity.

    Accepts custom evidence sources (e.g. IT-TGN, OT physics, IOC, etc)
    and returns exact Dempster-Shafer belief tracking.
    """
    if req is None:
        if not get_demo_entity(entity_id):
            raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found in telemetry DB")
        scores = score_entity(entity_id)
        fusion = _fuse_baseline_scores(scores)
        return {
            "entity_id": entity_id,
            "per_source_bpa": fusion["per_source_bpa"],
            "belief": fusion["belief"],
            "plausibility": fusion["plausibility"],
            "uncertainty": fusion["uncertainty"],
            "conflict": fusion["conflict"],
        }

    if not req.sources:
        raise HTTPException(status_code=400, detail="Must provide at least one evidence source.")

    bpas = []
    source_details = []

    for src in req.sources:
        bpa = to_bpa(raw_score=src.raw_score, source_reliability=src.source_reliability)
        bpas.append(bpa)
        source_details.append({
            "source_name": src.source_name,
            "raw_score": src.raw_score,
            "reliability": src.source_reliability,
            "bpa": bpa
        })

    # Combine all
    combined_bpa = ds_combine(bpas)
    metrics = belief_plausibility(combined_bpa)

    # Sort sources by their mass contribution to {Malicious} prior to combination
    # This helps identify "which sources contributed most"
    sorted_sources = sorted(
        source_details, 
        key=lambda x: x["bpa"]["Malicious"], 
        reverse=True
    )

    return {
        "entity_id": entity_id,
        "combined": metrics,
        "per_source": source_details,
        "most_contributing": sorted_sources[0]["source_name"] if sorted_sources else None,
        "contributions_ranked": [s["source_name"] for s in sorted_sources]
    }


# ---------------------------------------------------------------------------
# Resilience Signals Panel (GET /api/entities/{id}/evidence)
# ---------------------------------------------------------------------------

@app.get("/api/entities/{node_id}/evidence")
async def get_entity_evidence(node_id: str, _: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return exactly 5 mapped raw source scores + DS fusion output for the Resilience Signals panel."""
    demo_entity = get_demo_entity(node_id)
    if demo_entity:
        scores = score_entity(node_id)
        fusion = _fuse_baseline_scores(scores)
        names = {
            "login_time": ("Login Time", "IT"),
            "process_rarity": ("Process Rarity", "IT"),
            "network_flow": ("Network Flow", "IT"),
            "dns_entropy": ("DNS Entropy", "THREAT"),
            "ot_setpoint": ("OT Setpoint", "OT"),
        }
        return {
            "node_id": node_id,
            "sources": [
                {
                    "name": names[score.behavior_class][0],
                    "type": names[score.behavior_class][1],
                    "raw_score_100": 0.0 if score.status != "computed" else score.raw_score * 100,
                    "status": score.status,
                    "detail": score.detail,
                }
                for score in scores
            ],
            "fusion": {
                "belief": fusion["belief"] * 100,
                "plausibility": fusion["plausibility"] * 100,
                "uncertainty": fusion["uncertainty"] * 100,
                "conflict": fusion["conflict"] * 100,
            },
            "threat_intel_matches": [],
        }

    it = get_it_graph()
    ot = get_ot_graph()

    in_it = node_id in it
    in_ot = node_id in ot

    if not in_it and not in_ot:
        raise HTTPException(
            status_code=404,
            detail=f"Node '{node_id}' not found in IT or OT graph",
        )
    graph_domain = "IT+OT" if (in_it and in_ot) else ("IT" if in_it else "OT")
    node_data = _node_payload(node_id, it.nodes[node_id] if in_it else ot.nodes[node_id], graph_domain)

    behavior_scores = score_all(node_id, it, ot)
    scorer_dict = {s.scorer_class: s.score for s in behavior_scores}
    advisory_matches = match_advisories(node_id, graph_domain, node_data, scorer_dict)
    advisory_score = max((m["match_score"] for m in advisory_matches), default=0.0)

    # Map the existing scorers to the 5 requested UI sources
    # 1. IT-TGN (IT Telemetry Graph Network) -> use network & identity
    it_tgn_score = max(scorer_dict.get("network", 0.0), scorer_dict.get("identity", 0.0))
    # 2. OT Physics -> use ot_physics
    ot_physics_score = scorer_dict.get("ot_physics", 0.0)
    # 3. Threat Intel -> use credential / dns
    threat_intel_score = max(scorer_dict.get("credential", 0.0), scorer_dict.get("dns", 0.0), advisory_score)
    # 4. Graph Rarity -> process deviation
    graph_rarity_score = scorer_dict.get("process", 0.0)
    # 5. ATT&CK Match -> cloud_api
    attack_match_score = scorer_dict.get("cloud_api", 0.0)

    # Use the authentic graph DS fusion result instead of recreating it locally
    stealth_dampener = max(0.1, min(1.0, 0.8 - (get_active_simulation().stealth_vector - 5.0) * 0.1))
    ds_result = fuse_scores(
        [(s.scorer_class, s.score) for s in behavior_scores],
        default_reliability=stealth_dampener
    )
    
    # Format sources for UI display only
    def format_source(name, raw_score):
        return {
            "name": name,
            "raw_score_100": raw_score * 100,
            "type": "IT" if name == "IT-TGN" else ("OT" if name == "OT Physics" else "THREAT")
        }

    sources_out = [
        format_source("IT-TGN", it_tgn_score),
        format_source("OT Physics", ot_physics_score),
        format_source("Threat Intel", threat_intel_score),
        format_source("Graph Rarity", graph_rarity_score),
        format_source("ATT&CK Match", attack_match_score),
    ]

    return {
        "node_id": node_id,
        "sources": sources_out,
        "fusion": {
            "belief": ds_result.belief * 100,
            "plausibility": ds_result.plausibility * 100,
            "uncertainty": ds_result.uncertainty * 100,
            "conflict": ds_result.conflict * 100,
        },
        "threat_intel_matches": advisory_matches,
    }


# ---------------------------------------------------------------------------
# Inspector Panel Extensions (GET /api/entities/{id}/*)
# ---------------------------------------------------------------------------

@app.get("/api/entities/{node_id}/campaign-state")
async def get_entity_campaign_state(node_id: str, _: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the campaign state probability distribution for the inspector."""
    if get_demo_entity(node_id):
        campaign = match_campaign(get_entity_events(node_id))
        distribution = campaign.get("campaign_state", {"benign": 1.0})
        dominant = campaign.get("dominant_phase") or max(distribution, key=distribution.get)
        return {
            "node_id": node_id,
            "status": campaign["status"],
            "distribution": distribution,
            "dominant_phase": dominant,
            "dominant_probability": campaign.get("dominant_probability", distribution.get(dominant, 0.0)),
            "matched_techniques": campaign.get("matched_techniques", []),
            "raw_evidence": campaign.get("raw_evidence", []),
        }

    it = get_it_graph()
    ot = get_ot_graph()

    if node_id not in it and node_id not in ot:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    behavior_scores = score_all(node_id, it, ot)
    scorer_dict = {s.scorer_class: s.score for s in behavior_scores}
    campaign_state = compute_campaign_state(node_id, scorer_dict, it, ot)

    return {
        "node_id": node_id,
        "distribution": campaign_state.distribution,
        "dominant_phase": campaign_state.dominant_phase,
    }


@app.get("/api/entities/{node_id}/hypotheses")
async def get_entity_hypotheses(node_id: str, _: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Run ACH engine on the node's current scores and return ranked hypotheses.

    Uses the 7 behavior-class scores plus DS fusion belief to generate and
    rank 3 competing hypotheses: ExternalAttacker, InsiderThreat, FalsePositive.
    """
    from app.fusion.ach import analyze_hypotheses as ach

    demo_entity = get_demo_entity(node_id)
    if demo_entity:
        scores = score_entity(node_id)
        scorer_dict = {s.behavior_class: s.raw_score for s in scores}
        ds_result = _fuse_baseline_scores(scores)
        belief = ds_result["belief"]
        plausibility = ds_result["plausibility"]
    else:
        it = get_it_graph()
        ot = get_ot_graph()
        in_it = node_id in it
        in_ot = node_id in ot
        if not in_it and not in_ot:
            raise HTTPException(
                status_code=404,
                detail=f"Node '{node_id}' not found in IT or OT graph",
            )
        behavior_scores = score_all(node_id, it, ot)
        scorer_dict = {s.scorer_class: s.score for s in behavior_scores}
        ds_result = fuse_scores([(s.scorer_class, s.score) for s in behavior_scores])
        belief = ds_result.belief
        plausibility = ds_result.plausibility

    hypotheses = ach(
        scorer_scores=scorer_dict,
        belief=belief,
        plausibility=plausibility,
    )

    return {
        "node_id": node_id,
        "hypotheses": [
            {
                "name": h.name,
                "posterior_probability": h.posterior_probability,
                "explanation": h.explanation,
            }
            for h in hypotheses.hypotheses
        ],
    }


@app.get("/api/entities/{node_id}/evidence-log")
async def get_entity_evidence_log_endpoint(node_id: str, _: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return an append-only log of why this entity is flagged, with audit timestamps."""
    if get_demo_entity(node_id):
        entries = []
        for score in score_entity(node_id):
            latest = score.latest_event
            if score.status != "computed" or not latest:
                continue
            entries.append({
                "timestamp": latest["timestamp"],
                "source": score.behavior_class,
                "message": f"{score.raw_score:.2f} — {score.detail}",
                "raw_score": score.raw_score,
            })
        entries.sort(key=lambda entry: entry["timestamp"], reverse=True)
        return {"node_id": node_id, "entries": entries}

    it = get_it_graph()
    ot = get_ot_graph()

    if node_id not in it and node_id not in ot:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    # Re-score to see current evidence
    behavior_scores = score_all(node_id, it, ot)
    active_scorers = {s.scorer_class: s for s in behavior_scores if s.score > 0}

    # Fetch audit log to find when each active scorer first appeared for this node
    audit_entries = get_audit_log(limit=500, event_type="fusion", node_id=node_id)
    # The audit list is most-recent first
    audit_entries.reverse() # now chronological

    # Find first appearance time of each scorer
    first_seen_time = {}
    for entry in audit_entries:
        raw_scores = entry.get("metadata", {}).get("raw_scores", {})
        ts = entry.get("timestamp")
        for scorer, score in raw_scores.items():
            if score > 0 and scorer not in first_seen_time:
                first_seen_time[scorer] = ts

    evidence_entries = []
    # If a scorer hasn't been audited yet, default to now
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    for scorer_class, s in active_scorers.items():
        ts = first_seen_time.get(scorer_class, now_iso)
        # Format a concise message
        msg = f"Anomaly score {s.score:.2f} — {s.label}"
        if s.contributing_factors:
            msg += f" ({', '.join(s.contributing_factors[:2])})"
        
        evidence_entries.append({
            "timestamp": ts,
            "source": scorer_class,
            "message": msg,
            "raw_score": s.score
        })

    # Sort descending by timestamp
    evidence_entries.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "node_id": node_id,
        "entries": evidence_entries
    }


# ---------------------------------------------------------------------------
# Living Graph Polling (GET /api/graph/live-state)
# ---------------------------------------------------------------------------

@app.get("/api/graph/live-state")
async def get_graph_live_state(_: dict = Depends(require_viewer)) -> dict[str, Any]:
    """Return the real-time uncertainty and belief metrics for all graph nodes."""
    live_nodes = []
    for node_id, node_data, _domain, _is_ot in _iter_graph_nodes():
        scores, ds_result = _fused_scores(node_id)
        if isinstance(ds_result, dict):
            uncertainty = ds_result["uncertainty"]
            belief = ds_result["belief"]
            anomaly = overall_anomaly(scores)
        else:
            uncertainty = ds_result.uncertainty
            belief = ds_result.belief
            anomaly = belief
        live_nodes.append({
            "id": node_id,
            "type": node_data.get("node_type", "UNKNOWN"),
            "uncertainty": anomaly,
            "belief": belief,
            "anomaly_score": anomaly,
        })

    return {
        "nodes": live_nodes
    }


# ---------------------------------------------------------------------------
# Response Agent (GET /api/response-decisions & POST /api/entities/{id}/response-decision)
# ---------------------------------------------------------------------------

@app.get("/api/response-decisions")
async def get_response_decisions(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return live response decisions for all active (flagged) entities."""
    policy = _current_policy()

    decisions = []
    for entity in list_demo_entities():
        node_id = entity["id"]
        scores = score_entity(node_id)
        ds_result = _fuse_baseline_scores(scores)
        if ds_result["belief"] <= 0.0 and overall_anomaly(scores) <= 0.0:
            continue

        mc = _mission_from_demo_entity(entity)
        mc_dict = {
            "public_safety_impact": entity["public_safety_impact"],
            "human_dependency": entity["human_dependency"],
        }

        evidence_sources = ds_result["sources"]
        response_entity = {
            "id": entity["id"],
            "label": entity["label"],
            "type": entity["type"],
            "node_type": entity["type"],
            "domain": entity["domain"],
            "graph_domain": "OT" if entity["domain"] == "OT" else ("IT_OT_BRIDGE" if entity["domain"] == "IT_OT_BRIDGE" else "IT"),
        }
        threshold = policy_adjusted_threshold(policy, mc["asset_type"])
        decision = decide_response(
            response_entity,
            ds_result["belief"],
            mc_dict,
            evidence_sources=evidence_sources,
            audit=False,
            auto_execute_threshold=threshold,
            context=_audit_context(),
        )
        playbook = run_mock_playbook(response_entity, decision.action, evidence_sources=evidence_sources, audit=False)
        decisions.append({
            "node_id": node_id,
            "label": entity["label"],
            "org_id": get_demo_context()["org_id"],
            "facility_id": get_demo_context()["facility_id"],
            "sector": get_demo_context()["sector"],
            "action": decision.action,
            "tier": decision.tier,
            "reason": decision.reason,
            "requires_human_approval": decision.requires_human_approval,
            "status": decision.status,
            "is_ot": entity["domain"] == "OT",
            "policy_id": policy["policy_id"],
            "playbook": playbook,
        })

    return {"decisions": decisions}


@app.post("/api/entities/{node_id}/response-decision")
async def post_response_decision(
    node_id: str,
    payload: dict[str, Any] = None,
    authorization: str | None = Header(default=None),
    _: dict = Depends(require_operator)
) -> dict[str, Any]:
    """Endpoint for a specific node to run the response decision logic or execute an action."""
    action_to_execute = payload.get("action") if payload else None
    if action_to_execute:
        _authorize_response_execution(authorization)

    demo_entity = get_demo_entity(node_id)
    if demo_entity:
        scores = score_entity(node_id)
        ds_result = _fuse_baseline_scores(scores)
        mc = _mission_from_demo_entity(demo_entity)
        response_entity = {
            "id": demo_entity["id"],
            "label": demo_entity["label"],
            "type": demo_entity["type"],
            "node_type": demo_entity["type"],
            "domain": demo_entity["domain"],
            "graph_domain": "OT" if demo_entity["domain"] == "OT" else ("IT_OT_BRIDGE" if demo_entity["domain"] == "IT_OT_BRIDGE" else "IT"),
        }
        mc_dict = {
            "public_safety_impact": demo_entity["public_safety_impact"],
            "human_dependency": demo_entity["human_dependency"],
        }
        evidence_sources = ds_result["sources"]
        threshold = policy_adjusted_threshold(_current_policy(), mc["asset_type"])
        decision = decide_response(
            response_entity,
            ds_result["belief"],
            mc_dict,
            evidence_sources=evidence_sources,
            auto_execute_threshold=threshold,
            context=_audit_context(),
        )
        gate = evaluate_gate(
            node_id=demo_entity["id"],
            asset_type=mc["asset_type"],
            confidence=ds_result["belief"],
            criticality_composite=mc["composite_score"],
            safety_impact=mc["public_safety_impact"],
        )
        
        if action_to_execute:
            if action_to_execute in gate.blocked_actions:
                raise HTTPException(status_code=403, detail=f"Action {action_to_execute} is blocked by resilience gate logic.")
            try:
                execute_response_action(response_entity, action_to_execute)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            playbook = run_mock_playbook(
                response_entity,
                action_to_execute,
                evidence_sources=evidence_sources,
                audit=True,
                execute=True,
                context=_audit_context(),
            )
            return {"status": "success", "message": f"Action {action_to_execute} executed on {node_id}", "playbook": playbook}

        playbook = run_mock_playbook(response_entity, decision.action, evidence_sources=evidence_sources, audit=False)
        return {
            "action": decision.action,
            "tier": decision.tier,
            "reason": decision.reason,
            "requires_human_approval": decision.requires_human_approval,
            "status": decision.status,
            "policy_id": get_demo_context()["policy_id"],
            "org_id": get_demo_context()["org_id"],
            "facility_id": get_demo_context()["facility_id"],
            "fusion": ds_result,
            "playbook": playbook,
        }

    it = get_it_graph()
    ot = get_ot_graph()

    if node_id in it:
        node_data = _node_payload(node_id, it.nodes[node_id], "IT")
        is_ot = False
    elif node_id in ot:
        node_data = _node_payload(node_id, ot.nodes[node_id], "OT")
        is_ot = True
    else:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    scores = score_all(node_id, it, ot)
    ds_result = fuse_scores([(s.scorer_class, s.score) for s in scores])
    
    mc = compute_criticality(node_id, it, ot, _current_policy())
    mc_dict = {
        "public_safety_impact": mc.safety_impact,
        "human_dependency": mc.operational_importance,
    }
    
    evidence_sources = _audit_sources_from_scores(ds_result, scores)

    threshold = policy_adjusted_threshold(_current_policy(), mc.asset_type)
    decision = decide_response(
        node_data,
        ds_result.belief,
        mc_dict,
        evidence_sources=evidence_sources,
        auto_execute_threshold=threshold,
        context=_audit_context(),
    )
    
    gate = evaluate_gate(
        node_id=node_id,
        asset_type=mc.asset_type,
        confidence=ds_result.belief,
        criticality_composite=mc.composite_score,
        safety_impact=mc.safety_impact,
    )
    log_gate_decision(
        node_id=node_id,
        asset_type=mc.asset_type,
        confidence=ds_result.belief,
        criticality=mc.composite_score,
        risk_tier=gate.risk_tier,
        allowed_actions=gate.allowed_actions,
        blocked_actions=gate.blocked_actions,
        requires_escalation=gate.requires_human_escalation,
        escalation_reason=gate.escalation_reason,
        rationale=gate.rationale,
        context=_audit_context(),
    )

    if action_to_execute:
        if action_to_execute in gate.blocked_actions:
            raise HTTPException(status_code=403, detail=f"Action {action_to_execute} is blocked by resilience gate logic.")
        try:
            execute_response_action(node_data, action_to_execute)
            playbook = run_mock_playbook(
                node_data,
                action_to_execute,
                evidence_sources=evidence_sources,
                audit=True,
                execute=True,
                context=_audit_context(),
            )
            return {
                "status": "success",
                "message": f"Action {action_to_execute} executed on {node_id}",
                "playbook": playbook,
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    playbook = run_mock_playbook(node_data, decision.action, evidence_sources=evidence_sources, audit=False)

    return {
        "action": decision.action,
        "tier": decision.tier,
        "reason": decision.reason,
        "requires_human_approval": decision.requires_human_approval,
        "status": decision.status,
        "policy_id": get_demo_context()["policy_id"],
        "org_id": get_demo_context()["org_id"],
        "facility_id": get_demo_context()["facility_id"],
        "playbook": playbook,
    }


@app.get("/api/soar/state")
async def get_soar_state_endpoint(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return local mock SOAR connector side effects."""
    return {
        "org_id": get_demo_context()["org_id"],
        "facility_id": get_demo_context()["facility_id"],
        "state": get_soar_state(),
    }


@app.get("/api/audit")
async def get_api_audit(entity_id: str = None, _: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Return the audit log entries, optionally filtered by entity_id."""
    return {"entries": get_audit_chain(entity_id)}

@app.get("/api/audit/verify")
async def verify_audit(_: dict = Depends(require_analyst)) -> dict[str, Any]:
    """Cryptographically verify the response agent audit chain."""
    return verify_audit_chain()
