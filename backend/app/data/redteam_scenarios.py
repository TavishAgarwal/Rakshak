"""RAKSHAK — Judge-interactive Red Team branching demo layer.

Defines a deterministic decision tree (3 stages × 2-3 choices each).
Every branch eventually reaches the IT_OT_BRIDGE node. Each choice maps
to a single real `IncidentEvent` from `synthetic_incident.py` — reuse
the exact event format, no new schema invented.

State is tracked in-memory; the graph itself holds the cumulative effects
of all choices made so far.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.data.synthetic_incident import (
    IncidentEvent,
    apply_single_event,
    get_incident_timeline,
    init_defaults_only,
)
from app.graph.store import get_it_graph, get_ot_graph


# ---------------------------------------------------------------------------
# Choice & stage definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedChoice:
    """A single branch choice in the red-team decision tree."""

    id: str                         # unique choice identifier, e.g. "spearphish_operator"
    label: str                      # attacker-perspective label shown on card
    hint: str                       # one-line consequence hint
    event_index: int                # index into get_incident_timeline()
    affected_node: str              # primary node this choice affects
    is_blocked_action: bool = False # if True, the response gate blocks this for OT


@dataclass(frozen=True)
class RedStage:
    """A single stage in the decision tree."""

    stage: int
    label: str
    prompt: str
    choices: list[RedChoice]


# ---------------------------------------------------------------------------
# The decision tree — deterministic, no randomness
# ---------------------------------------------------------------------------

REDTEAM_STAGES: list[RedStage] = [
    RedStage(
        stage=0,
        label="Initial Access",
        prompt="How will you breach the perimeter?",
        choices=[
            RedChoice(
                id="spearphish_operator",
                label="Spearphish plant operator",
                hint="Weaponized PDF with Cobalt Strike beacon delivered via email gateway",
                event_index=0,
                affected_node="app-email-01",
            ),
            RedChoice(
                id="usb_drop",
                label="Drop USB in facility lot",
                hint="Autorun malware on plant operator's Windows workstation",
                event_index=1,
                affected_node="ep-ws-01",
            ),
            RedChoice(
                id="vpn_exploit",
                label="Exploit unpatched VPN appliance",
                hint="Remote code execution on perimeter VPN server, drops beacon on workstation",
                event_index=1,
                affected_node="ep-ws-01",
            ),
        ],
    ),
    RedStage(
        stage=1,
        label="Establish Foothold",
        prompt="How do you deepen your access?",
        choices=[
            RedChoice(
                id="c2_beacon",
                label="Deploy C2 beacon & scan network",
                hint="Internal reconnaissance from compromised host discovers live systems",
                event_index=2,
                affected_node="ep-ws-01",
            ),
            RedChoice(
                id="credential_dump",
                label="Dump credentials via LSASS",
                hint="Mimikatz extracts domain admin Kerberos tickets from memory",
                event_index=3,
                affected_node="ep-ws-01",
            ),
            RedChoice(
                id="lateral_rdp",
                label="Pivot to domain controller via RDP",
                hint="Pass-the-hash to RDP into domain controller using stolen tickets",
                event_index=4,
                affected_node="ep-srv-01",
            ),
        ],
    ),
    RedStage(
        stage=2,
        label="Pivot Toward OT",
        prompt="How will you reach the OT network?",
        choices=[
            RedChoice(
                id="historian_discovery",
                label="Discover OT historian API",
                hint="Enumerate historian REST API endpoints from compromised IT server",
                event_index=9,
                affected_node="api-historian-01",
            ),
            RedChoice(
                id="bridge_pivot",
                label="Pivot across IT/OT bridge gateway",
                hint="Leverage historian API to traverse IT/OT boundary — enters OT network",
                event_index=10,
                affected_node="bridge-historian-01",
            ),
        ],
    ),
    RedStage(
        stage=3,
        label="OT Impact",
        prompt="Choose your OT action (every path reaches the IT/OT bridge):",
        choices=[
            RedChoice(
                id="modify_plc",
                label="Modify turbine PLC setpoints",
                hint="Send malicious Modbus commands to turbine PLC via SCADA server",
                event_index=12,
                affected_node="plc-turbine-01",
            ),
            RedChoice(
                id="isolate_gateway",
                label="Isolate OT Historian Gateway",
                hint="⚠️ Attempt to forcibly isolate the bridge — safety gate may block this",
                event_index=10,
                affected_node="bridge-historian-01",
                is_blocked_action=True,
            ),
            RedChoice(
                id="exfil_data",
                label="Exfiltrate historian data via bridge",
                hint="Bulk-export operational data from ERP and pipe it back through the bridge",
                event_index=8,
                affected_node="app-erp-01",
            ),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Choice lookup helpers
# ---------------------------------------------------------------------------


def find_choice(choice_id: str) -> RedChoice | None:
    """Return the RedChoice with the given id, or None."""
    for stage in REDTEAM_STAGES:
        for choice in stage.choices:
            if choice.id == choice_id:
                return choice
    return None


def get_stage_for_choice(choice_id: str) -> int | None:
    """Return the stage index containing the given choice."""
    for stage in REDTEAM_STAGES:
        for choice in stage.choices:
            if choice.id == choice_id:
                return stage.stage
    return None


def available_choices(stage: int) -> list[dict[str, Any]]:
    """Return the choices for a given stage as plain dicts for JSON serialization."""
    for s in REDTEAM_STAGES:
        if s.stage == stage:
            return [
                {
                    "id": c.id,
                    "label": c.label,
                    "hint": c.hint,
                    "is_blocked_action": c.is_blocked_action,
                }
                for c in s.choices
            ]
    return []


def stage_info(stage: int) -> dict[str, Any] | None:
    """Return stage metadata."""
    for s in REDTEAM_STAGES:
        if s.stage == stage:
            return {
                "stage": s.stage,
                "label": s.label,
                "prompt": s.prompt,
                "total_stages": len(REDTEAM_STAGES),
            }
    return None


def timeline_event_for_choice(choice_id: str) -> IncidentEvent | None:
    """Return the IncidentEvent mapped to this choice, or None."""
    choice = find_choice(choice_id)
    if choice is None:
        return None
    timeline = get_incident_timeline()
    if choice.event_index < 0 or choice.event_index >= len(timeline):
        return None
    return timeline[choice.event_index]


# ---------------------------------------------------------------------------
# State machine (in-memory, per-session)
# ---------------------------------------------------------------------------

import threading
from app.simulation_state import session_id_var

@dataclass
class RedteamSessionState:
    current_stage: int = 0
    choice_history: list[dict[str, Any]] = field(default_factory=list)
    is_active: bool = False

_redteam_sessions: dict[str, RedteamSessionState] = {}
_rt_lock = threading.RLock()

def _get_rt_state() -> RedteamSessionState:
    sid = session_id_var.get()
    with _rt_lock:
        if sid not in _redteam_sessions:
            _redteam_sessions[sid] = RedteamSessionState()
        return _redteam_sessions[sid]


def get_state() -> dict[str, Any]:
    """Return the current red-team session state."""
    st = _get_rt_state()

    if not st.is_active:
        return {
            "active": False,
            "current_stage": None,
            "stage_info": None,
            "choices": [],
            "history": [],
            "finished": False,
        }

    finished = st.current_stage >= len(REDTEAM_STAGES)
    info = stage_info(st.current_stage) if not finished else stage_info(len(REDTEAM_STAGES) - 1)
    choices = available_choices(st.current_stage) if not finished else []

    return {
        "active": st.is_active,
        "current_stage": st.current_stage if not finished else None,
        "stage_info": info,
        "choices": choices,
        "history": st.choice_history,
        "finished": finished,
    }


def is_active() -> bool:
    """Whether a red-team session is in progress."""
    return _get_rt_state().is_active


def start_session() -> dict[str, Any]:
    """Start a new red-team session.

    Re-initializes the graph defaults (removing any incident effects from a
    previous session) and resets stage/history.
    """
    st = _get_rt_state()

    # Reset graph to clean state
    from app.graph.store import reset_graphs
    from app.graph import initialize_graphs
    reset_graphs()
    initialize_graphs(force=True)
    it = get_it_graph()
    ot = get_ot_graph()
    init_defaults_only(it, ot)

    st.current_stage = 0
    st.choice_history = []
    st.is_active = True

    return get_state()


def apply_choice(choice_id: str) -> dict[str, Any]:
    """Apply a choice through the pipeline and advance state.

    Steps:
    1. Look up the choice and its mapped event
    2. Apply the event to the graph via apply_single_event()
    3. Determine affected nodes
    4. Advance to next stage
    5. Log to choice history

    Returns:
        {
            "choice": {id, label, hint, is_blocked_action},
            "stage": current stage info,
            "applied_event": event brief,
            "affected_nodes": [node_id, ...],
            "history": updated choice history,
            "finished": bool,
            "next_stage": stage info or None if finished,
        }
    """
    st = _get_rt_state()

    if not st.is_active:
        return {"error": "No active red-team session. Call POST /redteam/reset first."}

    choice = find_choice(choice_id)
    if choice is None:
        return {"error": f"Unknown choice_id: {choice_id}"}

    # Look up the stage for this choice (validate it's the current stage)
    choice_stage = get_stage_for_choice(choice_id)
    if choice_stage is None:
        return {"error": f"Choice '{choice_id}' not found in any stage."}
    if choice_stage != st.current_stage:
        return {"error": f"Choice '{choice_id}' is for stage {choice_stage}, but current stage is {st.current_stage}."}

    it = get_it_graph()
    ot = get_ot_graph()

    # 1. Apply the event
    event = timeline_event_for_choice(choice_id)
    if event is None:
        return {"error": f"No event mapped for choice '{choice_id}'."}

    affected = apply_single_event(event, it, ot)
    if choice.affected_node not in affected:
        affected.append(choice.affected_node)

    # 2. Record history
    st.choice_history.append({
        "choice_id": choice.id,
        "label": choice.label,
        "hint": choice.hint,
        "stage": st.current_stage,
        "affected_node": choice.affected_node,
        "event_type": event.event_type,
        "mitre_technique": event.mitre_technique,
        "mitre_tactic": event.mitre_tactic,
    })

    # 3. Advance stage
    st.current_stage += 1
    finished = st.current_stage >= len(REDTEAM_STAGES)

    return {
        "choice": {
            "id": choice.id,
            "label": choice.label,
            "hint": choice.hint,
            "is_blocked_action": choice.is_blocked_action,
        },
        "stage": stage_info(choice_stage),
        "applied_event": {
            "event_type": event.event_type,
            "mitre_technique": event.mitre_technique,
            "mitre_tactic": event.mitre_tactic,
            "description": event.description,
            "affected_node": choice.affected_node,
        },
        "affected_nodes": affected,
        "history": st.choice_history,
        "finished": finished,
        "next_stage": stage_info(st.current_stage) if not finished else None,
    }


def reset_session() -> dict[str, Any]:
    """Reset the red-team session (same as start, but re-initializes)."""
    return start_session()


def available_stages() -> list[dict[str, Any]]:
    """List all stages with their metadata."""
    return [
        {
            "stage": s.stage,
            "label": s.label,
            "prompt": s.prompt,
            "choice_count": len(s.choices),
        }
        for s in REDTEAM_STAGES
    ]
