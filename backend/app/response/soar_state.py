"""Local mock SOAR connector state with real file-backed side effects."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_DATA_DIR = Path(os.getenv("RAKSHAK_DATA_DIR", Path(__file__).resolve().parents[2] / "data"))
_STATE_FILE = _DATA_DIR / "runtime" / "soar_state.json"
_LOCK = threading.Lock()

_EMPTY_STATE: dict[str, list[dict[str, Any]]] = {
    "isolated_endpoints": [],
    "blocked_hashes": [],
    "revoked_sessions": [],
    "firewall_denies": [],
    "siem_cases": [],
    "siem_iocs": [],
    "owner_notifications": [],
    "oncall_pages": [],
    "telemetry_boosts": [],
    "ot_monitoring": [],
    "operator_alerts": [],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_state() -> dict[str, list[dict[str, Any]]]:
    if not _STATE_FILE.exists():
        return {key: [] for key in _EMPTY_STATE}
    with open(_STATE_FILE, "r", encoding="utf-8") as f:
        state = json.load(f)
    for key in _EMPTY_STATE:
        state.setdefault(key, [])
    return state


def _save_state(state: dict[str, list[dict[str, Any]]]) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def get_soar_state() -> dict[str, list[dict[str, Any]]]:
    with _LOCK:
        return _load_state()


def reset_soar_state() -> None:
    with _LOCK:
        if _STATE_FILE.exists():
            _STATE_FILE.unlink()


def execute_connector_step(entity: dict[str, Any], step: dict[str, Any]) -> dict[str, str]:
    """Apply a mock connector side effect and return execution status."""
    entity_id = entity.get("id", "unknown")
    record = {
        "entity_id": entity_id,
        "step_id": step["id"],
        "connector": step["connector"],
        "timestamp": _now(),
    }
    target_by_step = {
        "edr-isolate": "isolated_endpoints",
        "edr-hash-block": "blocked_hashes",
        "iam-revoke": "revoked_sessions",
        "firewall-block": "firewall_denies",
        "siem-case": "siem_cases",
        "siem-ioc": "siem_iocs",
        "owner-notify": "owner_notifications",
        "pager-duty": "oncall_pages",
        "edr-telemetry": "telemetry_boosts",
        "ot-monitoring": "ot_monitoring",
        "operator-alert": "operator_alerts",
    }
    bucket = target_by_step.get(step["id"])
    if bucket is None:
        return {"status": "blocked", "detail": f"No local connector for {step['id']}"}

    with _LOCK:
        state = _load_state()
        state[bucket].append(record)
        _save_state(state)
    return {"status": "executed", "detail": f"Local {step['connector']} connector recorded {step['id']}"}
