"""Config-backed organization policy packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_POLICY_DIR = Path(__file__).resolve().parents[2] / "data" / "policies"
_DEFAULT_POLICY = "power_grid"


def list_policies() -> list[dict[str, Any]]:
    policies = []
    for path in sorted(_POLICY_DIR.glob("*.json")):
        policies.append(get_policy(path.stem))
    return policies


def get_policy(policy_id: str | None = None) -> dict[str, Any]:
    selected = policy_id or _DEFAULT_POLICY
    path = _POLICY_DIR / f"{selected}.json"
    if not path.exists():
        path = _POLICY_DIR / f"{_DEFAULT_POLICY}.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def policy_adjusted_threshold(policy: dict[str, Any], asset_type: str) -> float:
    thresholds = policy.get("auto_execute_thresholds", {})
    return float(thresholds.get(asset_type, thresholds.get("IT", 0.9)))
