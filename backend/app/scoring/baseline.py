"""Rolling statistical baselines over SQLite telemetry."""

from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from app.demo_data import connect, init_demo_db


BEHAVIOR_CLASSES = [
    "login_time",
    "process_rarity",
    "network_flow",
    "dns_entropy",
    "ot_setpoint",
]


@dataclass(frozen=True)
class BaselineScore:
    behavior_class: str
    raw_score: float
    status: str
    detail: str
    latest_event: dict[str, Any] | None = None


def _rows(conn: sqlite3.Connection, entity_id: str, behavior_class: str, normal_only: bool = False) -> list[dict[str, Any]]:
    sql = "SELECT * FROM entity_events WHERE entity_id = ? AND behavior_class = ?"
    params: list[Any] = [entity_id, behavior_class]
    if normal_only:
        sql += " AND anomalous = 0"
    sql += " ORDER BY timestamp, seq"
    return [dict(row) for row in conn.execute(sql, params)]


def _latest(conn: sqlite3.Connection, entity_id: str, behavior_class: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT * FROM entity_events
        WHERE entity_id = ? AND behavior_class = ?
        ORDER BY timestamp DESC, seq DESC
        LIMIT 1
        """,
        (entity_id, behavior_class),
    ).fetchone()
    return dict(row) if row else None


def _z_score(value: float, values: list[float]) -> tuple[float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0
    mu = mean(values)
    sigma = pstdev(values) or 1.0
    return abs(value - mu) / sigma, mu, sigma


def _normalize_z(z: float) -> float:
    return round(max(0.0, min(1.0, z / 4.0)), 4)


def dns_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _score_login(conn: sqlite3.Connection, entity_id: str) -> BaselineScore:
    latest = _latest(conn, entity_id, "login_time")
    if not latest or latest["login_hour"] is None:
        return BaselineScore("login_time", 0.0, "no_observation", "No login event observed")
    baseline = [row["login_hour"] for row in _rows(conn, entity_id, "login_time", True) if row["login_hour"] is not None]
    z, mu, sigma = _z_score(float(latest["login_hour"]), [float(v) for v in baseline])
    return BaselineScore(
        "login_time",
        _normalize_z(z),
        "computed",
        f"latest hour {latest['login_hour']:.2f}, mean {mu:.2f}, stddev {sigma:.2f}, z {z:.2f}",
        latest,
    )


def _score_process(conn: sqlite3.Connection, entity_id: str) -> BaselineScore:
    latest = _latest(conn, entity_id, "process_rarity")
    if not latest or not latest["process_name"]:
        return BaselineScore("process_rarity", 0.0, "no_observation", "No process event observed")
    baseline = [row["process_name"] for row in _rows(conn, entity_id, "process_rarity", True) if row["process_name"]]
    if not baseline:
        return BaselineScore("process_rarity", 1.0, "computed", "No baseline process table exists", latest)
    count = baseline.count(latest["process_name"])
    if count == 0:
        score = 1.0
    else:
        freq = count / len(baseline)
        score = 0.0 if freq >= 0.05 else (0.05 - freq) / 0.05
    return BaselineScore(
        "process_rarity",
        round(max(0.0, min(1.0, score)), 4),
        "computed",
        f"{latest['process_name']} appeared {count}/{len(baseline)} times in baseline",
        latest,
    )


def _score_network(conn: sqlite3.Connection, entity_id: str) -> BaselineScore:
    latest = _latest(conn, entity_id, "network_flow")
    if not latest or latest["network_bytes"] is None:
        return BaselineScore("network_flow", 0.0, "no_observation", "No network-flow event observed")
    baseline = [float(row["network_bytes"]) for row in _rows(conn, entity_id, "network_flow", True) if row["network_bytes"] is not None]
    z, mu, sigma = _z_score(float(latest["network_bytes"]), baseline)
    return BaselineScore(
        "network_flow",
        _normalize_z(z),
        "computed",
        f"latest {latest['network_bytes']:.0f} bytes, mean {mu:.0f}, stddev {sigma:.0f}, z {z:.2f}",
        latest,
    )


def _score_dns(conn: sqlite3.Connection, entity_id: str) -> BaselineScore:
    latest = _latest(conn, entity_id, "dns_entropy")
    if not latest or not latest["dns_query"]:
        return BaselineScore("dns_entropy", 0.0, "no_observation", "No DNS event observed")
    baseline = [dns_entropy(row["dns_query"]) for row in _rows(conn, entity_id, "dns_entropy", True) if row["dns_query"]]
    entropy = dns_entropy(latest["dns_query"])
    z, mu, sigma = _z_score(entropy, baseline)
    return BaselineScore(
        "dns_entropy",
        _normalize_z(z),
        "computed",
        f"latest entropy {entropy:.2f}, mean {mu:.2f}, stddev {sigma:.2f}, z {z:.2f}",
        latest,
    )


def _score_ot(conn: sqlite3.Connection, entity_id: str) -> BaselineScore:
    latest = _latest(conn, entity_id, "ot_setpoint")
    if not latest or latest["setpoint_value"] is None:
        return BaselineScore("ot_setpoint", 0.0, "no_observation", "No OT setpoint event observed")
    value = float(latest["setpoint_value"])
    low = float(latest["setpoint_low"])
    high = float(latest["setpoint_high"])
    if low <= value <= high:
        score = 0.0
        detail = f"setpoint {value:.2f} is inside allowed band {low:.2f}-{high:.2f}"
    else:
        band = max(high - low, 1.0)
        distance = low - value if value < low else value - high
        score = min(1.0, distance / band)
        detail = f"setpoint {value:.2f} is {distance:.2f} outside allowed band {low:.2f}-{high:.2f}"
    return BaselineScore("ot_setpoint", round(score, 4), "computed", detail, latest)


SCORERS = {
    "login_time": _score_login,
    "process_rarity": _score_process,
    "network_flow": _score_network,
    "dns_entropy": _score_dns,
    "ot_setpoint": _score_ot,
}


def score_entity(entity_id: str, conn: sqlite3.Connection | None = None) -> list[BaselineScore]:
    """Return the five requested behavior-class scores for one entity."""
    if conn is None:
        init_demo_db()
        with connect() as owned:
            return score_entity(entity_id, owned)
    return [SCORERS[name](conn, entity_id) for name in BEHAVIOR_CLASSES]


def score_map(entity_id: str, conn: sqlite3.Connection | None = None) -> dict[str, float]:
    return {score.behavior_class: score.raw_score for score in score_entity(entity_id, conn)}


def overall_anomaly(scores: list[BaselineScore]) -> float:
    observed = [score.raw_score for score in scores if score.status == "computed"]
    return round(max(observed), 4) if observed else 0.0
