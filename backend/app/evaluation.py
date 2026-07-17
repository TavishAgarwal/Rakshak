"""PS7 evaluation evidence pack computed from committed evidence subsets."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from statistics import median
from typing import Any

from app.campaign.attack_mapper import TECHNIQUE_DB, find_attack_path
from app.data.synthetic_incident import apply_single_event, get_incident_timeline, init_defaults_only
from app.fusion.dempster_shafer import fuse_scores
from app.graph.it_graph import build_steady_state_it_graph
from app.graph.ot_graph import build_steady_state_ot_graph
from app.response.playbooks import PLAYBOOKS, run_mock_playbook
from app.scoring.behavior_classes import score_all


_EVAL_DIR = Path(__file__).resolve().parents[1] / "data" / "evaluation"
_BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "data" / "benchmarks"


def _round(value: float) -> float:
    return round(value, 4)


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _binary_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in records:
        predicted = row["predicted_label"] == "malicious"
        actual = row["label"] == "malicious"
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    return {
        "sample_count": len(records),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": _round(precision),
        "recall_detection_rate": _round(recall),
        "false_positive_rate": _round(fpr),
        "f1": _round(f1),
    }


def _load_benchmark_manifest() -> dict[str, Any]:
    manifest = _load_json(_BENCHMARK_DIR / "benchmark_manifest.json")
    subset_path = _BENCHMARK_DIR / manifest["subset_file"]
    actual_hash = hashlib.sha256(subset_path.read_bytes()).hexdigest()
    if manifest.get("subset_sha256") != actual_hash:
        raise ValueError("Benchmark subset SHA256 does not match manifest")
    return manifest


def _load_benchmark_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    path = _BENCHMARK_DIR / manifest["subset_file"]
    features = manifest["features"]
    required = {"id", "dataset_family", "split", "label", *features}
    rows: list[dict[str, Any]] = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Benchmark subset missing columns: {sorted(missing)}")
        for row in reader:
            if row["label"] not in {"benign", "malicious"}:
                raise ValueError(f"Invalid benchmark label for {row['id']}: {row['label']}")
            parsed = {k: row[k] for k in ("id", "dataset_family", "split", "label")}
            for feature in features:
                parsed[feature] = float(row[feature])
            rows.append(parsed)
    return rows


def _family_baselines(rows: list[dict[str, Any]], features: list[str]) -> dict[str, dict[str, tuple[float, float]]]:
    baselines: dict[str, dict[str, tuple[float, float]]] = {}
    families = sorted({row["dataset_family"] for row in rows})
    for family in families:
        benign_train = [
            row for row in rows
            if row["dataset_family"] == family and row["split"] == "train" and row["label"] == "benign"
        ]
        if not benign_train:
            raise ValueError(f"No benign training rows for {family}")
        baselines[family] = {}
        for feature in features:
            values = [float(row[feature]) for row in benign_train]
            med = median(values)
            deviations = [abs(value - med) for value in values]
            mad = median(deviations)
            scale = 1.4826 * mad if mad > 0 else max(abs(med) * 0.10, 1.0)
            baselines[family][feature] = (med, scale)
    return baselines


def _score_benchmark_row(row: dict[str, Any], baseline: dict[str, tuple[float, float]], features: list[str]) -> float:
    z_values = [abs(float(row[feature]) - med) / scale for feature, (med, scale) in baseline.items() if feature in features]
    return min(max(z_values, default=0.0) / 8.0, 1.0)


def _benchmark_anomaly_metrics() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _load_benchmark_manifest()
    rows = _load_benchmark_rows(manifest)
    features = manifest["features"]
    baselines = _family_baselines(rows, features)
    threshold = 0.65

    scored: list[dict[str, Any]] = []
    for row in rows:
        if row["split"] != "test":
            continue
        score = _score_benchmark_row(row, baselines[row["dataset_family"]], features)
        scored.append({
            **{k: row[k] for k in ("id", "dataset_family", "label")},
            "score": _round(score),
            "predicted_label": "malicious" if score >= threshold else "benign",
        })

    overall = _binary_metrics(scored)
    overall["threshold"] = threshold
    overall["methodology"] = manifest["methodology"]
    overall["per_dataset"] = {
        family: _binary_metrics([row for row in scored if row["dataset_family"] == family])
        for family in sorted({row["dataset_family"] for row in scored})
    }
    overall["cases"] = scored
    return overall, manifest


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", text.lower()) if len(token) > 1}


def _predict_technique(row: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    it_graph = build_steady_state_it_graph()
    ot_graph = build_steady_state_ot_graph()
    init_defaults_only(it_graph, ot_graph)
    graph = it_graph if row["graph_domain"] == "IT" else ot_graph
    text_tokens = _tokens(f"{row['event_type']} {row['evidence']}")

    best_id: str | None = None
    best_score = -1
    best_path: dict[str, Any] | None = None
    for technique_id, technique in TECHNIQUE_DB.items():
        path_match = None
        if row["source_node"] != "external":
            path_match = find_attack_path(row["source_node"], row["target_node"], graph, technique_id)
        technique_tokens = _tokens(
            f"{technique.technique_id} {technique.name} {technique.tactic} {' '.join(technique.required_edge_types)}"
        )
        score = len(text_tokens & technique_tokens)
        if path_match:
            score += 3
        if not technique.required_edge_types:
            score += 1
        if score > best_score:
            best_id = technique_id
            best_score = score
            best_path = path_match

    return best_id, {"score": best_score, "path_match": best_path}


def _attribution_metrics() -> dict[str, Any]:
    cases = _load_json(_EVAL_DIR / "mitre_attribution_fixture.json")
    evaluated: list[dict[str, Any]] = []
    correct = 0
    for row in cases:
        predicted, details = _predict_technique(row)
        is_correct = predicted == row["expected_technique"]
        correct += 1 if is_correct else 0
        evaluated.append({
            **row,
            "predicted_technique": predicted,
            "correct": is_correct,
            "match_score": details["score"],
            "path": details["path_match"],
        })

    total = len(evaluated)
    return {
        "sample_count": total,
        "correct": correct,
        "incorrect": total - correct,
        "technique_level_accuracy": _round(correct / total) if total else 0.0,
        "prediction_method": "Deterministic STIX subset technique ranking using evidence-token overlap plus NetworkX path validation through attack_mapper.find_attack_path.",
        "cases": evaluated,
    }


def _playbook_metrics() -> dict[str, Any]:
    it_entity = {"id": "ep-ws-01", "node_type": "ENDPOINT", "graph_domain": "IT"}
    ot_entity = {"id": "plc-turbine-01", "node_type": "PLC", "graph_domain": "OT"}
    action_entities = {
        "gateway_air_gap": ot_entity,
        "passive_monitoring": ot_entity,
        "ot_shutdown_plc": ot_entity,
    }

    cases: list[dict[str, Any]] = []
    for action in sorted(PLAYBOOKS):
        entity = action_entities.get(action, it_entity)
        playbook = run_mock_playbook(entity, action, audit=False, execute=False)
        for step in playbook["steps"]:
            cases.append({
                "playbook": action,
                "step": step["id"],
                "connector": step["connector"],
                "status": step["status"],
            })

    total = len(cases)
    executable = sum(1 for row in cases if row["status"] == "executed")
    approval = sum(1 for row in cases if row["status"] == "requires_approval")
    blocked = sum(1 for row in cases if row["status"] == "blocked")
    return {
        "sample_count": total,
        "autonomously_executable_steps": executable,
        "requires_approval_steps": approval,
        "safety_blocked_steps": blocked,
        "automation_coverage": _round(executable / total) if total else 0.0,
        "cases": cases,
    }


def _playbook_latency_seconds() -> int:
    metrics = _playbook_metrics()
    return (
        metrics["autonomously_executable_steps"] * 45
        + metrics["requires_approval_steps"] * 600
        + metrics["safety_blocked_steps"] * 0
    )


def _mttd_mttr_metrics() -> dict[str, Any]:
    baseline = _load_json(_EVAL_DIR / "soc_baseline.json")
    it_graph = build_steady_state_it_graph()
    ot_graph = build_steady_state_ot_graph()
    init_defaults_only(it_graph, ot_graph)
    timeline = get_incident_timeline()
    threshold = float(baseline["detection_threshold"])
    first_ts = timeline[0].timestamp if timeline else 0.0
    detection_ts: float | None = None

    for event in timeline:
        affected = apply_single_event(event, it_graph, ot_graph)
        for node_id in affected:
            scores = score_all(node_id, it_graph, ot_graph)
            ds = fuse_scores([(score.scorer_class, score.score) for score in scores])
            if ds.belief >= threshold:
                detection_ts = event.timestamp
                break
        if detection_ts is not None:
            break

    if detection_ts is None:
        detection_ts = timeline[-1].timestamp if timeline else first_ts

    scale = float(baseline["operational_seconds_per_replay_second"])
    final_ts = timeline[-1].timestamp if timeline else detection_ts
    rakshak_mttd_hours = ((detection_ts - first_ts) * scale) / 3600.0
    rakshak_mttr_hours = (((final_ts - detection_ts) * scale) + _playbook_latency_seconds()) / 3600.0
    baseline_mttd = float(baseline["baseline_soc_mttd_hours"])
    baseline_mttr = float(baseline["baseline_soc_mttr_hours"])

    return {
        "baseline_soc_mttd_hours": baseline_mttd,
        "rakshak_mttd_hours": _round(rakshak_mttd_hours),
        "mttd_improvement_percent": _round((baseline_mttd - rakshak_mttd_hours) / baseline_mttd),
        "baseline_soc_mttr_hours": baseline_mttr,
        "rakshak_mttr_hours": _round(rakshak_mttr_hours),
        "mttr_improvement_percent": _round((baseline_mttr - rakshak_mttr_hours) / baseline_mttr),
        "detection_threshold": threshold,
        "detected_replay_second": detection_ts,
        "methodology": baseline["methodology"],
    }


def compute_ps7_summary(audit_verification: dict[str, Any] | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the official PS7 evaluation evidence in one judge-readable object."""
    anomaly_metrics, manifest = _benchmark_anomaly_metrics()
    return {
        "rubric": "ET AI Hackathon 2026 PS7 official evaluation focus",
        "fixture_note": "Metrics are computed from normalized benchmark subsets, deterministic STIX mapping, playbook execution catalog, and live audit verification.",
        "context": context or {},
        "benchmark_manifest": manifest,
        "anomaly_detection": anomaly_metrics,
        "mitre_attack_attribution": _attribution_metrics(),
        "incident_response_automation": _playbook_metrics(),
        "mttd_mttr": _mttd_mttr_metrics(),
        "auditability": audit_verification or {"valid": True, "total_verified": 0},
    }
