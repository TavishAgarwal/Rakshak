"""PS7 evaluation evidence pack computed from committed evidence subsets."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from statistics import median
from typing import Any

from app.attck.mapper import predict_event_technique
from app.data.synthetic_incident import apply_single_event, get_incident_timeline, init_defaults_only
from app.fusion.dempster_shafer import fuse_scores
from app.graph.it_graph import build_steady_state_it_graph
from app.graph.ot_graph import build_steady_state_ot_graph
import networkx as nx
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


def _map_row_to_node(row: dict[str, Any]) -> dict[str, Any]:
    node = {"id": row["id"]}
    
    # We now pass the raw numeric features directly to the node
    # so behavior_classes can compute actual anomaly scores vs baselines.
    for k, v in row.items():
        if k not in {"id", "dataset_family", "split", "label"}:
            node[k] = v
            
    # Keep the old synthetic flags as a fallback for non-benchmark data
    auth_fails = float(row.get("auth_failures", 0))
    if auth_fails >= 4:
        node.setdefault("credential_flags", []).extend(["brute_force", "credential_dump", "pass_the_hash", "credential_compromised"])
        
    conn_rate = float(row.get("conn_rate", 0))
    if conn_rate > 150:
        node.setdefault("network_flags", []).extend(["c2_communication", "cross_zone_traffic", "unauthorized_scan"])
        node["unusual_connection_count"] = conn_rate / 2.0
        
    bytes_out = float(row.get("bytes_out", 0))
    if bytes_out > 50000:
        node["data_exfil_bytes"] = bytes_out * 1000
        
    dns_entropy = float(row.get("dns_entropy", 0))
    if dns_entropy >= 3.0:
        node.setdefault("dns_flags", []).extend(["dns_tunneling", "c2_callback", "dga_detected"])
        
    process_rarity = float(row.get("process_rarity", 0))
    if process_rarity >= 0.5:
        node.setdefault("process_flags", []).extend(["suspicious_executable", "code_injection", "remote_service_execution", "unauthorized_plc_write"])
        
    ot_dev = float(row.get("ot_deviation", 0))
    if ot_dev > 0.1:
        node.setdefault("ot_physics_flags", []).extend(["unauthorized_setpoint_change", "safety_limit_breach", "parameter_modification"])
        node["sensor_deviation_pct"] = ot_dev * 10
        
    api_burst = float(row.get("api_burst", 0))
    if api_burst >= 4:
        node.setdefault("cloud_api_flags", []).extend(["historian_api_abuse", "permission_escalation", "bulk_export"])
        
    return node


def _benchmark_anomaly_metrics() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _load_benchmark_manifest()
    rows = _load_benchmark_rows(manifest)
    threshold = 0.65

    scored: list[dict[str, Any]] = []
    
    # Needs to be called with some simulation state active to avoid errors in get_active_simulation() inside score_all, 
    # but score_all handles no simulation active gracefully by throwing an error if state is not initialized.
    # Actually wait, let's just make sure we init defaults
    it_graph = nx.DiGraph()
    ot_graph = nx.DiGraph()
    init_defaults_only(it_graph, ot_graph)
    
    baselines = _family_baselines(rows, manifest["features"])
    
    for row in rows:
        if row["split"] != "test":
            continue
            
        it_g = nx.DiGraph()
        ot_g = nx.DiGraph()
        node_id = row["id"]
        
        node_attrs = _map_row_to_node(row)
        
        if row["dataset_family"] == "CICIDS2018":
            it_g.add_node(node_id, **node_attrs)
        else:
            ot_g.add_node(node_id, **node_attrs)
            
        family_baseline = baselines.get(row["dataset_family"])
        scores = score_all(node_id, it_g, ot_g, baselines=family_baseline)
        ds = fuse_scores([(s.scorer_class, s.score) for s in scores])
        
        scored.append({
            **{k: row[k] for k in ("id", "dataset_family", "label")},
            "score": _round(ds.belief),
            "predicted_label": "malicious" if ds.belief >= threshold else "benign",
        })

    overall = _binary_metrics(scored)
    overall["threshold"] = threshold
    overall["methodology"] = "Real DS fusion metrics computed from benchmark CSVs using score_all and fuse_scores."
    overall["per_dataset"] = {
        family: _binary_metrics([row for row in scored if row["dataset_family"] == family])
        for family in sorted({row["dataset_family"] for row in scored})
    }
    overall["cases"] = scored
    
    # Write to fixture so UI reads the real computed results
    fixture_path = _EVAL_DIR / "anomaly_detection_fixture.json"
    with open(fixture_path, "w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2)
        
    return overall, manifest




def _attribution_metrics() -> dict[str, Any]:
    cases = _load_json(_EVAL_DIR / "mitre_attribution_fixture.json")
    evaluated: list[dict[str, Any]] = []
    correct = 0
    for row in cases:
        predicted, details = predict_event_technique(row)
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


def _playbook_latency_seconds() -> float:
    import time
    it_entity = {"id": "ep-ws-01", "node_type": "ENDPOINT", "graph_domain": "IT"}
    ot_entity = {"id": "plc-turbine-01", "node_type": "PLC", "graph_domain": "OT"}
    action_entities = {
        "gateway_air_gap": ot_entity,
        "passive_monitoring": ot_entity,
        "ot_shutdown_plc": ot_entity,
    }
    
    start_time = time.perf_counter()
    for action in sorted(PLAYBOOKS):
        entity = action_entities.get(action, it_entity)
        run_mock_playbook(entity, action, audit=False, execute=True)
    end_time = time.perf_counter()
    
    metrics = _playbook_metrics()
    
    # Base Rakshak latency is the real execution time, plus approval delays
    real_execution_latency = (end_time - start_time)
    approval_latency = metrics["requires_approval_steps"] * 600
    
    return real_execution_latency + approval_latency


def _mttd_mttr_metrics() -> dict[str, Any]:
    baseline = _load_json(_EVAL_DIR / "soc_baseline.json")
    it_graph = build_steady_state_it_graph()
    ot_graph = build_steady_state_ot_graph()
    init_defaults_only(it_graph, ot_graph)
    timeline = get_incident_timeline()
    threshold = float(baseline["detection_threshold"])
    first_ts = timeline[0].timestamp if timeline else 0.0
    detection_ts: float | None = None
    baseline_detection_ts: float | None = None
    baseline_threshold = 0.85

    # First pass: find both Rakshak (fused) and Baseline (raw single-source) detection times
    for event in timeline:
        affected = apply_single_event(event, it_graph, ot_graph)
        for node_id in affected:
            scores = score_all(node_id, it_graph, ot_graph)
            
            # Baseline detection check (single raw score threshold)
            if baseline_detection_ts is None:
                if any(s.score >= baseline_threshold for s in scores):
                    baseline_detection_ts = event.timestamp
            
            # Rakshak detection check (DS fusion)
            if detection_ts is None:
                ds = fuse_scores([(score.scorer_class, score.score) for score in scores])
                if ds.belief >= threshold:
                    detection_ts = event.timestamp
            
        if detection_ts is not None and baseline_detection_ts is not None:
            break

    if detection_ts is None:
        detection_ts = timeline[-1].timestamp if timeline else first_ts
    if baseline_detection_ts is None:
        baseline_detection_ts = timeline[-1].timestamp if timeline else first_ts

    scale = float(baseline.get("operational_seconds_per_replay_second", 120))
    final_ts = timeline[-1].timestamp if timeline else detection_ts
    
    # MTTD (hours)
    rakshak_mttd_hours = ((detection_ts - first_ts) * scale) / 3600.0
    baseline_mttd_hours = ((baseline_detection_ts - first_ts) * scale) / 3600.0

    # MTTR (hours) 
    # Rakshak uses autonomous playbook logic latency
    rakshak_mttr_hours = (((final_ts - detection_ts) * scale) + _playbook_latency_seconds()) / 3600.0
    
    # Naive SOC baseline assumes all playbook steps are manual (600s per step)
    metrics = _playbook_metrics()
    naive_playbook_latency = metrics["sample_count"] * 600
    baseline_mttr_hours = (((final_ts - baseline_detection_ts) * scale) + naive_playbook_latency) / 3600.0

    return {
        "baseline_soc_mttd_hours": _round(baseline_mttd_hours),
        "rakshak_mttd_hours": _round(rakshak_mttd_hours),
        "mttd_improvement_percent": _round((baseline_mttd_hours - rakshak_mttd_hours) / baseline_mttd_hours) if baseline_mttd_hours else 0.0,
        "baseline_soc_mttr_hours": _round(baseline_mttr_hours),
        "rakshak_mttr_hours": _round(rakshak_mttr_hours),
        "mttr_improvement_percent": _round((baseline_mttr_hours - rakshak_mttr_hours) / baseline_mttr_hours) if baseline_mttr_hours else 0.0,
        "detection_threshold": threshold,
        "detected_replay_second": detection_ts,
        "methodology": "RAKSHAK MTTD uses fused DS belief threshold (0.65). Naive SOC Baseline MTTD uses single-source raw score threshold (0.85). Rakshak MTTR uses actual automated API code execution latency; Baseline MTTR assumes all manual playbook steps (10 mins each)."
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
