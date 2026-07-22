"""SQLite append-only audit chain."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from app.demo_data import connect, create_schema, init_demo_db


_DEFAULT_CONTEXT = {
    "org_id": "national-grid-cni",
    "facility_id": "grid-west-01",
    "policy_id": "power_grid",
}
_chain_lock = threading.Lock()
_AUDIT_DIR: str | None = None
_CHAIN_FILE: str | None = None

# ── Retention cap (Must-Fix #9 from security audit) ──────────────────
#
# The append-only audit chain grows without bound.  We cap it at
# ``_MAX_AUDIT_ENTRIES`` so a long-running demo or an automated caller
# cannot exhaust disk space.  When the cap is exceeded the oldest
# entries are pruned before the new entry is written.

_MAX_AUDIT_ENTRIES = int(os.getenv("RAKSHAK_AUDIT_MAX_ENTRIES", "5000"))


def _last_hash(conn) -> str:
    row = conn.execute("SELECT this_hash FROM audit_entries ORDER BY id DESC LIMIT 1").fetchone()
    return row["this_hash"] if row else "0" * 64


def _content_for_hash(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _use_jsonl() -> bool:
    return bool(_CHAIN_FILE)


def _jsonl_last_hash() -> str:
    if not _CHAIN_FILE or not os.path.exists(_CHAIN_FILE):
        return "0" * 64
    last = "0" * 64
    with open(_CHAIN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line).get("hash", last)
    return last


def _append_jsonl(content: dict[str, Any]) -> dict[str, Any]:
    assert _CHAIN_FILE is not None
    os.makedirs(_AUDIT_DIR or os.path.dirname(_CHAIN_FILE), exist_ok=True)
    
    # Prune oldest if we hit the cap
    if _MAX_AUDIT_ENTRIES > 0 and os.path.exists(_CHAIN_FILE):
        with open(_CHAIN_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) >= _MAX_AUDIT_ENTRIES:
            lines = lines[-(_MAX_AUDIT_ENTRIES - 1):]
            with open(_CHAIN_FILE, "w", encoding="utf-8") as f:
                f.writelines(lines)
                
    prev_hash = _jsonl_last_hash()
    this_hash = hashlib.sha256((prev_hash + _content_for_hash(content)).encode("utf-8")).hexdigest()
    entry = {**content, "prev_hash": prev_hash, "this_hash": this_hash, "previous_hash": prev_hash, "hash": this_hash}
    with open(_CHAIN_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def append_audit_entry(
    entity_id: str,
    evidence_sources: list[dict[str, Any]],
    alternatives_considered: list[str],
    human_approval: dict[str, Any],
    action_taken: str,
    event_type: str = "response_action",
    technique_id: str | None = None,
    playbook_step_id: str | None = None,
    step_status: str | None = None,
    source_refs: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    org_id: str | None = None,
    facility_id: str | None = None,
    policy_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Create and append a hash-chained audit entry."""
    init_demo_db()
    content = {
        "decision_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "entity_id": entity_id,
        "node_id": entity_id,
        "org_id": org_id or _DEFAULT_CONTEXT["org_id"],
        "facility_id": facility_id or _DEFAULT_CONTEXT["facility_id"],
        "policy_id": policy_id or _DEFAULT_CONTEXT["policy_id"],
        "evidence_sources": evidence_sources,
        "alternatives_considered": alternatives_considered,
        "model_versions": {
            "baseline_scoring": "sqlite-stat-v1",
            "attck_kb": "enterprise-attack-cache",
            "fusion": "dempster-shafer-v1",
            "response_gate": "safety-gate-v1",
        },
        "human_approval": human_approval,
        "action_taken": action_taken,
        "source_refs": source_refs or [],
    }
    if technique_id:
        content["technique_id"] = technique_id
    if playbook_step_id:
        content["playbook_step_id"] = playbook_step_id
    if step_status:
        content["step_status"] = step_status
    if metadata:
        content["metadata"] = metadata
    if run_id:
        content["run_id"] = run_id

    if _use_jsonl():
        with _chain_lock:
            return _append_jsonl(content)

    with _chain_lock, connect() as conn:
        create_schema(conn)
        prev_hash = _last_hash(conn)
        this_hash = hashlib.sha256((prev_hash + _content_for_hash(content)).encode("utf-8")).hexdigest()
        entry = {
            **content,
            "prev_hash": prev_hash,
            "this_hash": this_hash,
            "previous_hash": prev_hash,
            "hash": this_hash,
        }
        conn.execute(
            """
            INSERT INTO audit_entries
            (decision_id, timestamp, entity_id, entry_json, prev_hash, this_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry["decision_id"],
                entry["timestamp"],
                entity_id,
                json.dumps(entry, sort_keys=True),
                prev_hash,
                this_hash,
            ),
        )
        conn.commit()

        # ── Enforce retention cap (oldest entries pruned first) ──────
        _prune_entries_if_needed(conn)

    return entry


def get_audit_chain(entity_id: str | None = None, event_type: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    if _use_jsonl():
        if not _CHAIN_FILE or not os.path.exists(_CHAIN_FILE):
            return []
        entries = []
        with open(_CHAIN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entity_id and entry.get("entity_id") != entity_id:
                    continue
                if event_type and entry.get("event_type") != event_type:
                    continue
                entries.append(entry)
        newest = entries[::-1]
        return newest[:limit] if limit else newest

    init_demo_db()
    sql = "SELECT entry_json FROM audit_entries"
    clauses: list[str] = []
    params: list[Any] = []
    if entity_id:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    if event_type:
        clauses.append("json_extract(entry_json, '$.event_type') = ?")
        params.append(event_type)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    with connect() as conn:
        return [json.loads(row["entry_json"]) for row in conn.execute(sql, params)]


def _prune_entries_if_needed(conn) -> None:
    """Prune oldest audit entries when the cap is exceeded."""
    if _MAX_AUDIT_ENTRIES <= 0:
        return  # cap disabled
    count_row = conn.execute(
        "SELECT COUNT(*) AS cnt FROM audit_entries"
    ).fetchone()
    total = count_row["cnt"] if count_row else 0
    if total > _MAX_AUDIT_ENTRIES:
        excess = total - _MAX_AUDIT_ENTRIES
        conn.execute(
            "DELETE FROM audit_entries WHERE id IN "
            "(SELECT id FROM audit_entries ORDER BY id LIMIT ?)",
            (excess,),
        )
        conn.commit()


def clear_audit_chain() -> None:
    if _use_jsonl():
        if _CHAIN_FILE and os.path.exists(_CHAIN_FILE):
            os.remove(_CHAIN_FILE)
        return

    init_demo_db()
    with _chain_lock, connect() as conn:
        conn.execute("DELETE FROM audit_entries")
        conn.commit()


def verify_audit_chain() -> dict[str, Any]:
    if _use_jsonl():
        if not _CHAIN_FILE or not os.path.exists(_CHAIN_FILE):
            return {"valid": True, "invalid_at_index": None, "total_verified": 0}
        previous_expected = None
        with open(_CHAIN_FILE, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if not line.strip():
                    continue
                entry = json.loads(line)
                
                # If this is the first line we're reading, accept its prev_hash as the root.
                # This handles pruned chains where the true genesis block was deleted.
                if previous_expected is None:
                    previous_expected = entry.get("previous_hash", "0" * 64)
                    
                content = {
                    key: value
                    for key, value in entry.items()
                    if key not in {"prev_hash", "this_hash", "previous_hash", "hash"}
                }
                if entry.get("previous_hash") != previous_expected:
                    return {"valid": False, "invalid_at_index": idx, "reason": "Previous hash mismatch"}
                computed = hashlib.sha256((previous_expected + _content_for_hash(content)).encode("utf-8")).hexdigest()
                if entry.get("hash") != computed:
                    return {"valid": False, "invalid_at_index": idx, "reason": "Hash mismatch"}
                previous_expected = computed
        return {"valid": True, "invalid_at_index": None, "total_verified": idx + 1 if "idx" in locals() else 0}

    init_demo_db()
    previous_expected = None
    with _chain_lock, connect() as conn:
        rows = conn.execute("SELECT id, entry_json, prev_hash, this_hash FROM audit_entries ORDER BY id").fetchall()
        for idx, row in enumerate(rows):
            entry = json.loads(row["entry_json"])
            
            # If this is the first row we're reading, accept its prev_hash as the root.
            if previous_expected is None:
                previous_expected = row["prev_hash"]
                
            content = {
                key: value
                for key, value in entry.items()
                if key not in {"prev_hash", "this_hash", "previous_hash", "hash"}
            }
            if row["prev_hash"] != previous_expected or entry.get("prev_hash") != previous_expected:
                return {"valid": False, "invalid_at_index": idx, "reason": "Previous hash mismatch"}
            computed = hashlib.sha256((previous_expected + _content_for_hash(content)).encode("utf-8")).hexdigest()
            if row["this_hash"] != computed or entry.get("this_hash") != computed:
                return {"valid": False, "invalid_at_index": idx, "reason": "Hash mismatch"}
            previous_expected = computed
    return {"valid": True, "invalid_at_index": None, "total_verified": len(rows)}
