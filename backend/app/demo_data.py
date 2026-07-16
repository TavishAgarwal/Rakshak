"""SQLite-backed demo telemetry for the real RAKSHAK walkthrough.

The seed files are synthetic, but every number shown by the UI is computed
from rows in this database. Baseline rows are loaded into ``entity_events`` at
startup; attack rows stay in ``staged_events`` until ``/api/demo/advance``
releases them.
"""

from __future__ import annotations

import csv
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = Path(os.getenv("RAKSHAK_DATA_DIR", ROOT / "backend" / "data" / "runtime"))
DB_PATH = DEFAULT_DATA_DIR / "rakshak.sqlite"
SEED_DIR = ROOT / "seed"
ENTITIES_FILE = SEED_DIR / "entities.json"
EVENTS_FILE = SEED_DIR / "telemetry_events.csv"

EVENT_FIELDS = [
    "seq",
    "initial_released",
    "stage",
    "timestamp",
    "entity_id",
    "source_entity",
    "target_entity",
    "event_type",
    "behavior_class",
    "login_hour",
    "process_name",
    "network_bytes",
    "dns_query",
    "setpoint_value",
    "setpoint_low",
    "setpoint_high",
    "mitre_technique",
    "mitre_phase",
    "description",
    "anomalous",
]


def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            type TEXT NOT NULL,
            domain TEXT NOT NULL,
            public_safety_impact TEXT NOT NULL,
            human_dependency TEXT NOT NULL,
            mission_criticality REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entity_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seq INTEGER NOT NULL,
            stage INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            source_entity TEXT,
            target_entity TEXT,
            event_type TEXT NOT NULL,
            behavior_class TEXT NOT NULL,
            login_hour REAL,
            process_name TEXT,
            network_bytes REAL,
            dns_query TEXT,
            setpoint_value REAL,
            setpoint_low REAL,
            setpoint_high REAL,
            mitre_technique TEXT,
            mitre_phase TEXT,
            description TEXT,
            anomalous INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS staged_events (
            seq INTEGER PRIMARY KEY,
            stage INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            source_entity TEXT,
            target_entity TEXT,
            event_type TEXT NOT NULL,
            behavior_class TEXT NOT NULL,
            login_hour REAL,
            process_name TEXT,
            network_bytes REAL,
            dns_query TEXT,
            setpoint_value REAL,
            setpoint_low REAL,
            setpoint_high REAL,
            mitre_technique TEXT,
            mitre_phase TEXT,
            description TEXT,
            anomalous INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS audit_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            entry_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            this_hash TEXT NOT NULL
        );
        """
    )
    conn.commit()


def _entities() -> list[dict[str, Any]]:
    return [
        {
            "id": "AuthServer-03",
            "label": "AuthServer-03",
            "type": "ITServer",
            "domain": "IT",
            "public_safety_impact": "medium",
            "human_dependency": "medium",
            "mission_criticality": 0.82,
        },
        {
            "id": "API-Gateway-01",
            "label": "API Gateway",
            "type": "ITServer",
            "domain": "IT",
            "public_safety_impact": "medium",
            "human_dependency": "medium",
            "mission_criticality": 0.76,
        },
        {
            "id": "Historian-01",
            "label": "Historian Server",
            "type": "ITOTBridge",
            "domain": "IT_OT_BRIDGE",
            "public_safety_impact": "high",
            "human_dependency": "medium",
            "mission_criticality": 0.92,
        },
        {
            "id": "SCADA-HMI-07",
            "label": "SCADA-HMI-07",
            "type": "OTDevice",
            "domain": "OT",
            "public_safety_impact": "high",
            "human_dependency": "high",
            "mission_criticality": 0.96,
        },
        {
            "id": "Workstation-22",
            "label": "Operator Workstation",
            "type": "ITWorkstation",
            "domain": "IT",
            "public_safety_impact": "low",
            "human_dependency": "low",
            "mission_criticality": 0.38,
        },
    ]


def _row(seq: int, released: bool, stage: int, ts: datetime, entity_id: str, **extra: Any) -> dict[str, Any]:
    row = {field: "" for field in EVENT_FIELDS}
    row.update(
        {
            "seq": seq,
            "initial_released": 1 if released else 0,
            "stage": stage,
            "timestamp": ts.isoformat(),
            "entity_id": entity_id,
            "target_entity": entity_id,
            "anomalous": 0 if released else 1,
        }
    )
    row.update(extra)
    return row


def generate_seed_files(seed_dir: Path = SEED_DIR) -> None:
    """Create deterministic synthetic telemetry files for the demo."""
    seed_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(42)
    base = datetime(2026, 7, 10, 0, 0, tzinfo=timezone.utc)
    entities = _entities()
    rows: list[dict[str, Any]] = []
    seq = 1

    normal_processes = {
        "AuthServer-03": ["lsass.exe", "kerberos.exe", "svchost.exe", "authsync.exe"],
        "API-Gateway-01": ["nginx", "envoy", "node", "healthcheck"],
        "Historian-01": ["historiand", "opcua-reader", "backup-agent", "timeseries-writer"],
        "SCADA-HMI-07": ["hmi-runtime", "opcua-client", "screen-recorder", "alarm-panel"],
        "Workstation-22": ["explorer.exe", "teams.exe", "chrome.exe", "vpnclient.exe"],
    }
    domains = ["corp.local", "gridwest.internal", "vendor-updates.net", "time.windows.com"]

    for entity in entities:
        entity_id = entity["id"]
        for day in range(5):
            for _ in range(5):
                hour = rng.choice([8, 9, 10, 11, 14, 15, 16, 17]) + rng.random()
                ts = base + timedelta(days=day, hours=hour, minutes=rng.randint(0, 50))
                rows.append(
                    _row(
                        seq,
                        True,
                        0,
                        ts,
                        entity_id,
                        event_type="normal_login",
                        behavior_class="login_time",
                        login_hour=round(hour, 2),
                        description="Normal shift login",
                    )
                )
                seq += 1

        for i in range(40):
            ts = base + timedelta(hours=i * 3, minutes=rng.randint(0, 40))
            rows.append(
                _row(
                    seq,
                    True,
                    0,
                    ts,
                    entity_id,
                    event_type="normal_process",
                    behavior_class="process_rarity",
                    process_name=rng.choice(normal_processes[entity_id]),
                    description="Common process observed",
                )
            )
            seq += 1

        for i in range(30):
            ts = base + timedelta(hours=i * 4, minutes=rng.randint(0, 40))
            rows.append(
                _row(
                    seq,
                    True,
                    0,
                    ts,
                    entity_id,
                    event_type="normal_flow",
                    behavior_class="network_flow",
                    network_bytes=max(1000, rng.gauss(250_000, 35_000)),
                    description="Baseline east-west traffic",
                )
            )
            seq += 1

        if entity["domain"] != "OT":
            for i in range(10):
                ts = base + timedelta(hours=i * 10, minutes=rng.randint(0, 40))
                rows.append(
                    _row(
                        seq,
                        True,
                        0,
                        ts,
                        entity_id,
                        event_type="normal_dns",
                        behavior_class="dns_entropy",
                        dns_query=rng.choice(domains),
                        description="Normal DNS lookup",
                    )
                )
                seq += 1

    for i in range(20):
        ts = base + timedelta(hours=i * 6)
        rows.append(
            _row(
                seq,
                True,
                0,
                ts,
                "SCADA-HMI-07",
                event_type="normal_setpoint_read",
                behavior_class="ot_setpoint",
                setpoint_value=round(50 + rng.uniform(-2.5, 2.5), 2),
                setpoint_low=45,
                setpoint_high=55,
                description="Normal SCADA setpoint",
            )
        )
        seq += 1

    attack_base = base + timedelta(days=5, hours=3)
    attack_rows = [
        _row(
            seq,
            False,
            1,
            attack_base,
            "AuthServer-03",
            source_entity="external",
            event_type="stolen_credential_login",
            behavior_class="login_time",
            login_hour=3.15,
            mitre_technique="T1003.001",
            mitre_phase="credential-access",
            description="Stolen credential used against AuthServer-03 outside baseline hours",
        ),
        _row(
            seq + 1,
            False,
            1,
            attack_base + timedelta(minutes=2),
            "AuthServer-03",
            source_entity="AuthServer-03",
            event_type="credential_dump_process",
            behavior_class="process_rarity",
            process_name="mimikatz.exe",
            mitre_technique="T1003.001",
            mitre_phase="credential-access",
            description="Credential dumping tool executes on AuthServer-03",
        ),
        _row(
            seq + 2,
            False,
            1,
            attack_base + timedelta(minutes=3),
            "AuthServer-03",
            source_entity="external",
            event_type="credential_reuse_network_spike",
            behavior_class="network_flow",
            network_bytes=1_850_000,
            mitre_technique="T1003.001",
            mitre_phase="credential-access",
            description="Credential abuse causes an abnormal AuthServer-03 network spike",
        ),
        _row(
            seq + 3,
            False,
            1,
            attack_base + timedelta(minutes=4),
            "AuthServer-03",
            source_entity="external",
            event_type="credential_c2_dns",
            behavior_class="dns_entropy",
            dns_query="az9xkq-auth-sync-control.net",
            mitre_technique="T1003.001",
            mitre_phase="credential-access",
            description="High-entropy DNS callback follows the stolen credential use",
        ),
        _row(
            seq + 4,
            False,
            2,
            attack_base + timedelta(minutes=9),
            "API-Gateway-01",
            source_entity="AuthServer-03",
            event_type="lateral_movement_flow",
            behavior_class="network_flow",
            network_bytes=1_900_000,
            mitre_technique="T1021",
            mitre_phase="lateral-movement",
            description="Stolen credential reused for lateral movement into API Gateway",
        ),
        _row(
            seq + 5,
            False,
            2,
            attack_base + timedelta(minutes=10),
            "API-Gateway-01",
            source_entity="AuthServer-03",
            event_type="rare_gateway_process",
            behavior_class="process_rarity",
            process_name="psexec.exe",
            mitre_technique="T1021.002",
            mitre_phase="lateral-movement",
            description="Remote service execution appears on API Gateway",
        ),
        _row(
            seq + 6,
            False,
            3,
            attack_base + timedelta(minutes=18),
            "Historian-01",
            source_entity="API-Gateway-01",
            event_type="it_ot_bridge_pivot",
            behavior_class="network_flow",
            network_bytes=2_800_000,
            mitre_technique="T1021",
            mitre_phase="lateral-movement",
            description="API Gateway pivots across the IT/OT bridge to Historian",
        ),
        _row(
            seq + 7,
            False,
            3,
            attack_base + timedelta(minutes=19),
            "Historian-01",
            source_entity="API-Gateway-01",
            event_type="dga_callback",
            behavior_class="dns_entropy",
            dns_query="xj92kq8zzp1a-control-sync.net",
            mitre_technique="T1021",
            mitre_phase="lateral-movement",
            description="High-entropy callback domain from Historian",
        ),
        _row(
            seq + 8,
            False,
            4,
            attack_base + timedelta(minutes=29),
            "SCADA-HMI-07",
            source_entity="Historian-01",
            event_type="ot_setpoint_drift",
            behavior_class="ot_setpoint",
            setpoint_value=72,
            setpoint_low=45,
            setpoint_high=55,
            mitre_technique="T0831",
            mitre_phase="impact",
            description="SCADA-HMI-07 receives an out-of-band setpoint drift command",
        ),
        _row(
            seq + 9,
            False,
            4,
            attack_base + timedelta(minutes=30),
            "SCADA-HMI-07",
            source_entity="Historian-01",
            event_type="ot_protocol_spike",
            behavior_class="network_flow",
            network_bytes=1_700_000,
            mitre_technique="T0831",
            mitre_phase="impact",
            description="OT protocol traffic spike follows the setpoint drift",
        ),
    ]
    rows.extend(attack_rows)

    with open(seed_dir / "entities.json", "w", encoding="utf-8") as f:
        json.dump(entities, f, indent=2)
    with open(seed_dir / "telemetry_events.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EVENT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _coerce(row: dict[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in row.items():
        if value == "":
            values[key] = None
        elif key in {"seq", "initial_released", "stage", "anomalous"}:
            values[key] = int(float(value))
        elif key in {"login_hour", "network_bytes", "setpoint_value", "setpoint_low", "setpoint_high"}:
            values[key] = float(value)
        else:
            values[key] = value
    return values


def init_demo_db(reset: bool = False, db_path: Path = DB_PATH) -> None:
    if reset and db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if not ENTITIES_FILE.exists() or not EVENTS_FILE.exists():
        generate_seed_files()

    with connect(db_path) as conn:
        create_schema(conn)
        has_seed = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] > 0
        if has_seed:
            return

        with open(ENTITIES_FILE, "r", encoding="utf-8") as f:
            entities = json.load(f)
        conn.executemany(
            """
            INSERT INTO entities
            (id, label, type, domain, public_safety_impact, human_dependency, mission_criticality)
            VALUES (:id, :label, :type, :domain, :public_safety_impact, :human_dependency, :mission_criticality)
            """,
            entities,
        )

        with open(EVENTS_FILE, "r", encoding="utf-8", newline="") as f:
            rows = [_coerce(row) for row in csv.DictReader(f)]

        event_cols = [field for field in EVENT_FIELDS if field != "initial_released"]
        placeholders = ", ".join(f":{field}" for field in event_cols)
        column_sql = ", ".join(event_cols)
        for row in rows:
            target = "entity_events" if row.pop("initial_released") else "staged_events"
            conn.execute(f"INSERT INTO {target} ({column_sql}) VALUES ({placeholders})", row)
        conn.commit()


def get_entity(entity_id: str) -> dict[str, Any] | None:
    init_demo_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        return dict(row) if row else None


def list_entities() -> list[dict[str, Any]]:
    init_demo_db()
    with connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM entities ORDER BY id")]


def get_entity_events(entity_id: str) -> list[dict[str, Any]]:
    init_demo_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM entity_events WHERE entity_id = ? ORDER BY timestamp, seq",
            (entity_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def advance_demo() -> dict[str, Any]:
    """Release the next staged attack batch into entity history."""
    init_demo_db()
    with connect() as conn:
        stage_row = conn.execute("SELECT MIN(stage) AS stage FROM staged_events").fetchone()
        if stage_row["stage"] is None:
            return {"status": "complete", "released": [], "remaining_stages": 0}
        stage = stage_row["stage"]
        rows = [dict(row) for row in conn.execute("SELECT * FROM staged_events WHERE stage = ? ORDER BY seq", (stage,))]
        if not rows:
            return {"status": "complete", "released": [], "remaining_stages": 0}

        cols = [field for field in EVENT_FIELDS if field != "initial_released"]
        placeholders = ", ".join(f":{field}" for field in cols)
        conn.executemany(
            f"INSERT INTO entity_events ({', '.join(cols)}) VALUES ({placeholders})",
            rows,
        )
        conn.execute("DELETE FROM staged_events WHERE stage = ?", (stage,))
        remaining = conn.execute("SELECT COUNT(DISTINCT stage) FROM staged_events").fetchone()[0]
        conn.commit()

    return {
        "status": "advanced",
        "stage": stage,
        "released": rows,
        "affected_entities": sorted({row["entity_id"] for row in rows}),
        "remaining_stages": remaining,
    }


if __name__ == "__main__":
    generate_seed_files()
    init_demo_db(reset=True)
    print(f"Seeded {DB_PATH}")
