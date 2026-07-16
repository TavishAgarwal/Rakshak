"""RAKSHAK — Synthetic multi-stage APT incident generator.

Deterministic, scripted IT→OT bridge pivot campaign plus steady-state
baseline indicators.  This is a **rule-based simulation**, NOT a trained
model (per rules.md).

Campaign progression (mapped to MITRE ATT&CK):
  T1566.001 Spearphishing → T1204.002 Malicious File → T1018 Remote
  System Discovery → T1003.001 LSASS Dump → T1021.001 RDP Lateral →
  T1136 Persistence → T1083 File Discovery → T1021.002 SMB Lateral →
  T1005 Data Collection → T1046 Service Discovery → IT→OT Bridge Pivot →
  OT Reconnaissance → OT Impact Attempt

Timeline spans 90 seconds (compressed demo time per phases.md §5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.simulation_state import get_active_simulation


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IncidentEvent:
    """A single step in the scripted APT campaign."""

    timestamp: float               # seconds from incident start
    source_node: str               # origin of the action
    target_node: str               # primary target
    event_type: str                # e.g. "credential_dump"
    mitre_tactic: str              # ATT&CK tactic name
    mitre_technique: str           # ATT&CK technique ID
    description: str
    graph_domain: str              # "IT" or "OT"
    node_effects: dict[str, dict[str, Any]] = field(default_factory=dict)
    # node_effects: {node_id: {attr_key: value_to_merge}}


# ---------------------------------------------------------------------------
# Indicator attribute defaults (applied to every node before the incident)
# ---------------------------------------------------------------------------

INDICATOR_DEFAULTS: dict[str, list[str] | int | float | bool] = {
    # Identity scorer
    "identity_flags":              [],
    # Credential scorer
    "credential_flags":            [],
    # Process scorer
    "process_flags":               [],
    "suspicious_processes":        [],
    # Network scorer
    "network_flags":               [],
    "unusual_connection_count":    0,
    "data_exfil_bytes":            0.0,
    # DNS scorer
    "dns_flags":                   [],
    "dga_domain_count":            0,
    # Cloud-API scorer
    "cloud_api_flags":             [],
    "unusual_api_call_count":      0,
    # OT-physics scorer
    "ot_physics_flags":            [],
    "sensor_deviation_pct":        0.0,
    "unauthorized_command_count":  0,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _init_indicator_defaults(graph: nx.DiGraph) -> None:
    """Set default indicator attributes on every node in *graph*."""
    for node_id in graph.nodes:
        for key, default in INDICATOR_DEFAULTS.items():
            if key not in graph.nodes[node_id]:
                # Copy mutable defaults so nodes don't share the same list
                graph.nodes[node_id][key] = (
                    list(default) if isinstance(default, list) else default
                )


def _merge_effects(graph: nx.DiGraph, node_id: str, effects: dict[str, Any], intensity_multiplier: float = 1.0) -> None:
    """Merge incident effects into a graph node's attributes.

    Merge strategy per type:
    - list  → extend (append items)
    - bool  → logical OR
    - int / float → accumulate (add) scaled by intensity_multiplier
    - other → overwrite
    """
    if node_id not in graph:
        return
    node = graph.nodes[node_id]
    for key, value in effects.items():
        if isinstance(value, list):
            existing = node.get(key, [])
            node[key] = existing + value
        elif isinstance(value, bool):
            node[key] = node.get(key, False) or value
        elif isinstance(value, (int, float)):
            node[key] = node.get(key, 0) + (value * intensity_multiplier)
        else:
            node[key] = value


# ---------------------------------------------------------------------------
# Scripted APT timeline
# ---------------------------------------------------------------------------

def get_incident_timeline() -> list[IncidentEvent]:
    """Return the full scripted APT campaign as an ordered event list.

    Every event specifies which nodes it affects and what indicator
    attributes to merge.  The timeline is deterministic and repeatable.
    """
    raw_timeline = [
        # ── Phase 1: Initial Access ──────────────────────────────
        IncidentEvent(
            timestamp=0.0,
            source_node="external",
            target_node="app-email-01",
            event_type="spearphishing_delivery",
            mitre_tactic="initial-access",
            mitre_technique="T1566.001",
            description="Spearphishing email with weaponized attachment "
                        "delivered to plant operator via email gateway",
            graph_domain="IT",
            node_effects={
                "app-email-01": {
                    "network_flags": ["inbound_phishing"],
                    "unusual_connection_count": 1,
                },
                "usr-operator-01": {
                    "identity_flags": ["phishing_target"],
                },
            },
        ),

        # ── Phase 2: Execution ───────────────────────────────────
        IncidentEvent(
            timestamp=5.0,
            source_node="usr-operator-01",
            target_node="ep-ws-01",
            event_type="malicious_file_execution",
            mitre_tactic="execution",
            mitre_technique="T1204.002",
            description="Operator opens weaponized attachment; Cobalt-Strike "
                        "beacon executes on admin workstation",
            graph_domain="IT",
            node_effects={
                "ep-ws-01": {
                    "process_flags": ["suspicious_executable", "code_injection"],
                    "suspicious_processes": ["beacon.exe", "powershell_encoded"],
                    "dns_flags": ["c2_callback"],
                    "dga_domain_count": 3,
                    "network_flags": ["c2_communication"],
                    "unusual_connection_count": 2,
                },
            },
        ),

        # ── Phase 3: Discovery ───────────────────────────────────
        IncidentEvent(
            timestamp=12.0,
            source_node="ep-ws-01",
            target_node="ep-ws-01",
            event_type="network_discovery",
            mitre_tactic="discovery",
            mitre_technique="T1018",
            description="Beacon runs internal network scan from compromised "
                        "workstation, enumerating live hosts and services",
            graph_domain="IT",
            node_effects={
                "ep-ws-01": {
                    "network_flags": ["port_scan_outbound"],
                    "unusual_connection_count": 5,
                    "process_flags": ["reconnaissance_tool"],
                    "suspicious_processes": ["portscan.ps1"],
                },
            },
        ),

        # ── Phase 4: Credential Access ───────────────────────────
        IncidentEvent(
            timestamp=20.0,
            source_node="ep-ws-01",
            target_node="ep-ws-01",
            event_type="credential_dump",
            mitre_tactic="credential-access",
            mitre_technique="T1003.001",
            description="LSASS memory dump via Mimikatz extracts domain "
                        "admin Kerberos tickets from workstation memory",
            graph_domain="IT",
            node_effects={
                "ep-ws-01": {
                    "credential_flags": ["credential_dump"],
                    "suspicious_processes": ["mimikatz.exe"],
                },
                "usr-admin-01": {
                    "credential_flags": ["credential_compromised"],
                    "identity_flags": ["credential_theft_victim"],
                },
            },
        ),

        # ── Phase 5: Lateral Movement to DC ──────────────────────
        IncidentEvent(
            timestamp=28.0,
            source_node="ep-ws-01",
            target_node="ep-srv-01",
            event_type="lateral_movement_rdp",
            mitre_tactic="lateral-movement",
            mitre_technique="T1021.001",
            description="Attacker uses stolen admin ticket to RDP into "
                        "domain controller from compromised workstation",
            graph_domain="IT",
            node_effects={
                "ep-srv-01": {
                    "identity_flags": ["unusual_login", "privilege_escalation"],
                    "credential_flags": ["pass_the_hash"],
                    "network_flags": ["unexpected_rdp"],
                    "unusual_connection_count": 1,
                },
            },
        ),

        # ── Phase 6: Persistence ─────────────────────────────────
        IncidentEvent(
            timestamp=35.0,
            source_node="ep-srv-01",
            target_node="ep-srv-01",
            event_type="persistence_install",
            mitre_tactic="persistence",
            mitre_technique="T1136.001",
            description="Backdoor admin account and scheduled task created "
                        "on domain controller for persistence",
            graph_domain="IT",
            node_effects={
                "ep-srv-01": {
                    "process_flags": ["new_local_account", "scheduled_task"],
                    "identity_flags": ["new_admin_account"],
                    "suspicious_processes": ["schtasks.exe", "net_user.exe"],
                },
            },
        ),

        # ── Phase 7: File Server Enumeration ─────────────────────
        IncidentEvent(
            timestamp=42.0,
            source_node="ep-srv-01",
            target_node="ep-srv-02",
            event_type="file_discovery",
            mitre_tactic="discovery",
            mitre_technique="T1083",
            description="Attacker enumerates file shares on secondary "
                        "file server via SMB from the domain controller",
            graph_domain="IT",
            node_effects={
                "ep-srv-02": {
                    "network_flags": ["smb_enumeration"],
                    "unusual_connection_count": 2,
                },
            },
        ),

        # ── Phase 8: Lateral Movement to File Server ─────────────
        IncidentEvent(
            timestamp=48.0,
            source_node="ep-srv-01",
            target_node="ep-srv-02",
            event_type="lateral_movement_smb",
            mitre_tactic="lateral-movement",
            mitre_technique="T1021.002",
            description="PsExec used to move to file server via SMB "
                        "using pass-the-hash with stolen credentials",
            graph_domain="IT",
            node_effects={
                "ep-srv-02": {
                    "credential_flags": ["pass_the_hash"],
                    "process_flags": ["remote_service_execution"],
                    "suspicious_processes": ["psexec.exe"],
                    "network_flags": ["unusual_smb_session"],
                    "unusual_connection_count": 1,
                },
            },
        ),

        # ── Phase 9: ERP Data Collection ─────────────────────────
        IncidentEvent(
            timestamp=55.0,
            source_node="ep-srv-02",
            target_node="app-erp-01",
            event_type="data_collection",
            mitre_tactic="collection",
            mitre_technique="T1005",
            description="Bulk export of operational data from ERP system, "
                        "staging for exfiltration via file server",
            graph_domain="IT",
            node_effects={
                "app-erp-01": {
                    "cloud_api_flags": ["unusual_data_query", "bulk_export"],
                    "unusual_api_call_count": 8,
                    "network_flags": ["large_data_transfer"],
                    "data_exfil_bytes": 52_000_000.0,
                },
            },
        ),

        # ── Phase 10: Historian API Discovery ────────────────────
        IncidentEvent(
            timestamp=62.0,
            source_node="ep-srv-01",
            target_node="api-historian-01",
            event_type="service_discovery",
            mitre_tactic="discovery",
            mitre_technique="T1046",
            description="Attacker discovers OT historian REST API and "
                        "enumerates its schema and endpoints",
            graph_domain="IT",
            node_effects={
                "api-historian-01": {
                    "cloud_api_flags": ["api_enumeration", "schema_discovery"],
                    "unusual_api_call_count": 5,
                    "network_flags": ["recon_activity"],
                    "unusual_connection_count": 2,
                },
            },
        ),

        # ── Phase 11: IT→OT Bridge Pivot (critical moment) ──────
        IncidentEvent(
            timestamp=70.0,
            source_node="api-historian-01",
            target_node="bridge-historian-01",
            event_type="bridge_pivot",
            mitre_tactic="lateral-movement",
            mitre_technique="T1021",
            description="Attacker leverages historian API to traverse the "
                        "IT/OT boundary via the bridge gateway — entering "
                        "the OT network for the first time",
            graph_domain="IT",
            node_effects={
                "bridge-historian-01": {
                    "network_flags": ["cross_zone_traffic", "unusual_opc_ua"],
                    "unusual_connection_count": 4,
                    "identity_flags": ["unauthorized_access",
                                       "unauthorized_bridge_access"],
                    "cloud_api_flags": ["historian_api_abuse"],
                    "unusual_api_call_count": 6,
                    "credential_flags": ["credential_reuse"],
                },
            },
        ),

        # ── Phase 12: OT Reconnaissance ──────────────────────────
        IncidentEvent(
            timestamp=78.0,
            source_node="bridge-historian-01",
            target_node="scada-srv-01",
            event_type="ot_reconnaissance",
            mitre_tactic="discovery",
            mitre_technique="T1046",
            description="Attacker scans the OT network from the bridge, "
                        "identifying SCADA servers and control protocols",
            graph_domain="OT",
            node_effects={
                "bridge-historian-01": {
                    "network_flags": ["cross_zone_traffic"],
                    "unusual_connection_count": 2,
                    "ot_physics_flags": ["ot_network_scan"],
                },
                "scada-srv-01": {
                    "network_flags": ["unauthorized_scan", "protocol_anomaly"],
                    "unusual_connection_count": 3,
                    "ot_physics_flags": ["reconnaissance_detected"],
                },
            },
        ),

        # ── Phase 13: OT Impact Attempt (climax) ─────────────────
        IncidentEvent(
            timestamp=85.0,
            source_node="scada-srv-01",
            target_node="plc-turbine-01",
            event_type="ot_impact_attempt",
            mitre_tactic="impact",
            mitre_technique="T0831",
            description="Attacker attempts to modify turbine PLC setpoints "
                        "via Modbus/TCP, causing sensor reading deviation — "
                        "this should trigger OT safety interlocks",
            graph_domain="OT",
            node_effects={
                "plc-turbine-01": {
                    "ot_physics_flags": ["unauthorized_setpoint_change",
                                         "firmware_query",
                                         "parameter_modification"],
                    "unauthorized_command_count": 3,
                    "process_flags": ["unauthorized_plc_write"],
                },
                "sensor-temp-01": {
                    "ot_physics_flags": ["reading_deviation"],
                    "sensor_deviation_pct": 0.65,
                },
            },
        ),
    ]

    # Remap nodes if targets are specified in simulation config
    sim = get_active_simulation()
    if sim.target_node_ids:
        targets = sim.target_node_ids
        # Find all unique nodes in the timeline (excluding 'external')
        unique_nodes = []
        for event in raw_timeline:
            if event.source_node != "external" and event.source_node not in unique_nodes:
                unique_nodes.append(event.source_node)
            if event.target_node != "external" and event.target_node not in unique_nodes:
                unique_nodes.append(event.target_node)
            for eff_node in event.node_effects.keys():
                if eff_node != "external" and eff_node not in unique_nodes:
                    unique_nodes.append(eff_node)
                    
        # Create mapping (round-robin mapping from unique timeline nodes to selected targets)
        node_map = {}
        for i, node in enumerate(unique_nodes):
            node_map[node] = targets[i % len(targets)]
            
        # Apply mapping
        remapped_timeline = []
        for event in raw_timeline:
            remapped_effects = {}
            for old_node, effects in event.node_effects.items():
                new_node = node_map.get(old_node, old_node)
                # If multiple old nodes map to same new node, merge effects
                if new_node in remapped_effects:
                    for k, v in effects.items():
                        if isinstance(v, list):
                            remapped_effects[new_node][k] = remapped_effects[new_node].get(k, []) + v
                        elif isinstance(v, bool):
                            remapped_effects[new_node][k] = remapped_effects[new_node].get(k, False) or v
                        elif isinstance(v, (int, float)):
                            remapped_effects[new_node][k] = remapped_effects[new_node].get(k, 0) + v
                        else:
                            remapped_effects[new_node][k] = v
                else:
                    # Create a copy so we don't mutate the original dictionary
                    remapped_effects[new_node] = dict(effects)
            
            # Determine new graph_domain based on the first affected node
            from app.graph import get_it_graph
            new_domain = event.graph_domain
            if remapped_effects:
                first_node = list(remapped_effects.keys())[0]
                new_domain = "IT" if first_node in get_it_graph() else "OT"

            remapped_event = IncidentEvent(
                timestamp=event.timestamp,
                source_node=node_map.get(event.source_node, event.source_node),
                target_node=node_map.get(event.target_node, event.target_node),
                event_type=event.event_type,
                mitre_tactic=event.mitre_tactic,
                mitre_technique=event.mitre_technique,
                description=event.description,
                graph_domain=new_domain,
                node_effects=remapped_effects,
            )
            remapped_timeline.append(remapped_event)
            
        return remapped_timeline

    return raw_timeline


# ---------------------------------------------------------------------------
# Application API
# ---------------------------------------------------------------------------

def apply_incident(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> list[IncidentEvent]:
    """Apply all scripted incident events to the graphs.

    1. Sets indicator defaults on every node (so scorers always find attrs).
    2. Walks the timeline and merges each event's effects into the
       appropriate graph.
    3. Returns the full event list for downstream use (audit, streaming).
    """
    _init_indicator_defaults(it_graph)
    _init_indicator_defaults(ot_graph)

    timeline = get_incident_timeline()
    for event in timeline:
        graph = it_graph if event.graph_domain == "IT" else ot_graph
        for node_id, effects in event.node_effects.items():
            _merge_effects(graph, node_id, effects)

    return timeline


def apply_single_event(
    event: IncidentEvent,
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
    intensity_multiplier: float = 1.0,
) -> list[str]:
    """Apply one event to the appropriate graph.

    Returns the list of affected node IDs (for downstream score updates).
    Does NOT re-initialize indicator defaults — caller must ensure
    _init_indicator_defaults() was called once beforehand.
    """
    graph = it_graph if event.graph_domain == "IT" else ot_graph
    affected: list[str] = []
    for node_id, effects in event.node_effects.items():
        _merge_effects(graph, node_id, effects, intensity_multiplier)
        affected.append(node_id)
    return affected


def init_defaults_only(
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
) -> None:
    """Set indicator defaults on all nodes without applying any events.

    Call once before using apply_single_event() in a streaming loop.
    """
    _init_indicator_defaults(it_graph)
    _init_indicator_defaults(ot_graph)
