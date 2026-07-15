"""RAKSHAK — OT-domain graph construction.

Builds a realistic steady-state OT graph for a CNI facility:
PLCs, RTUs, HMIs, SCADA servers, Sensors, Actuators, and one
IT_OT_BRIDGE node (matching the IT graph's bridge by ID).

Edge types: PHYSICAL_PROCESS_LINK, SAFETY_INTERLOCK, CONTROLS,
MONITORS, FIELDBUS_LINK, REDUNDANCY_PAIR.

No scoring or fusion logic — graph topology only.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from app.graph.store import OT_NODE_TYPES, OT_EDGE_TYPES


# ---------------------------------------------------------------------------
# Node builder helpers
# ---------------------------------------------------------------------------

def _add_node(
    g: nx.DiGraph,
    node_id: str,
    node_type: str,
    *,
    label: str,
    purdue_level: int = 1,
    safety_rated: bool = False,
    mission_criticality: float = 0.5,
    **extra: Any,
) -> None:
    """Add a typed OT node with mandatory metadata fields."""
    assert node_type in OT_NODE_TYPES, f"Invalid OT node type: {node_type}"
    g.add_node(
        node_id,
        node_type=node_type,
        label=label,
        purdue_level=purdue_level,
        safety_rated=safety_rated,
        mission_criticality=mission_criticality,
        anomaly_score=0.0,         # Placeholder — scoring fills this in Phase 2
        org_id="national-grid-cni",
        facility_id="grid-west-01",
        sector="power",
        policy_id="power_grid",
        **extra,
    )


def _add_edge(
    g: nx.DiGraph,
    source: str,
    target: str,
    edge_type: str,
    **attrs: Any,
) -> None:
    """Add a typed OT edge with optional attributes."""
    assert edge_type in OT_EDGE_TYPES, f"Invalid OT edge type: {edge_type}"
    g.add_edge(source, target, edge_type=edge_type, **attrs)


# ---------------------------------------------------------------------------
# Steady-state OT graph factory
# ---------------------------------------------------------------------------

def build_steady_state_ot_graph() -> nx.DiGraph:
    """Construct the baseline OT graph representing a power-grid / CNI facility.

    Topology models a simplified industrial control system:
    - SCADA server overseeing the control network
    - PLCs controlling physical processes
    - RTUs for remote telemetry
    - HMIs for operator interfaces
    - Sensors feeding readings to PLCs/RTUs
    - Actuators executing PLC commands
    - An IT_OT_BRIDGE (historian) mirroring the IT-side bridge node
    """
    g = nx.DiGraph(name="RAKSHAK_OT_Graph")

    # --- IT_OT_BRIDGE (same ID as IT graph for correlation) ---
    _add_node(g, "bridge-historian-01", "IT_OT_BRIDGE",
              label="OT Historian Gateway",
              purdue_level=3,
              safety_rated=False,
              mission_criticality=0.95,
              description="Data gateway bridging OT network to IT historian API")

    _add_node(g, "Historian-01", "IT_OT_BRIDGE",
              label="Historian Server",
              purdue_level=3,
              safety_rated=False,
              mission_criticality=0.92,
              description="Seeded demo historian bridge for scripted IT/OT pivot")

    # --- SCADA Server ---
    _add_node(g, "scada-srv-01", "SCADA_SERVER",
              label="Primary SCADA Server",
              purdue_level=3,
              safety_rated=False,
              mission_criticality=0.95,
              protocol="modbus_tcp")

    _add_node(g, "scada-srv-02", "SCADA_SERVER",
              label="Backup SCADA Server",
              purdue_level=3,
              safety_rated=False,
              mission_criticality=0.85,
              protocol="modbus_tcp")

    # --- HMIs ---
    _add_node(g, "hmi-console-01", "HMI",
              label="Control Room HMI",
              purdue_level=2,
              safety_rated=False,
              mission_criticality=0.7,
              location="control_room")

    _add_node(g, "hmi-console-02", "HMI",
              label="Engineering HMI",
              purdue_level=2,
              safety_rated=False,
              mission_criticality=0.6,
              location="engineering_bay")

    _add_node(g, "SCADA-HMI-07", "HMI",
              label="SCADA-HMI-07",
              purdue_level=2,
              safety_rated=True,
              mission_criticality=0.96,
              location="control_room")

    # --- PLCs ---
    _add_node(g, "plc-turbine-01", "PLC",
              label="Turbine Controller PLC",
              purdue_level=1,
              safety_rated=True,
              mission_criticality=0.98,
              firmware="v4.2.1",
              process="turbine_speed_control")

    _add_node(g, "plc-cooling-01", "PLC",
              label="Cooling System PLC",
              purdue_level=1,
              safety_rated=True,
              mission_criticality=0.9,
              firmware="v3.8.0",
              process="cooling_loop")

    _add_node(g, "plc-valve-01", "PLC",
              label="Valve Bank PLC",
              purdue_level=1,
              safety_rated=True,
              mission_criticality=0.85,
              firmware="v4.0.3",
              process="valve_sequencing")

    # --- RTUs ---
    _add_node(g, "rtu-substation-01", "RTU",
              label="Substation RTU Alpha",
              purdue_level=1,
              safety_rated=False,
              mission_criticality=0.8,
              protocol="dnp3",
              location="substation_alpha")

    _add_node(g, "rtu-substation-02", "RTU",
              label="Substation RTU Beta",
              purdue_level=1,
              safety_rated=False,
              mission_criticality=0.8,
              protocol="dnp3",
              location="substation_beta")

    # --- Sensors ---
    _add_node(g, "sensor-temp-01", "SENSOR",
              label="Turbine Temperature Sensor",
              purdue_level=0,
              safety_rated=True,
              mission_criticality=0.7,
              measurement="temperature_celsius",
              range_min=20.0,
              range_max=650.0)

    _add_node(g, "sensor-pressure-01", "SENSOR",
              label="Cooling Pressure Sensor",
              purdue_level=0,
              safety_rated=True,
              mission_criticality=0.7,
              measurement="pressure_bar",
              range_min=0.0,
              range_max=25.0)

    _add_node(g, "sensor-flow-01", "SENSOR",
              label="Flow Rate Sensor",
              purdue_level=0,
              safety_rated=False,
              mission_criticality=0.5,
              measurement="flow_liters_per_min",
              range_min=0.0,
              range_max=500.0)

    _add_node(g, "sensor-voltage-01", "SENSOR",
              label="Grid Voltage Sensor",
              purdue_level=0,
              safety_rated=False,
              mission_criticality=0.75,
              measurement="voltage_kv",
              range_min=0.0,
              range_max=400.0)

    # --- Actuators ---
    _add_node(g, "act-valve-01", "ACTUATOR",
              label="Main Steam Valve",
              purdue_level=0,
              safety_rated=True,
              mission_criticality=0.9,
              actuator_type="pneumatic_valve")

    _add_node(g, "act-breaker-01", "ACTUATOR",
              label="Circuit Breaker",
              purdue_level=0,
              safety_rated=True,
              mission_criticality=0.85,
              actuator_type="electrical_breaker")

    # === Edges ===

    # Bridge → SCADA (DATA_FLOW equivalent via FIELDBUS_LINK at higher Purdue level)
    _add_edge(g, "bridge-historian-01", "scada-srv-01", "FIELDBUS_LINK",
              protocol="opc_ua", purdue_boundary="L3-L3")
    _add_edge(g, "Historian-01", "SCADA-HMI-07", "FIELDBUS_LINK",
              protocol="opc_ua", purdue_boundary="L3-L2")

    # SCADA ↔ SCADA (REDUNDANCY_PAIR)
    _add_edge(g, "scada-srv-01", "scada-srv-02", "REDUNDANCY_PAIR",
              failover_mode="hot_standby")
    _add_edge(g, "scada-srv-02", "scada-srv-01", "REDUNDANCY_PAIR",
              failover_mode="hot_standby")

    # SCADA → HMIs (FIELDBUS_LINK)
    _add_edge(g, "scada-srv-01", "hmi-console-01", "FIELDBUS_LINK",
              protocol="opc_ua", purdue_boundary="L3-L2")
    _add_edge(g, "scada-srv-01", "hmi-console-02", "FIELDBUS_LINK",
              protocol="opc_ua", purdue_boundary="L3-L2")
    _add_edge(g, "scada-srv-01", "SCADA-HMI-07", "FIELDBUS_LINK",
              protocol="opc_ua", purdue_boundary="L3-L2")

    # SCADA → PLCs (CONTROLS)
    _add_edge(g, "scada-srv-01", "plc-turbine-01", "CONTROLS",
              protocol="modbus_tcp", purdue_boundary="L3-L1")
    _add_edge(g, "scada-srv-01", "plc-cooling-01", "CONTROLS",
              protocol="modbus_tcp", purdue_boundary="L3-L1")
    _add_edge(g, "scada-srv-01", "plc-valve-01", "CONTROLS",
              protocol="modbus_tcp", purdue_boundary="L3-L1")

    # SCADA → RTUs (CONTROLS)
    _add_edge(g, "scada-srv-01", "rtu-substation-01", "CONTROLS",
              protocol="dnp3", purdue_boundary="L3-L1")
    _add_edge(g, "scada-srv-01", "rtu-substation-02", "CONTROLS",
              protocol="dnp3", purdue_boundary="L3-L1")

    # PLCs → Sensors (MONITORS)
    _add_edge(g, "plc-turbine-01", "sensor-temp-01", "MONITORS",
              signal="analog_input", purdue_boundary="L1-L0")
    _add_edge(g, "plc-cooling-01", "sensor-pressure-01", "MONITORS",
              signal="analog_input", purdue_boundary="L1-L0")
    _add_edge(g, "plc-valve-01", "sensor-flow-01", "MONITORS",
              signal="analog_input", purdue_boundary="L1-L0")

    # RTU → Sensor (MONITORS)
    _add_edge(g, "rtu-substation-01", "sensor-voltage-01", "MONITORS",
              signal="analog_input", purdue_boundary="L1-L0")

    # PLCs → Actuators (CONTROLS)
    _add_edge(g, "plc-valve-01", "act-valve-01", "CONTROLS",
              signal="digital_output", purdue_boundary="L1-L0")
    _add_edge(g, "rtu-substation-01", "act-breaker-01", "CONTROLS",
              signal="digital_output", purdue_boundary="L1-L0")

    # Physical process links (sensors and actuators involved in the same process)
    _add_edge(g, "sensor-temp-01", "act-valve-01", "PHYSICAL_PROCESS_LINK",
              process="turbine_thermal_loop",
              description="Temp sensor feeds back to steam valve control")
    _add_edge(g, "sensor-pressure-01", "act-valve-01", "PHYSICAL_PROCESS_LINK",
              process="cooling_pressure_loop",
              description="Pressure sensor feeds back to valve sequencing")

    # Safety interlocks (critical safety-rated connections)
    _add_edge(g, "plc-turbine-01", "plc-cooling-01", "SAFETY_INTERLOCK",
              interlock_type="thermal_protection",
              description="Turbine overheat triggers cooling system override")
    _add_edge(g, "plc-cooling-01", "plc-valve-01", "SAFETY_INTERLOCK",
              interlock_type="pressure_relief",
              description="Cooling failure triggers emergency valve open")

    # RTU redundancy
    _add_edge(g, "rtu-substation-01", "rtu-substation-02", "REDUNDANCY_PAIR",
              failover_mode="warm_standby")
    _add_edge(g, "rtu-substation-02", "rtu-substation-01", "REDUNDANCY_PAIR",
              failover_mode="warm_standby")

    return g
