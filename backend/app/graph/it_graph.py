"""RAKSHAK — IT-domain graph construction.

Builds a realistic steady-state IT graph for a CNI operator:
Users, Endpoints, Cloud Resources, Applications, APIs, and one
IT_OT_BRIDGE node linking to the OT domain.

Edge types: AUTHENTICATES_TO, ACCESSES, TRUST_LEVEL, SECURITY_ZONE,
DATA_FLOW, LATERAL_MOVEMENT.

No scoring or fusion logic — graph topology only.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from app.graph.store import IT_NODE_TYPES, IT_EDGE_TYPES


# ---------------------------------------------------------------------------
# Node builder helpers
# ---------------------------------------------------------------------------

def _add_node(
    g: nx.DiGraph,
    node_id: str,
    node_type: str,
    *,
    label: str,
    security_zone: str = "corporate",
    trust_level: float = 0.5,
    mission_criticality: float = 0.5,
    **extra: Any,
) -> None:
    """Add a typed node with mandatory metadata fields."""
    assert node_type in IT_NODE_TYPES, f"Invalid IT node type: {node_type}"
    g.add_node(
        node_id,
        node_type=node_type,
        label=label,
        security_zone=security_zone,
        trust_level=trust_level,
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
    """Add a typed edge with optional attributes."""
    assert edge_type in IT_EDGE_TYPES, f"Invalid IT edge type: {edge_type}"
    g.add_edge(source, target, edge_type=edge_type, **attrs)


# ---------------------------------------------------------------------------
# Steady-state IT graph factory
# ---------------------------------------------------------------------------

def build_steady_state_it_graph() -> nx.DiGraph:
    """Construct the baseline IT graph representing a CNI operator's IT estate.

    Topology models a simplified government/CNI network:
    - Domain admin + regular users authenticating to endpoints
    - Endpoints accessing applications and cloud resources
    - Applications communicating via APIs
    - An IT_OT_BRIDGE (historian/data gateway) connecting IT↔OT
    """
    g = nx.DiGraph(name="RAKSHAK_IT_Graph")

    # --- Users ---
    _add_node(g, "usr-admin-01", "USER",
              label="Domain Admin",
              security_zone="corporate",
              trust_level=0.9,
              mission_criticality=0.8,
              role="domain_admin")

    _add_node(g, "usr-analyst-01", "USER",
              label="SOC Analyst",
              security_zone="soc",
              trust_level=0.7,
              mission_criticality=0.6,
              role="soc_analyst")

    _add_node(g, "usr-operator-01", "USER",
              label="Plant Operator",
              security_zone="corporate",
              trust_level=0.6,
              mission_criticality=0.7,
              role="plant_operator")

    # --- Endpoints ---
    _add_node(g, "ep-ws-01", "ENDPOINT",
              label="Admin Workstation",
              security_zone="corporate",
              trust_level=0.8,
              mission_criticality=0.7,
              os="windows_11",
              endpoint_type="workstation")

    _add_node(g, "ep-ws-02", "ENDPOINT",
              label="Analyst Workstation",
              security_zone="soc",
              trust_level=0.7,
              mission_criticality=0.5,
              os="windows_11",
              endpoint_type="workstation")

    _add_node(g, "ep-srv-01", "ENDPOINT",
              label="Domain Controller",
              security_zone="corporate",
              trust_level=0.95,
              mission_criticality=0.95,
              os="windows_server_2022",
              endpoint_type="server")

    _add_node(g, "ep-srv-02", "ENDPOINT",
              label="File Server",
              security_zone="corporate",
              trust_level=0.7,
              mission_criticality=0.6,
              os="windows_server_2022",
              endpoint_type="server")

    # --- Cloud Resources ---
    _add_node(g, "cloud-siem-01", "CLOUD_RESOURCE",
              label="SIEM Platform",
              security_zone="cloud",
              trust_level=0.8,
              mission_criticality=0.7,
              service="azure_sentinel")

    _add_node(g, "cloud-storage-01", "CLOUD_RESOURCE",
              label="Log Archive",
              security_zone="cloud",
              trust_level=0.6,
              mission_criticality=0.4,
              service="s3_bucket")

    # --- Applications ---
    _add_node(g, "app-erp-01", "APPLICATION",
              label="ERP System",
              security_zone="corporate",
              trust_level=0.7,
              mission_criticality=0.8,
              app_type="enterprise")

    _add_node(g, "app-email-01", "APPLICATION",
              label="Email Gateway",
              security_zone="dmz",
              trust_level=0.5,
              mission_criticality=0.6,
              app_type="communication")

    # --- APIs ---
    _add_node(g, "api-auth-01", "API",
              label="Auth Service API",
              security_zone="corporate",
              trust_level=0.85,
              mission_criticality=0.8,
              protocol="REST")

    _add_node(g, "AuthServer-03", "ENDPOINT",
              label="AuthServer-03",
              security_zone="corporate",
              trust_level=0.9,
              mission_criticality=0.82,
              os="windows_server_2022",
              endpoint_type="auth_server")

    _add_node(g, "API-Gateway-01", "API",
              label="API Gateway",
              security_zone="dmz",
              trust_level=0.7,
              mission_criticality=0.76,
              protocol="REST")

    _add_node(g, "api-historian-01", "API",
              label="Historian Data API",
              security_zone="dmz",
              trust_level=0.6,
              mission_criticality=0.9,
              protocol="REST")

    # --- IT_OT_BRIDGE ---
    _add_node(g, "bridge-historian-01", "IT_OT_BRIDGE",
              label="OT Historian Gateway",
              security_zone="dmz",
              trust_level=0.5,
              mission_criticality=0.95,
              description="Data gateway bridging IT network to OT SCADA/historian")

    _add_node(g, "Historian-01", "IT_OT_BRIDGE",
              label="Historian Server",
              security_zone="dmz",
              trust_level=0.5,
              mission_criticality=0.92,
              description="Seeded demo historian bridge for the scripted APT replay")

    # === Edges ===

    # Users → Endpoints (AUTHENTICATES_TO)
    _add_edge(g, "usr-admin-01", "ep-ws-01", "AUTHENTICATES_TO", method="kerberos")
    _add_edge(g, "usr-admin-01", "ep-srv-01", "AUTHENTICATES_TO", method="kerberos")
    _add_edge(g, "usr-analyst-01", "ep-ws-02", "AUTHENTICATES_TO", method="kerberos")
    _add_edge(g, "usr-operator-01", "ep-ws-01", "AUTHENTICATES_TO", method="password")

    # Endpoints → Applications / Cloud (ACCESSES)
    _add_edge(g, "ep-ws-01", "app-erp-01", "ACCESSES", access_level="read_write")
    _add_edge(g, "ep-ws-01", "app-email-01", "ACCESSES", access_level="read_write")
    _add_edge(g, "ep-ws-02", "cloud-siem-01", "ACCESSES", access_level="read")
    _add_edge(g, "ep-srv-01", "cloud-storage-01", "ACCESSES", access_level="write")

    # Server → Server (LATERAL_MOVEMENT potential paths)
    _add_edge(g, "ep-srv-01", "ep-srv-02", "LATERAL_MOVEMENT", protocol="smb")
    _add_edge(g, "ep-ws-01", "ep-srv-01", "LATERAL_MOVEMENT", protocol="rdp")

    # Application → API (DATA_FLOW)
    _add_edge(g, "app-erp-01", "api-auth-01", "DATA_FLOW", protocol="https")
    _add_edge(g, "app-erp-01", "api-historian-01", "DATA_FLOW", protocol="https")
    _add_edge(g, "AuthServer-03", "API-Gateway-01", "LATERAL_MOVEMENT", protocol="kerberos")
    _add_edge(g, "API-Gateway-01", "Historian-01", "DATA_FLOW", protocol="https")

    # API → Bridge (DATA_FLOW — the critical IT→OT path)
    _add_edge(g, "api-historian-01", "bridge-historian-01", "DATA_FLOW",
              protocol="https", description="Historian API feeds OT data gateway")
    _add_edge(g, "Historian-01", "bridge-historian-01", "DATA_FLOW",
              protocol="opc_ua", description="Seeded demo historian bridge path")

    # Security zone boundaries (SECURITY_ZONE edges mark zone transitions)
    _add_edge(g, "ep-ws-01", "app-email-01", "SECURITY_ZONE",
              from_zone="corporate", to_zone="dmz")
    _add_edge(g, "app-erp-01", "bridge-historian-01", "SECURITY_ZONE",
              from_zone="corporate", to_zone="dmz")

    # Trust level edges
    _add_edge(g, "ep-srv-01", "api-auth-01", "TRUST_LEVEL",
              trust_score=0.9, direction="delegates_auth")
    _add_edge(g, "cloud-siem-01", "cloud-storage-01", "TRUST_LEVEL",
              trust_score=0.7, direction="log_archive")

    return g
