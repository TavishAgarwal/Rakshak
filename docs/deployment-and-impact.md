# Business Impact & Deployment Path

This document outlines the gap between the current hackathon MVP state of RAKSHAK and the requirements for a full production deployment in a Critical National Infrastructure (CNI) environment.

## Business Impact Model
The UI component `BusinessImpactCalculator` provides a transparent formula for estimating cost avoidance: **Exposure = MTTR Reduction × Tier Hourly Cost**. The assumptions for the asset criticality tiers are based on estimated hourly downtime costs for varying scales of infrastructure:
- **Critical (Tier 0)**: $1,000,000/hr (e.g., regional power grid failure, major payment gateway outage)
- **High (Tier 1)**: $250,000/hr (e.g., core banking service, hospital critical care network)
- **Medium (Tier 2)**: $50,000/hr (e.g., corporate IT services, secondary logistics)
- **Low (Tier 3)**: $10,000/hr (e.g., internal portals, back-office administration)

## 1. Telemetry Ingestion Path
Currently, RAKSHAK is driven by `demo_data.py` and `synthetic_incident.py` using normalized CSV subsets and static fixtures. 

**To ingest real telemetry:**
- The data generation loop must be replaced with an event broker consumer (e.g., Apache Kafka or AWS Kinesis).
- A stream processing adapter must map incoming SIEM (e.g., Splunk/Sentinel) and OT (e.g., Claroty/Nozomi) logs to the unified schema expected by `streaming.py`.
- The `apply_single_event` function would no longer poll a synthetic timeline, but rather act as a callback handler for the consumer group.

## 2. Integration with Existing SOC Workflows
RAKSHAK is not designed to replace an entire SOC platform overnight. It can act as a decision-support engine.

**Realistic Integration Point:**
- The `/api/response-decisions` output can be exported as a JSON payload to a webhook. 
- A mature SOAR tool (like Cortex XSOAR or Splunk SOAR) can consume RAKSHAK's `{belief, plausibility, uncertainty}` scores and `GateDecision` payloads. 
- The SOAR tool's own playbooks can parse RAKSHAK's "allowed" vs "blocked" recommendations, enforcing the OT safety hard-blocks before executing any API calls to downstream infrastructure.

## 3. Path to Production Readiness
To move RAKSHAK from MVP to a production-ready enterprise product, the following gaps must be closed:
- **Persistence Layer:** While `benchmark_networkx.py` proves an 85k-node graph works in memory, true production needs a highly available graph database (e.g., Neo4j or Amazon Neptune) with Cypher/Gremlin queries to handle multi-tenant concurrency and disaster recovery.
- **Authentication & RBAC:** The current MVP lacks an Auth model. Real deployments need enterprise SSO integration (SAML/OIDC) and granular role-based access control, especially for overriding OT response gates.
- **Live Response Connectors:** The mocked state-mutating playbooks in `soar_state.py` must be swapped for real API wrappers (e.g., hitting CrowdStrike APIs for endpoint isolation or Palo Alto firewalls for IP blocking).
