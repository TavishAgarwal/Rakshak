# RAKSHAK — Evaluation Metrics & Coverage

This document outlines the real, evidence-backed metrics calculated against the synthetic and normalized benchmark subsets using RAKSHAK's evaluation engine.

## MTTD / MTTR (Mean Time to Detect / Respond)
These metrics are derived by replaying the scripted IT-to-OT incident dataset.
- **Baseline Naive SOC**: Assumes single-source raw threshold alerts (score >= 0.85) without Dempster-Shafer fusion for detection. MTTR assumes all response steps are manual and require human action (10 mins per step).
- **RAKSHAK**: Uses DS fused belief >= 0.65 for detection. MTTR uses autonomous idempotent playbook state mutations (0s for autonomous steps).

| Metric | Naive SOC Baseline | RAKSHAK | Improvement |
| :--- | :--- | :--- | :--- |
| **MTTD** | 0.1667 hours | 0.1667 hours | 0.0% |
| **MTTR** | 6.1667 hours | 3.2250 hours | **47.7%** |

*(Note: In the specific incident scenario evaluated, RAKSHAK and the Naive SOC detect the incident at the same timestamp since raw threshold breach coincided with the fused breach. The massive MTTR improvement stems entirely from autonomous state mutation execution vs human-in-the-loop delays).*

## Anomaly Detection Metrics (Dempster-Shafer Fusion)
Metrics computed by mapping normalized telemetry CSV subsets (CICIDS2018 for IT, SWaT-WADI for OT) into `score_all` and `fuse_scores`.
**Note: These numbers represent a unit-scale sanity check (n=16), not a statistical benchmark. A full benchmark against CICIDS2018/SWaT-WADI is planned future work, not completed work.**
- **Threshold**: 0.65 belief threshold
- **Methodology**: Real DS fusion metrics computed from tiny CSV subsets using score_all and fuse_scores.

| Dataset | Samples | Precision | Recall (Detection Rate) | F1 Score | False Positive Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CICIDS2018 (IT)** | 8 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **SWaT-WADI (OT)** | 8 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| **Overall** | 16 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |


## Response Automation Coverage
RAKSHAK's SOAR playbooks are state-mutating and idempotent. 

| Metric | Value |
| :--- | :--- |
| **Total Playbook Steps** | 21 |
| **Autonomously Executable (Real State Mutations)** | 18 |
| **Requires Human Approval** | 2 |
| **Safety Blocked (OT Disruption)** | 1 |
| **Actual Automation Coverage** | **85.7%** |

Every autonomous step interacts with `soar_state.py` to record a real side-effect mutation, allowing secondary executions of the same playbook step on the same entity to correctly return a `skipped` status.

- **Note on System Boundaries**: The `isolate_endpoint` playbook (`edr-isolate` step) goes beyond local state mutation and makes a real HTTP request across a system boundary to a mock EDR service (`mock_services/edr_mock.py`). If the service is running on port 8001, it accurately tracks external state and enforces idempotency through HTTP responses. All other playbooks rely strictly on local simulated state tracking.
