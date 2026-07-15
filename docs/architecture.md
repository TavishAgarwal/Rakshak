# RAKSHAK — Architecture

## 1. High-Level Flow
Synthetic IT/OT event feed
│
▼
Ingestion Service ── writes ──▶ Graph Store (IT graph + OT graph, JSON/NetworkX)
│
▼
Behavior Scoring Service (per-class scorers: identity, credential, process,
network, DNS, cloud-API, OT-physics) → independent labeled scores (m1..m5)
│
▼
Evidence Fusion Service (Dempster-Shafer combine) → {belief, plausibility, uncertainty}
│
▼
Campaign State Engine (state machine over kill-chain phases,
Cypher-style graph constraint checks done in-process against NetworkX graph)
│
▼
├──▶ Narration Service (Claude API) — narrates matched path / unattributed cluster only
│
▼
Response Gate Service (confidence × mission_criticality × asset_type → allowed actions)
│
▼
Resilience Score Service (redundancy, degraded-mode, recovery time, continuity)
│
▼
Audit Log (append-only, every fused score + action with contributing sources)
│
▼
Frontend Dashboard (Living Graph, Signals panel, Inspector, Score breakdown)

Rule carried through: **LLM is only called in the Narration Service and the AI Query Bar** — never
in scoring, fusion, or matching. Those stay deterministic Python.

## 2. Tech Stack
- **Frontend:** Next.js (App Router) + TypeScript + Tailwind CSS
- **Graph visualization:** D3-force (custom canvas/SVG renderer for the Living Graph — no
  off-the-shelf graph-widget library, since the "breathing" behavior is the signature element)
- **Backend:** FastAPI (Python 3.11)
- **Graph store:** NetworkX in-memory graph, persisted to JSON on disk (Neo4j is a stated
  stretch goal only if time remains — do not block MVP on it)
- **LLM:** Anthropic API (Claude), used only for narration + query-bar responses
- **State/data fetching (frontend):** TanStack Query
- **Realtime:** WebSocket (FastAPI) pushing score/graph updates to the dashboard
- **Synthetic data:** Python script generating a scripted multi-stage incident (IT→OT bridge
  pivot) plus steady-state "quiet" telemetry

## 3. Folder / File Structure
rakshak/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app entry, WS + REST routes
│   │   ├── graph/
│   │   │   ├── store.py             # NetworkX graph load/save, node/edge schema
│   │   │   ├── it_graph.py
│   │   │   └── ot_graph.py
│   │   ├── scoring/
│   │   │   ├── behavior_classes.py  # 7 independent scorers
│   │   │   └── mission_criticality.py
│   │   ├── fusion/
│   │   │   └── dempster_shafer.py   # real DS combine implementation
│   │   ├── campaign/
│   │   │   ├── state_machine.py     # kill-chain probabilistic states
│   │   │   └── attack_mapper.py     # ATT&CK subgraph matching
│   │   ├── response/
│   │   │   ├── gate.py              # safety-gated decision logic
│   │   │   └── policy_engine.py     # (stretch) org policy weighting
│   │   ├── resilience/
│   │   │   ├── score.py             # resilience score formula
│   │   │   └── recovery_sequencer.py# (stretch)
│   │   ├── narration/
│   │   │   └── claude_client.py     # LLM calls, scoped prompts only
│   │   ├── audit/
│   │   │   └── log.py               # append-only audit trail
│   │   └── data/
│   │       └── synthetic_incident.py
│   └── requirements.txt
├── frontend/
│   ├── app/
│   │   ├── page.tsx                 # dashboard shell
│   │   └── layout.tsx
│   ├── components/
│   │   ├── LivingGraph/
│   │   ├── ResilienceSignals/
│   │   ├── EntityInspector/
│   │   ├── ResilienceScoreBar/
│   │   ├── AIQueryBar/
│   │   └── ui/                      # glass panel, badge, tabs primitives
│   ├── lib/
│   │   ├── api.ts
│   │   └── ws.ts
│   └── styles/globals.css
├── docs/
│   ├── PRD.md
│   ├── architecture.md
│   ├── rules.md
│   ├── phases.md
│   └── design.md
└── README.md

## 4. Key API Endpoints
- `GET /graph` — current IT+OT graph snapshot
- `WS /stream` — pushes score/graph deltas during the scripted incident
- `GET /entity/{id}` — mission criticality vector, campaign state distribution, evidence log
- `POST /query` — AI query bar; server assembles structured evidence, calls narration service
- `GET /resilience-score` — current breakdown
- `POST /incident/{id}/respond` — trigger response gate evaluation (returns allowed actions only)