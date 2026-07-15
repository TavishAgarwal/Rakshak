# RAKSHAK — Build Phases

Each phase is scoped so an AI coding agent can complete it in one focused session without
touching other phases' files. Agent must read PRD.md, architecture.md, rules.md, and design.md
before starting any phase, and must not do work outside that phase's listed scope.

## Phase 0 — Scaffolding
Repo structure, FastAPI skeleton, Next.js skeleton, env config, health-check endpoint,
`requirements.txt` / `package.json`. No business logic yet.

## Phase 1 — Graph Data Layer
NetworkX-based IT graph + OT graph schema, node/edge types per architecture.md §4 (IT graph) and
the OT graph section, `IT_OT_BRIDGE` node type, JSON persistence, `GET /graph` endpoint,
synthetic steady-state graph (no incident yet).

## Phase 2 — Synthetic Incident + Behavior Scorers
`synthetic_incident.py` generating a scripted multi-stage APT (IT→OT pivot). Seven independent
behavior-class scorers producing labeled scores per architecture.md. No fusion yet — raw scores
only, exposed via a temporary debug endpoint.

## Phase 3 — Evidence Fusion + Campaign State Machine
Real Dempster-Shafer combination over the Phase 2 scores. Kill-chain state machine with
precondition constraints enforced via graph logic. `GET /entity/{id}` returns mission criticality
vector + campaign state distribution + evidence log.

## Phase 4 — Response Gate + Resilience Score
Safety-gated response logic (confidence × mission criticality × asset type), OT hard-block rule.
Resilience score formula and `GET /resilience-score`. Audit log wired to record every gated
decision and every fused score.

## Phase 5 — Realtime Streaming
WebSocket `/stream` pushing graph/score deltas as the scripted incident plays out over a fixed
timeline (e.g. 90 seconds compressed demo time).

## Phase 6 — Frontend Shell + Design System
Next.js app shell, Tailwind config with design.md's token system, glass panel primitives,
typography setup, base layout matching design.md's wireframe (no live data yet — static mock).

## Phase 7 — Living Graph (signature element)
Canvas/SVG force-directed renderer with breathing/pulse animation tied to per-node uncertainty,
distinct bridge-node styling, click-to-select wired to Entity Inspector state.

## Phase 8 — Resilience Signals + Entity Inspector + Score Breakdown
Wire Signals panel to real per-source scores, Inspector to `/entity/{id}`, Score Breakdown band to
`/resilience-score`. All live via the Phase 5 WebSocket.

## Phase 9 — AI Query Bar + Narration
`POST /query` assembling structured evidence for the selected cluster, Claude API call scoped to
narration only, frontend query bar UI wired to it.

## Phase 10 — Incident Demo Polish
End-to-end run-through of the scripted incident, response-gate demo interaction, audit trail
viewer, empty/loading/error states, responsive pass, final visual QA against design.md.