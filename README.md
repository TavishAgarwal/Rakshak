# RAKSHAK

**AI-Driven Cyber Resilience Intelligence Platform for Indian Critical National Infrastructure**

RAKSHAK is a hackathon MVP for **ET AI Hackathon 2026 - PS7**, focused on cyber resilience for critical national infrastructure. The core idea is simple: a CNI security platform should not only ask "is this malicious?" It should also ask "can the mission keep operating safely while we respond?"

The system models separate IT and OT estates, scores suspicious behavior through deterministic evidence sources, fuses uncertainty with Dempster-Shafer theory, tracks campaign progression, gates response actions by mission criticality and asset type, and keeps an auditable record of automated recommendations.

## What It Does

- **Living IT/OT graph:** separate IT and OT NetworkX graphs, correlated only through explicit `IT_OT_BRIDGE` nodes.
- **Scripted multi-stage incident:** synthetic APT-style flow from initial IT compromise through IT-to-OT pivot and OT impact.
- **Independent behavior scoring:** identity, credential, process, network, DNS, cloud/API, and OT-physics signals remain visible before fusion.
- **Evidence fusion:** Dempster-Shafer combination returns belief, plausibility, uncertainty, and conflict rather than a single opaque score.
- **Campaign state tracking:** deterministic kill-chain state machine estimates the dominant attack phase.
- **Mission criticality vector:** scores operational importance, data sensitivity, connectivity risk, safety impact, recovery difficulty, and composite criticality.
- **Resilience score:** continuously estimates redundancy coverage, degraded-mode availability, recovery speed, and service continuity.
- **Safety-gated response:** OT active disruption actions are hard-blocked in code; IT actions are tiered by confidence and criticality.
- **AI narration:** Claude can narrate graph-computed evidence, but never decides scores, matches, or response actions.
- **Audit trail:** response decisions are hash-chained and verifiable.
- **Judge evidence pack:** PS7 metrics for detection, false positives, ATT&CK attribution, playbook coverage, MTTD/MTTR, India-CNI context, and audit verification.

## Tech Stack

- **Backend:** FastAPI, Python, NetworkX, Pydantic, Uvicorn
- **Frontend:** Next.js App Router, React, TypeScript, Tailwind CSS, D3, SWR
- **Realtime:** FastAPI WebSocket stream
- **Data:** synthetic graph and incident data persisted as JSON/JSONL
- **LLM:** Anthropic Claude for narration only, with deterministic fallback when no API key is configured
- **CI:** GitHub Actions workflow for backend tests and frontend type-check/build

## Repository Layout

```text
backend/
  app/
    audit/          Hash-chained response audit log
    campaign/       ATT&CK-style campaign state logic
    data/           Synthetic incident generator
    fusion/         Dempster-Shafer implementation
    graph/          IT/OT NetworkX graph construction and persistence
    narration/      Claude narration client and fallback
    resilience/     Resilience score logic
    response/       Safety gate and response decision logic
    scoring/        Deterministic behavior scorers
    main.py         FastAPI app and route definitions
  data/             Demo graph, STIX subset, audit JSONL files
  tests/            Backend unit and security tests
  requirements.txt

frontend/
  app/              Next.js app shell
  components/       Dashboard panels and visualizations
  lib/              API, WebSocket, and UI state helpers
  styles/           Global Tailwind/CSS tokens
  package.json

docs/
  PRD.md
  architecture.md
  architecture-diagram.svg
  evaluation.md
  design.md
  phases.md
  rules.md

deliverables/
  RAKSHAK_PS7_deck.pptx
  RAKSHAK_demo_video.mp4
  RAKSHAK_demo_video_script.md

.github/workflows/ci.yml
```

## Quick Start

### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Verify:

```bash
curl http://localhost:8000/health
```

Expected:

```json
{"status":"ok","service":"rakshak-backend"}
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

## Environment Variables

RAKSHAK runs without live secrets by default. The narration layer falls back to deterministic text if no Anthropic key is present.

| Variable | Required | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | No | Enables Claude narration for `/query`. If absent, deterministic fallback narration is used. |
| `RAKSHAK_NARRATION_MODEL` | No | Overrides the Claude model name used by the narration client. |
| `RAKSHAK_DATA_DIR` | No | Overrides backend data storage path for graphs and audit logs. |
| `RAKSHAK_RESPONSE_API_TOKEN` | Required for response POSTs | Bearer token required before `/api/entities/{node_id}/response-decision` can evaluate or execute response actions. |
| `NEXT_PUBLIC_API_URL` | No | Frontend REST API base URL. Defaults to `http://localhost:8000`. |
| `NEXT_PUBLIC_WS_URL` | No | Frontend WebSocket base URL. Defaults to `ws://localhost:8000`. |

Example response-action call:

```bash
export RAKSHAK_RESPONSE_API_TOKEN="replace-with-local-demo-token"

curl -X POST "http://localhost:8000/api/entities/ep-ws-01/response-decision" \
  -H "Authorization: Bearer $RAKSHAK_RESPONSE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"isolate_endpoint"}'
```

Do not commit real API keys or tokens. Use a local `.env` file or shell environment for secrets.

## API Overview

Core routes:

| Route | Method | Description |
| --- | --- | --- |
| `/health` | GET | Backend health check |
| `/graph` | GET | Current IT and OT graph snapshot |
| `/stream` | WebSocket | Scripted incident stream with graph/score deltas |
| `/entity/{node_id}` | GET | Entity inspector data: criticality, fusion, campaign state, response gate |
| `/query` | POST | AI Query Bar narration over structured evidence |
| `/api/resilience-score` | GET | Headline resilience score and component breakdown |
| `/api/entities/{node_id}/evidence` | GET | Five source scores and fused uncertainty metrics |
| `/api/entities/{node_id}/campaign-state` | GET | Campaign state probability distribution |
| `/api/entities/{node_id}/evidence-log` | GET | Evidence log for an entity |
| `/api/graph/live-state` | GET | Current belief/uncertainty for graph nodes |
| `/api/response-decisions` | GET | Read-only response decision previews |
| `/api/entities/{node_id}/response-decision` | POST | Token-gated response decision/action endpoint |
| `/api/audit` | GET | Hash-chained response audit entries |
| `/api/audit/verify` | GET | Verify audit-chain integrity |
| `/api/evaluation/summary` | GET | PS7 judge metrics and audit verification |
| `/api/threat-intel/advisories` | GET | CERT-In-style advisory and India-CNI scenario fixtures |
| `/api/policies` | GET | Available sector policy packs |
| `/api/demo/context` | GET/POST | Active judge-demo scenario and policy |

Debug/development routes:

| Route | Method | Description |
| --- | --- | --- |
| `/api/entities/{entity_id}/fuse` | POST | Manual Dempster-Shafer fusion sandbox |
| `/audit` | GET | General audit log view for fusion/gate/resilience events |

## Security Model

This is a hackathon/demo system, but the code aims to avoid public-repo red flags:

- API keys are read from environment variables, not source literals.
- Claude output is display-only and never affects scoring, fusion, campaign matching, or response gating.
- The AI Query Bar renders narration as React text nodes, not injected HTML.
- CORS is explicitly limited to `http://localhost:3000` in the demo backend.
- Response-action POSTs require `Authorization: Bearer <RAKSHAK_RESPONSE_API_TOKEN>`.
- OT disruptive actions such as `ot_shutdown_plc`, `ot_isolate_segment`, and `ot_disable_actuator` are hard-blocked in backend code.
- Response decisions are written to a hash chain and can be verified with `/api/audit/verify`.
- Fusion results, ATT&CK mapping, threat-intel matches, response decisions, and playbook steps are hash-chain auditable.

Recommended before publishing a fresh public repository:

- Add a root `.gitignore` for `.env`, `.env.local`, `node_modules`, `.next`, `venv`, `__pycache__`, `.pytest_cache`, `*.db`, `*.sqlite`, `secrets/`, `credentials/`, and `.DS_Store`.
- Do not commit local `frontend/node_modules`, `frontend/.next`, `backend/venv`, or generated audit logs unless intentionally fixture-scoped.
- Add a `.env.example` with placeholder-only values.

## Testing And Verification

Backend tests:

```bash
cd backend
python3 -m pytest tests -q
```

Frontend type check:

```bash
cd frontend
npm run lint
```

Frontend production build:

```bash
cd frontend
npm run build
```

Recent local verification:

```text
Backend tests: 24 passed
Frontend lint/type check: passed
Frontend production build: passed
```

## CI

GitHub Actions workflow:

```text
.github/workflows/ci.yml
```

The workflow runs:

- backend dependency install
- backend tests, including Dempster-Shafer and response API security checks
- frontend `npm ci`
- frontend TypeScript check
- frontend production build

The test suite does not require live Anthropic credentials.

## Data And Licensing Notes

- Demo graphs and incident telemetry are synthetic.
- No real customer, government, agency, or company infrastructure is required to run the project.
- No raw CERT, CICIDS, LANL, SWaT, or WADI datasets are committed.
- Evaluation fixtures are small, labeled, benchmark-style samples for reproducible hackathon scoring.
- `backend/data/stix/enterprise-attack-subset.json` is a small MITRE ATT&CK-derived subset. If redistributed publicly, preserve MITRE attribution/license text as required by the ATT&CK STIX data license.

## Design Principles

RAKSHAK follows the rules in `docs/rules.md`:

- Deterministic graph logic decides; the LLM only narrates.
- Evidence stays explainable through labeled source scores.
- IT and OT remain separate except at explicit bridge nodes.
- OT safety constraints are enforced server-side.
- Resilience and degraded operation are first-class outputs, not afterthoughts.

## Documentation

More detail lives in:

- `docs/PRD.md` - product requirements and hackathon success criteria
- `docs/architecture.md` - system architecture and data flow
- `docs/design.md` - UI design system
- `docs/rules.md` - implementation constraints and safety rules
- `docs/phases.md` - phase plan

## Status

RAKSHAK is an MVP/demo implementation, not production CNI software. It is suitable for hackathon judging, research demonstrations, and local experimentation with synthetic IT/OT resilience workflows.
