# RAKSHAK — Product Requirements Document

## 1. What We're Building
RAKSHAK is an AI-driven Cyber Resilience Intelligence Platform for Indian Critical National
Infrastructure (CNI), built for ET AI Hackathon 2026 — PS7 (AI-Driven Cyber Resilience for
Critical National Infrastructure).

Core thesis: **resilience, not just detection**. The platform fuses IT and OT signals separately,
scores evidence probabilistically (never a single opaque number), maps attack progression as a
state machine grounded in MITRE ATT&CK, and — critically — treats "can we keep operating in a
degraded state" as the first response instinct before "should we isolate this."

## 2. Target Users
- **Primary (demo persona):** SOC analyst / CISO at a CNI operator (power grid, hospital network,
  government exam board) monitoring a mixed IT/OT estate.
- **Secondary (judge persona):** Hackathon evaluators assessing technical depth, business impact,
  and UX in a 5–7 minute live demo.
- **Tertiary (paper persona):** Reviewers of the accompanying research paper assessing the
  evidence-fusion and resilience-scoring methodology.

## 3. Problem We're Solving (from PS7)
Government/CNI entities detect breaches weeks or months after infiltration because signals from
disparate IT/OT/sensor systems aren't fused into a real-time, evidence-backed risk picture, and
because response tooling ignores operational continuity — it's binary (isolate or don't).

## 4. Core Features (MVP scope for hackathon)

### Must-have
1. **Dual-track behavioral graph view** — IT graph and OT graph, visually distinct, fused only at
   flagged IT_OT_BRIDGE nodes.
2. **Living Graph** (signature visual) — animated, "breathing" node network. Pulse rate/glow
   intensity of each node reflects live uncertainty/anomaly score. Bridge nodes pulse distinctly.
3. **Resilience Signals panel** — real-time evidence sources (IT-TGN score, OT physics score,
   threat-intel match, graph-structural rarity, ATT&CK sequence match) shown as independent,
   labeled scores — never pre-blended.
4. **Evidence Fusion (Dempster-Shafer)** — real DS combination rule implemented server-side,
   output as {belief, plausibility, uncertainty}, not a single float.
5. **Selected-Entity Inspector** — clicking a node shows its Mission Criticality Vector, campaign
   state distribution (e.g. 60% Discovery / 30% Lateral Movement / 10% benign), and evidence log.
6. **AI Query Bar** — natural-language query over the currently flagged cluster; LLM narrates the
   graph-computed result, it never computes the match itself ("LLM narrates, graph decides").
7. **Resilience Score** — headline metric = f(redundancy_coverage, degraded_mode_availability,
   mean_recovery_time, service_continuity_last_N), shown continuously, not just post-incident.
8. **Safety-gated response demo** — one scripted incident showing: containment options gated by
   Mission Criticality + asset type, with OT active disruption hard-blocked.
9. **Audit trail** — every fused score and every automated suggestion logged with contributing
   sources and timestamp; viewable, not just claimed.

### Nice-to-have (only if time remains)
- Recovery Sequencing Agent output (Contained → Recovered → Verified timeline).
- Policy Engine demo (switch "hospital" vs "power grid" policy file, same incident → different
  recommended action).
- Security Investment Optimizer (ranked list of interventions by marginal risk reduction).

### Explicitly out of scope for hackathon build
- Training real ML models (TGN, LSTM autoencoders) on real datasets — use deterministic
  rule/statistical stand-ins that produce believable, internally-consistent scores instead.
- Real SCADA/ICS protocol integration.
- Multi-tenant auth, RBAC, production security hardening.
- Real SOAR integrations (isolate endpoint, revoke credential) — simulate the action + log entry.

## 5. Success Criteria (mapped to official judging weights)
- **Innovation (25%):** Living Graph + DS-fusion + degrade-before-isolate framing is visibly
  distinct from a generic SOC dashboard.
- **Business Impact (25%):** Resilience Score and recovery sequencing must be demoable as a
  decision an executive/CISO could act on, not just a chart.
- **Technical Excellence (20%):** DS combination math and resilience score formula must actually
  execute correctly on sample data, not be hardcoded.
- **Scalability (15%):** Architecture must show clear separation of IT/OT ingestion, evidence
  fusion, and response layers so it reads as extensible, not a monolith.
- **User Experience (15%):** Glassmorphism dashboard must feel calm and legible under a live
  incident, not cluttered or "hacker-movie" themed.