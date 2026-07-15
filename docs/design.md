# RAKSHAK — Design

## 1. Concept
Signature element: **the Living Graph** — a breathing, pulsing node network representing the
Cyber Knowledge Graph. Pulse rate and glow intensity per node map directly to that node's live
uncertainty/anomaly score; IT_OT_BRIDGE nodes pulse in a visually distinct color and cadence so a
judge can spot an IT→OT pivot at a glance without reading a label.

Design direction: dark glassmorphism — translucent frosted panels over a deep near-black canvas,
so the Living Graph reads as if it's glowing behind glass.

## 2. Color Tokens
- `--bg-void`: #0A0E17 (base canvas)
- `--glass-panel`: rgba(18, 24, 38, 0.55) with backdrop-blur, 1px border rgba(255,255,255,0.08)
- `--accent-it`: #5B8DEF (IT graph nodes/signals — electric blue)
- `--accent-ot`: #F2A65A (OT graph nodes/signals — industrial amber)
- `--accent-fusion`: #E23F6B (bridge nodes, high-uncertainty alerts — rose)
- `--accent-resilience`: #34D399 (resilience score, healthy states — emerald)
- `--text-primary`: #E7EBF5
- `--text-muted`: #8993A8

## 3. Typography
- **Display** (headers, Resilience Score number): Space Grotesk — geometric, technical, used with
  restraint (headers + the one big score number only).
- **Body**: Inter — for panel labels, descriptions, inspector text.
- **Utility/data**: JetBrains Mono — entity IDs, timestamps, evidence values, audit log rows.

## 4. Layout
┌──────────────────────────────────────────────────────────────────┐
│ RAKSHAK  [shield glyph]        Resilience Score  78 ▲2.1   [search]│
├───────────────┬──────────────────────────────────┬────────────────┤
│ RESILIENCE     │                                  │ ENTITY         │
│ SIGNALS        │        LIVING GRAPH              │ INSPECTOR      │
│  IT-TGN   m1   │   (breathing node network,       │  Mission       │
│  OT-Phys  m2   │    bridge nodes glow rose)        │  Criticality   │
│  Threat-Intel  │                                  │  Vector        │
│  Graph-Rarity  │  ┌────────────────────────────┐  │  Campaign      │
│  ATT&CK Match  │  │ Ask RAKSHAK about this...  │  │  State Dist.   │
│                │  └────────────────────────────┘  │  Evidence Log  │
├───────────────┴──────────────────────────────────┴────────────────┤
│ RESILIENCE SCORE BREAKDOWN                                         │
│ redundancy | degraded-mode availability | mean recovery | uptime   │
└──────────────────────────────────────────────────────────────────┘

## 5. Component Notes
- **Resilience Signals panel:** each row is its own glass mini-card showing the source name, raw
  score, and a small belief/plausibility/uncertainty bar — never a single merged number here.
- **Living Graph:** dark canvas, no grid lines. Idle nodes breathe slowly (~4s cycle, low opacity
  shift). As uncertainty rises, cycle shortens and glow radius increases. Bridge nodes always
  rendered slightly larger with a rose halo, regardless of current score, so their structural role
  is always legible.
- **AI Query bar:** docked at the bottom of the Living Graph panel, glass pill input, response
  renders as a narration card above the input, not a chat thread — this is a lookup tool, not a
  chatbot.
- **Entity Inspector:** appears only once a node is selected; empty state invites selection
  ("Select a node to inspect it") rather than showing placeholder data.
- **Resilience Score breakdown:** horizontal band, four equal segments, each with a small sparkline
  trend, emerald accent for healthy values, amber/rose as they degrade.

## 6. Motion
- One orchestrated moment: on a confirmed incident, the affected node cluster and its shortest
  path to the nearest IT_OT_BRIDGE briefly highlights in sequence (300ms stagger) before settling
  into its new elevated-pulse state. This is the only "big" animation moment — everything else
  (breathing, hover states) stays subtle.
- Respect `prefers-reduced-motion`: fall back to static glow-intensity by score, no pulsing.

## 7. Responsiveness
- Below 1024px: Signals panel and Inspector collapse into slide-over drawers triggered from the
  header; Living Graph stays full-width and remains the primary view.