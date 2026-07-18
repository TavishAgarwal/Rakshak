/**
 * RAKSHAK — REST API client.
 *
 * Typed fetch wrappers for all backend endpoints.
 */

const IS_SERVER = typeof window === 'undefined';
export const API_BASE = IS_SERVER
  ? (process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000')
  : '';
export const fetcher = async (url: string) => {
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Request failed: ${res.status}`);
  }
  return data;
};

/* ── Types ────────────────────────────────────────────── */

export interface ScoreSource {
  scorer_class: string;
  raw_score: number;
  mass_malicious: number;
  mass_benign: number;
  mass_theta: number;
}

export interface FusionResult {
  belief: number;
  plausibility: number;
  uncertainty: number;
  conflict: number;
  sources: ScoreSource[];
}

export interface MissionCriticality {
  operational_importance: number;
  data_sensitivity: number;
  connectivity_risk: number;
  safety_impact: number;
  recovery_difficulty: number;
  composite_score: number;
  asset_type: string;
}

export interface PhaseEvidence {
  phase: string;
  display_name: string;
  raw_score: number;
  matched_indicators: string[];
  scorer_contributions: Record<string, number>;
  preconditions_satisfied?: string[];
  precondition_blocked?: boolean;
}

export interface CampaignState {
  distribution: Record<string, number>;
  dominant_phase: string;
  dominant_probability: number;
  phase_evidence: PhaseEvidence[];
}

export interface ResponseGate {
  risk_tier: string;
  allowed_actions: string[];
  blocked_actions: string[];
  requires_human_escalation: boolean;
  escalation_reason: string | null;
  rationale: string[];
}

export interface EvidenceEntry {
  source: string;
  raw_score: number;
  label: string;
  contributing_factors?: string[];
}

export interface EntityData {
  node_id: string;
  graph_domain: string;
  mission_criticality: MissionCriticality;
  campaign_state: CampaignState;
  fusion: FusionResult;
  response_gate: ResponseGate;
  evidence_log: EvidenceEntry[];
}

export interface ResilienceData {
  headline_score: number;
  score: number;
  assessment: string;
  breakdown: {
    redundancy_coverage: number;
    degraded_mode_availability: number;
    mean_recovery_time: number;
    service_continuity: number;
  };
}

export interface GraphNode {
  id: string;
  node_type: string;
  graph_domain: string;
  label?: string;
  [key: string]: any;
}

export interface GraphEdge {
  source: string;
  target: string;
  edge_type: string;
}

export interface GraphSnapshot {
  it_graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  ot_graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  meta: {
    it_node_count: number;
    it_edge_count: number;
    ot_node_count: number;
    ot_edge_count: number;
  };
}

export interface AuditEntry {
  decision_id: string;
  timestamp: string;
  entity_id: string;
  evidence_sources: Array<{ source: string; weight: number }>;
  alternatives_considered: string[];
  model_versions: unknown;
  human_approval: { approved_by: string | null; timestamp: string | null };
  action_taken: string;
  previous_hash: string;
  hash: string;
  metadata?: Record<string, any>;
}

export interface AuditVerificationResult {
  valid: boolean;
  invalid_at_index: number | null;
  reason?: string;
  total_verified?: number;
}

/* ── API calls ────────────────────────────────────────── */

export async function fetchGraph(): Promise<GraphSnapshot> {
  const res = await fetch(`${API_BASE}/graph`);
  if (!res.ok) throw new Error(`GET /graph failed: ${res.status}`);
  return res.json();
}

export async function fetchEntity(nodeId: string): Promise<EntityData> {
  const res = await fetch(`${API_BASE}/entity/${encodeURIComponent(nodeId)}`);
  if (!res.ok) throw new Error(`GET /entity/${nodeId} failed: ${res.status}`);
  return res.json();
}

export async function fetchResilience(): Promise<ResilienceData> {
  const res = await fetch(`${API_BASE}/api/resilience-score`);
  if (!res.ok) throw new Error(`GET /api/resilience-score failed: ${res.status}`);
  return res.json();
}

export interface QueryResult {
  node_id: string;
  query: string;
  narration: string;
  model: string;
  tokens_used: number;
  error: string | null;
}

export async function fetchQuery(nodeId: string, query: string): Promise<QueryResult> {
  const res = await fetch(`${API_BASE}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_id: nodeId, query }),
  });
  if (!res.ok) throw new Error(`POST /query failed: ${res.status}`);
  return res.json();
}

/* ── Red Team Mode types ──────────────────────────────── */

export interface RedChoice {
  id: string;
  label: string;
  hint: string;
  is_blocked_action: boolean;
}

export interface RedStageInfo {
  stage: number;
  label: string;
  prompt: string;
  total_stages: number;
}

export interface RedHistoryEntry {
  choice_id: string;
  label: string;
  hint: string;
  stage: number;
  affected_node: string;
  event_type: string;
  mitre_technique: string;
  mitre_tactic: string;
}

export interface RedAppliedEvent {
  event_type: string;
  mitre_technique: string;
  mitre_tactic: string;
  description: string;
  affected_node: string;
}

export interface RedTeamState {
  active: boolean;
  current_stage: number | null;
  stage_info: RedStageInfo | null;
  choices: RedChoice[];
  history: RedHistoryEntry[];
  finished: boolean;
}

export interface RedTeamChooseResponse {
  choice: RedChoice;
  stage: RedStageInfo;
  applied_event: RedAppliedEvent;
  affected_nodes: string[];
  history: RedHistoryEntry[];
  finished: boolean;
  next_stage: RedStageInfo | null;
  node_state: {
    node_id: string;
    graph_domain: string;
    scores: Record<string, number>;
    fusion: {
      belief: number;
      plausibility: number;
      uncertainty: number;
      conflict: number;
    };
    campaign_state: {
      dominant_phase: string;
      dominant_probability: number;
      distribution: Record<string, number>;
    };
    response_gate: {
      risk_tier: string;
      allowed_actions: string[];
      blocked_actions: string[];
      requires_human_escalation: boolean;
      escalation_reason: string | null;
      rationale: string[];
    };
  };
  updated_state: RedTeamState;
}

/* ── Red Team API calls ───────────────────────────────── */

export async function fetchRedTeamState(): Promise<RedTeamState> {
  const res = await fetch(`${API_BASE}/redteam/state`);
  if (!res.ok) throw new Error(`GET /redteam/state failed: ${res.status}`);
  return res.json();
}

export async function postRedTeamChoose(choiceId: string): Promise<RedTeamChooseResponse> {
  const res = await fetch(`${API_BASE}/redteam/choose`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ choice_id: choiceId }),
  });
  if (!res.ok) throw new Error(`POST /redteam/choose failed: ${res.status}`);
  return res.json();
}

export async function postRedTeamReset(): Promise<RedTeamState> {
  const res = await fetch(`${API_BASE}/redteam/reset`, { method: 'POST' });
  if (!res.ok) throw new Error(`POST /redteam/reset failed: ${res.status}`);
  return res.json();
}

/* ── Simulation API calls ───────────────────────────────── */

export interface SimulationConfig {
  scenario_id: string;
  attack_intensity: number;
  stealth_vector: number;
  target_node_ids: string[];
  payload_summary: string;
}

export async function postSimulationConfigure(config: SimulationConfig) {
  const res = await fetch(`${API_BASE}/simulation/configure`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) throw new Error(`POST /simulation/configure failed: ${res.status}`);
  return res.json();
}

export async function postSimulationDeploy() {
  const res = await fetch(`${API_BASE}/simulation/deploy`, { method: 'POST' });
  if (!res.ok) throw new Error(`POST /simulation/deploy failed: ${res.status}`);
  return res.json();
}
