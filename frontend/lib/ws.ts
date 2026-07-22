/**
 * RAKSHAK — WebSocket client for /stream endpoint.
 *
 * Connects to the backend WS /stream and dispatches typed events.
 */

const IS_SERVER = typeof window === 'undefined';
const WS_BASE = IS_SERVER ? (process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000') : `ws://${window.location.host}`;

/* ── Stream message types ─────────────────────────────── */

export interface StreamNodeUpdate {
  node_id: string;
  graph_domain: string;
  run_id?: string;
  scores: Record<string, number>;
  fusion: {
    belief: number;
    plausibility: number;
    uncertainty: number;
    conflict: number;
  };
  criticality: {
    composite_score: number;
    safety_impact: number;
    asset_type: string;
  };
  campaign: {
    dominant_phase: string;
    dominant_probability: number;
  };
  gate: {
    risk_tier: string;
    requires_human_escalation: boolean;
    blocked_actions: string[];
  };
}

export interface StreamEvent {
  event_index: number;
  total_events: number;
  source_node: string;
  target_node: string;
  event_type: string;
  mitre_tactic: string;
  mitre_technique: string;
  description: string;
  graph_domain: string;
  run_id?: string;
  affected_nodes: StreamNodeUpdate[];
  resilience_update?: {
    before: { score: number; assessment: string; breakdown: Record<string, number> };
    after: { score: number; assessment: string; breakdown: Record<string, number> };
  } | null;
}

export interface StreamResilienceUpdate {
  score: number;
  headline_score?: number;
  assessment: string;
  breakdown: {
    redundancy_coverage: number;
    degraded_mode_availability: number;
    mean_recovery_time: number;
    service_continuity: number;
  };
  components?: {
    redundancy_coverage: number;
    degraded_mode_availability: number;
    mean_recovery_time: number;
    service_continuity: number;
  };
}

export interface StreamStartData {
  total_events: number;
  timeline_duration_s: number;
  speed_factor: number;
  estimated_wall_time_s: number;
  initial_resilience: {
    score: number;
    assessment: string;
  };
}

export interface StreamEndData {
  events_delivered: number;
  final_resilience: StreamResilienceUpdate;
}

export type StreamMessage =
  | { type: 'stream_start'; timestamp: number; wall_clock: string; data: StreamStartData }
  | { type: 'event'; timestamp: number; wall_clock: string; data: StreamEvent }
  | { type: 'resilience_update'; timestamp: number; wall_clock: string; data: StreamResilienceUpdate }
  | { type: 'stream_end'; timestamp: number; wall_clock: string; data: StreamEndData }
  | { type: 'error'; wall_clock: string; data: { message: string } };

/* ── Callbacks ────────────────────────────────────────── */

export interface StreamCallbacks {
  onStart?: (data: StreamStartData) => void;
  onEvent?: (data: StreamEvent, timestamp: number) => void;
  onResilience?: (data: StreamResilienceUpdate, timestamp: number) => void;
  onEnd?: (data: StreamEndData) => void;
  onError?: (error: string) => void;
  onClose?: () => void;
}

/* ── Connect ──────────────────────────────────────────── */

export function connectStream(
  speed: number = 1.0,
  callbacks: StreamCallbacks,
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/stream?speed=${speed}`);

  ws.onmessage = (event) => {
    const msg: StreamMessage = JSON.parse(event.data);
    switch (msg.type) {
      case 'stream_start':
        callbacks.onStart?.(msg.data);
        break;
      case 'event':
        callbacks.onEvent?.(msg.data, msg.timestamp);
        break;
      case 'resilience_update':
        callbacks.onResilience?.(msg.data, msg.timestamp);
        break;
      case 'stream_end':
        callbacks.onEnd?.(msg.data);
        break;
      case 'error':
        callbacks.onError?.(msg.data.message);
        break;
    }
  };

  ws.onclose = () => callbacks.onClose?.();
  ws.onerror = () => callbacks.onError?.('WebSocket connection failed');

  return ws;
}
