'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useDashboard } from '@/lib/store';
import {
  fetchRedTeamState,
  API_BASE,
  postRedTeamChoose,
  postRedTeamReset,
  fetchEntity,
  fetchResilience,
  type RedTeamState,
  type RedChoice,
  type RedTeamChooseResponse,
} from '@/lib/api';
import { deriveLinesFromResult, type FeedSource } from '@/components/AgentActivityFeed/AgentActivityFeed';

/* ── Design tokens matching the codebase ──────────────── */
const COLORS = {
  IT: '#5B8DEF',
  OT: '#F2A65A',
  BRIDGE: '#8B5CF6',
  FUSION: '#E23F6B',
  RESILIENCE: '#34D399',
  WARNING: '#FBBF24',
};

/* ── Comparison Ticker Component (task item 8) ────────── */

function ComparisonTicker({ mttd }: { mttd: number | null }) {
  const mttdStr = mttd !== null ? `${mttd.toFixed(1)}h` : '—';

  return (
    <div className="flex items-center gap-3 text-[0.6rem] font-mono px-3 py-1.5 rounded-full"
      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}
    >
      <span className="flex items-center gap-1.5" style={{ color: 'var(--color-text-muted)' }}>
        <span className="w-1.5 h-1.5 rounded-full bg-white/20" />
        Traditional SOC: investigating (Day 14 avg)
      </span>
      <span className="text-white/20">|</span>
      <span className="flex items-center gap-1.5" style={{ color: COLORS.RESILIENCE }}>
        <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: COLORS.RESILIENCE, boxShadow: `0 0 6px ${COLORS.RESILIENCE}` }} />
        RAKSHAK: Detected in {mttdStr}
      </span>
    </div>
  );
}

/* ── Choice Card ──────────────────────────────────────── */

function ChoiceCard({
  choice,
  onChoose,
  disabled,
}: {
  choice: RedChoice;
  onChoose: (id: string) => void;
  disabled: boolean;
}) {
  const isBlocked = choice.is_blocked_action;
  const borderColor = isBlocked ? COLORS.FUSION : COLORS.IT;

  return (
    <button
      onClick={() => onChoose(choice.id)}
      disabled={disabled}
      className="relative flex flex-col items-start text-left w-full p-4 rounded-lg transition-all duration-200 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed hover:scale-[1.02] active:scale-[0.98]"
      style={{
        background: isBlocked
          ? 'rgba(226,63,107,0.08)'
          : 'rgba(91,141,239,0.08)',
        border: `1px solid ${borderColor}33`,
        boxShadow: isBlocked
          ? `0 0 12px ${COLORS.FUSION}15`
          : 'none',
      }}
    >
      {/* Attacker-perspective label */}
      <div className="flex items-center gap-2 mb-1">
        {isBlocked && (
          <span className="text-[0.55rem] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
            style={{
              background: `${COLORS.FUSION}20`,
              color: COLORS.FUSION,
            }}
          >
            ⚠ Blocked
          </span>
        )}
        <span className="text-sm font-bold tracking-tight"
          style={{ color: 'var(--color-text-primary)', fontFamily: 'var(--font-display)' }}
        >
          {choice.label}
        </span>
      </div>

      {/* One-line consequence hint */}
      <span className="text-[0.6rem] leading-snug mt-1"
        style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}
      >
        {choice.hint}
      </span>

      {/* Arrow indicator */}
      <div className="absolute right-3 top-1/2 -translate-y-1/2 text-xs" style={{ color: borderColor }}>
        {isBlocked ? '⛔' : '→'}
      </div>
    </button>
  );
}

/* ── Blocked Action Override Card (task item 7) ───────── */

function BlockedActionCard({
  gate,
  onApprove,
  disabled,
}: {
  gate: { allowed_actions: string[]; blocked_actions: string[]; escalation_reason: string | null; rationale: string[] };
  onApprove: (action: string) => void;
  disabled: boolean;
}) {
  const blockReason = gate.escalation_reason || 'OT active disruption is structurally blocked by the safety gate.';
  const allowed = gate.allowed_actions.filter(a => !a.startsWith('ot_')); // OT monitoring
  const fallbackAction = allowed.length > 0 ? allowed[0] : 'increase_monitoring';

  return (
    <div className="w-full p-4 rounded-lg space-y-3"
      style={{
        background: 'rgba(226,63,107,0.06)',
        border: `1px solid ${COLORS.FUSION}33`,
      }}
    >
      {/* Block reason as prominent inline card */}
      <div className="flex items-start gap-2 p-2.5 rounded"
        style={{
          background: `${COLORS.FUSION}12`,
          border: `1px solid ${COLORS.FUSION}25`,
        }}
      >
        <span className="text-sm mt-0.5">⛔</span>
        <div>
          <div className="text-xs font-bold uppercase tracking-wider mb-0.5"
            style={{ color: COLORS.FUSION, fontFamily: 'var(--font-mono)' }}
          >
            Action Blocked by Safety Gate
          </div>
          <div className="text-[0.6rem] leading-snug"
            style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}
          >
            {blockReason}
          </div>
        </div>
      </div>

      {/* Reveal the actual allowed alternative action from response gate */}
      <div className="flex items-center justify-between gap-2 p-2.5 rounded"
        style={{
          background: 'rgba(52,211,153,0.08)',
          border: `1px solid ${COLORS.RESILIENCE}25`,
        }}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm">✅</span>
          <div>
            <div className="text-xs font-medium"
              style={{ color: COLORS.RESILIENCE, fontFamily: 'var(--font-mono)' }}
            >
              Allowed alternative: {fallbackAction}
            </div>
            <div className="text-[0.55rem] mt-0.5"
              style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}
            >
              The safety gate permits this action instead
            </div>
          </div>
        </div>

        <button
          onClick={() => onApprove(fallbackAction)}
          disabled={disabled}
          className="px-3 py-1.5 rounded text-[0.6rem] font-mono font-medium tracking-wider whitespace-nowrap transition-all cursor-pointer disabled:opacity-40"
          style={{
            background: COLORS.RESILIENCE,
            color: '#000',
            boxShadow: `0 0 12px ${COLORS.RESILIENCE}40`,
          }}
        >
          Approve
        </button>
      </div>
    </div>
  );
}

/* ── Node State Snapshot (reuses existing components' shapes) ─ */

function NodeStateCard({ nodeState }: { nodeState: RedTeamChooseResponse['node_state'] }) {
  const bel = (nodeState.fusion.belief * 100).toFixed(1);
  const unc = (nodeState.fusion.uncertainty * 100).toFixed(1);

  return (
    <div className="space-y-2 p-3 rounded-lg"
      style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <div className="text-[0.55rem] font-mono uppercase tracking-wider mb-2"
        style={{ color: 'var(--color-text-muted)' }}
      >
        {nodeState.node_id} — Score Deltas
      </div>

      {/* Fusion */}
      <div className="flex items-center justify-between">
        <span className="text-[0.6rem] font-mono" style={{ color: 'var(--color-text-muted)' }}>Belief</span>
        <span className="text-xs font-mono font-bold" style={{ color: COLORS.FUSION }}>{bel}%</span>
      </div>
      <div className="w-full h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.05)' }}>
        <div className="h-full rounded-full transition-all duration-500"
          style={{ width: `${nodeState.fusion.belief * 100}%`, background: COLORS.FUSION, boxShadow: `0 0 8px ${COLORS.FUSION}40` }}
        />
      </div>

      {/* Campaign dominant phase */}
      <div className="flex items-center gap-2 mt-2">
        <span className="text-[0.55rem] font-mono uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Phase:</span>
        <span className="text-[0.6rem] font-mono px-1.5 py-0.5 rounded"
          style={{ background: `${COLORS.IT}15`, color: COLORS.IT }}
        >
          {nodeState.campaign_state.dominant_phase}
        </span>
        <span className="text-[0.55rem] font-mono" style={{ color: 'var(--color-text-muted)' }}>
          {((nodeState.campaign_state.dominant_probability) * 100).toFixed(0)}%
        </span>
      </div>

      {/* Gate */}
      <div className="flex items-center gap-2 mt-1">
        <span className="text-[0.55rem] font-mono uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Risk:</span>
        <span className="text-[0.5rem] font-mono px-1.5 py-0.5 rounded"
          style={{
            background: nodeState.response_gate.risk_tier === 'critical' ? `${COLORS.FUSION}20` : `${COLORS.WARNING}20`,
            color: nodeState.response_gate.risk_tier === 'critical' ? COLORS.FUSION : COLORS.WARNING,
          }}
        >
          {nodeState.response_gate.risk_tier.toUpperCase()}
        </span>
      </div>
    </div>
  );
}

/* ── Main RedTeamMode Component ───────────────────────── */

interface RedTeamModeProps {
  onClose: () => void;
}

export function RedTeamMode({ onClose }: RedTeamModeProps) {
  const {
    setSelectedEntityId,
    setSignalsDrawerOpen,
    setInspectorDrawerOpen,
    setLatestNarration,
    addFeedLines,
    clearFeed,
  } = useDashboard();

  const [state, setState] = useState<RedTeamState | null>(null);
  const [loading, setLoading] = useState(false);
  const [choosing, setChoosing] = useState(false);
  const [lastResult, setLastResult] = useState<RedTeamChooseResponse | null>(null);
  const [showBlockedCard, setShowBlockedCard] = useState(false);
  const [mttd, setMttd] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load initial state and MTTD on mount
  useEffect(() => {
    loadState();
    loadMttd();
  }, []);

  const loadState = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await fetchRedTeamState();
      setState(s);
      if (!s.active && s.current_stage === 0) {
        // Auto-start session if not active
        await postRedTeamReset();
        const refreshed = await fetchRedTeamState();
        setState(refreshed);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load state');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadMttd = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/evaluation/summary`);
      const data = await res.json();
      const mttdVal = data?.mttd_mttr?.rakshak_mttd_hours;
      if (typeof mttdVal === 'number') setMttd(mttdVal);
    } catch {
      // non-critical
    }
  }, []);

  const handleChoose = useCallback(async (choiceId: string) => {
    setChoosing(true);
    setShowBlockedCard(false);
    setLastResult(null);
    setError(null);
    try {
      const result = await postRedTeamChoose(choiceId);
      setLastResult(result);

      // Update state
      setState(result.updated_state);

      // Set narration from applied event
      setLatestNarration(result.applied_event.description);

      // Select the affected node in the graph
      if (result.affected_nodes.length > 0) {
        setSelectedEntityId(result.affected_nodes[0]);
      }

      // Open the signals panel to show real returned data
      setSignalsDrawerOpen(true);
      setInspectorDrawerOpen(true);

      // If this is the blocked action choice, show the override card
      if (result.choice.is_blocked_action) {
        setShowBlockedCard(true);
      }

      // ── Feed the Agent Activity Feed with real data ──
      if (result.node_state) {
        const ns = result.node_state;
        const feedSource: FeedSource = {
          scores: ns.scores,
          fusion: ns.fusion,
          campaign: ns.campaign_state,
          gate: ns.response_gate,
          label: ns.node_id,
        };
        const lines = deriveLinesFromResult(feedSource);
        if (lines.length > 0) {
          addFeedLines(lines);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to make choice');
    } finally {
      setChoosing(false);
    }
  }, [setSelectedEntityId, setSignalsDrawerOpen, setInspectorDrawerOpen, setLatestNarration, addFeedLines]);

  const handleApproveAlternative = useCallback(async (action: string) => {
    // Approving calls the existing execute-action flow
    setChoosing(true);
    try {
      if (!lastResult) return;
      const nodeId = lastResult.affected_nodes[0];
      const res = await fetch(`${API_BASE}/api/entities/${encodeURIComponent(nodeId)}/response-decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      if (!res.ok) throw new Error(`Action execution failed: ${res.status}`);
      setLatestNarration(`Approved alternative action: ${action} on ${nodeId}`);
      setShowBlockedCard(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setChoosing(false);
    }
  }, [lastResult, setLatestNarration]);

  const handleReset = useCallback(async () => {
    setLoading(true);
    setError(null);
    setLastResult(null);
    setShowBlockedCard(false);
    try {
      const s = await postRedTeamReset();
      setState(s);
      setLatestNarration('Red team session reset — calm starting state.');
      setSelectedEntityId(null);
      setSignalsDrawerOpen(false);
      setInspectorDrawerOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed');
    } finally {
      setLoading(false);
    }
  }, [setSelectedEntityId, setSignalsDrawerOpen, setInspectorDrawerOpen, setLatestNarration]);

  // ── Render ────────────────────────────────────────────

  if (loading && !state) {
    return (
      <div className="flex items-center justify-center h-full">
        <span className="text-sm animate-pulse" style={{ color: 'var(--color-text-muted)' }}>Loading red team demo...</span>
      </div>
    );
  }

  const isFinished = state?.finished ?? false;
  const currentStage = state?.current_stage ?? 0;
  const choices = state?.choices ?? [];
  const stageInfo = state?.stage_info;
  const history = state?.history ?? [];

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Error bar */}
      {error && (
        <div className="px-3 py-1.5 mb-2 rounded text-[0.6rem] font-mono"
          style={{
            background: `${COLORS.FUSION}15`,
            border: `1px solid ${COLORS.FUSION}30`,
            color: COLORS.FUSION,
          }}
        >
          ⚠ {error}
        </div>
      )}

      {/* Comparison ticker (task item 8) */}
      <div className="mb-3">
        <ComparisonTicker mttd={mttd} />
      </div>

      {/* Header area */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="section-label text-xs">Red Team Mode</div>
          <div className="text-[0.55rem] font-mono mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            Judge-interactive branching demo — each choice applies a real event through the pipeline
          </div>
        </div>

        <button
          onClick={handleReset}
          disabled={loading}
          className="px-3 py-1.5 rounded text-[0.6rem] font-mono border border-white/10 hover:bg-white/5 disabled:opacity-30 transition-all cursor-pointer"
          style={{ color: 'var(--color-text-muted)' }}
        >
          ↺ Reset
        </button>
      </div>

      <div className="flex-1 overflow-y-auto pr-1 space-y-4">

        {/* Stage prompt */}
        {stageInfo && !isFinished && (
          <div className="p-3 rounded-lg"
            style={{ background: 'rgba(91,141,239,0.06)', border: `1px solid ${COLORS.IT}22` }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[0.55rem] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded"
                style={{ background: `${COLORS.IT}15`, color: COLORS.IT }}
              >
                Stage {stageInfo.stage + 1} / {stageInfo.total_stages}: {stageInfo.label}
              </span>
            </div>
            <div className="text-sm font-medium mt-1" style={{ color: 'var(--color-text-primary)' }}>
              {stageInfo.prompt}
            </div>
          </div>
        )}

        {/* Finished state */}
        {isFinished && (
          <div className="p-4 rounded-lg text-center space-y-2"
            style={{ background: 'rgba(52,211,153,0.06)', border: `1px solid ${COLORS.RESILIENCE}22` }}
          >
            <span className="text-2xl">🎯</span>
            <div className="text-sm font-bold" style={{ color: COLORS.RESILIENCE }}>
              Campaign Complete
            </div>
            <div className="text-[0.6rem] font-mono" style={{ color: 'var(--color-text-muted)' }}>
              All stages completed. The full kill chain reached the IT/OT bridge.
              Check the audit trail for detailed logs of every choice.
            </div>
          </div>
        )}

        {/* Choice cards (task items 5, 7) */}
        {!isFinished && choices.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {choices.map((choice) => (
              <ChoiceCard
                key={choice.id}
                choice={choice}
                onChoose={handleChoose}
                disabled={choosing}
              />
            ))}
          </div>
        )}

        {/* Blocked action override card (task item 7) */}
        {showBlockedCard && lastResult?.node_state?.response_gate && (
          <BlockedActionCard
            gate={lastResult.node_state.response_gate}
            onApprove={handleApproveAlternative}
            disabled={choosing}
          />
        )}

        {/* Node state snapshot — shows updated scores from real returned data */}
        {lastResult?.node_state && (
          <NodeStateCard nodeState={lastResult.node_state} />
        )}

        {/* Choice history */}
        {history.length > 0 && (
          <div className="p-3 rounded-lg"
            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}
          >
            <div className="text-[0.55rem] font-mono uppercase tracking-wider mb-2"
              style={{ color: 'var(--color-text-muted)' }}
            >
              Decision History
            </div>
            <div className="space-y-1.5">
              {history.map((entry, idx) => (
                <div key={idx} className="flex items-center gap-2 text-[0.6rem] font-mono"
                  style={{ color: 'var(--color-text-muted)' }}
                >
                  <span className="w-4 h-4 rounded-full flex items-center justify-center text-[0.45rem] font-bold"
                    style={{ background: `${COLORS.IT}20`, color: COLORS.IT }}
                  >
                    {idx + 1}
                  </span>
                  <span className="font-medium" style={{ color: 'var(--color-text-primary)' }}>{entry.label}</span>
                  <span className="text-white/30">→</span>
                  <span>{entry.affected_node}</span>
                  <span className="text-white/20">·</span>
                  <span className="italic">{entry.mitre_tactic}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
