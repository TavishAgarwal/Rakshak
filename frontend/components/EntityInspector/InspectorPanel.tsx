'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import { useDashboard } from '@/lib/store';
import { InfoTooltip } from '@/components/ui/InfoTooltip';
import { API_BASE, fetcher } from '@/lib/api';

/* ── Helpers ──────────────────────────────────────────── */

function getTierColor(tier: string): string {
  switch (tier) {
    case 'critical': return 'var(--color-accent-fusion)';
    case 'high': return 'var(--color-accent-ot)';
    case 'medium': return 'var(--color-warning)';
    default: return 'var(--color-accent-resilience)';
  }
}

function ProgressBar({ value, color, max = 1 }: { value: number; color: string; max?: number }) {
  return (
    <div className="w-full h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
      <div
        className="h-full rounded-full transition-all duration-300"
        style={{ width: `${(value / max) * 100}%`, background: color, boxShadow: `0 0 6px ${color}40` }}
      />
    </div>
  );
}

/* ── Section wrapper ──────────────────────────────────── */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-3">
      <div className="text-[0.6rem] font-medium tracking-widest uppercase mb-2"
        style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
        {title}
      </div>
      <div className="glass-panel-sm p-3">
        {children}
      </div>
    </div>
  );
}

/* ── Toast state ──────────────────────────────────────── */

/* ── Main panel ───────────────────────────────────────── */
export function InspectorPanel() {
  const { selectedEntityId, entityData, entityLoading } = useDashboard();
  const [toast, setToast] = useState<string | null>(null);

  const { data: campaignData } = useSWR(
    selectedEntityId ? `${API_BASE}/api/entities/${encodeURIComponent(selectedEntityId)}/campaign-state` : null,
    fetcher
  );

  const { data: evidenceLogData } = useSWR(
    selectedEntityId ? `${API_BASE}/api/entities/${encodeURIComponent(selectedEntityId)}/evidence-log` : null,
    fetcher
  );

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 4000);
  };

  // Empty state — no entity selected
  if (!selectedEntityId) {
    return (
      <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
        <div className="section-label mb-3">Entity Inspector</div>
        <div className="flex-1 flex flex-col items-center justify-center">
          <div className="mb-3" style={{ opacity: 0.3 }}>
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-muted)" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4l3 3" />
            </svg>
          </div>
          <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
            Select a node to inspect
          </span>
          <span className="text-[0.6rem] mt-1" style={{ color: 'var(--color-text-muted)', opacity: 0.6, fontFamily: 'var(--font-mono)' }}>
            Click any node in the Living Graph
          </span>
        </div>
      </div>
    );
  }

  // Loading state
  if (entityLoading || !entityData) {
    return (
      <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
        <div className="section-label mb-3">Entity Inspector</div>
        <div className="flex-1 flex items-center justify-center">
          <span className="text-sm animate-pulse" style={{ color: 'var(--color-text-muted)' }}>
            Loading {selectedEntityId}...
          </span>
        </div>
      </div>
    );
  }

  const { mission_criticality: mc, campaign_state: cs, fusion, response_gate: gate, evidence_log } = entityData;

  return (
    <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
      {/* Toast notification */}
      {toast && (
        <div
          className="absolute top-2 left-2 right-2 z-50 px-3 py-2 rounded text-[0.6rem] font-mono animate-in fade-in slide-in-from-top-2 duration-200"
          style={{
            background: 'rgba(226,63,107,0.15)',
            border: '1px solid rgba(226,63,107,0.3)',
            color: 'var(--color-accent-fusion)',
          }}
        >
          ⛔ {toast}
        </div>
      )}

      {/* Header */}
      <div className="section-label mb-1">Entity Inspector</div>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs font-medium" style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>
          {entityData.node_id}
        </span>
        <span className="text-[0.55rem] px-1.5 py-0.5 rounded" style={{
          background: entityData.graph_domain === 'IT' ? 'rgba(91,141,239,0.15)' : 'rgba(242,166,90,0.15)',
          color: entityData.graph_domain === 'IT' ? 'var(--color-accent-it)' : 'var(--color-accent-ot)',
          fontFamily: 'var(--font-mono)',
        }}>
          {entityData.graph_domain}
        </span>
        <span className={`score-badge ${gate.risk_tier === 'critical' ? 'critical' : gate.risk_tier === 'high' ? 'elevated' : 'suspicious'}`}>
          {gate.risk_tier}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto pr-1 space-y-0 relative">
        {/* Mission Criticality Vector */}
        <Section title="Mission Criticality Vector">
          <div className="space-y-2">
            {[
              { label: 'Operational', value: mc.operational_importance },
              { label: 'Data Sensitivity', value: mc.data_sensitivity },
              { label: 'Connectivity', value: mc.connectivity_risk },
              { label: 'Safety Impact', value: mc.safety_impact },
              { label: 'Recovery Diff.', value: mc.recovery_difficulty },
            ].map((dim) => (
              <div key={dim.label} className="flex items-center justify-between gap-2">
                <span className="text-[0.65rem] w-24 flex-shrink-0" style={{ color: 'var(--color-text-muted)' }}>
                  {dim.label}
                </span>
                <div className="flex-1">
                  <ProgressBar
                    value={dim.value}
                    color={dim.value >= 0.7 ? 'var(--color-accent-fusion)' : dim.value >= 0.4 ? 'var(--color-accent-ot)' : 'var(--color-accent-it)'}
                  />
                </div>
                <span className="text-[0.6rem] w-8 text-right" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {(dim.value * 100).toFixed(0)}
                </span>
              </div>
            ))}
            <div className="flex items-center justify-between pt-1" style={{ borderTop: '1px solid var(--color-glass-border)' }}>
              <span className="text-[0.6rem] flex items-center" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                Composite <InfoTooltip label="Composite: The overall mission criticality score combining all factors (operational, data, connectivity, safety, recovery)." />
              </span>
              <span className="text-xs font-bold" style={{ fontFamily: 'var(--font-display)', color: 'var(--color-text-primary)' }}>
                {(mc.composite_score * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </Section>

        {/* Campaign State Distribution */}
        <Section title="Campaign State Distribution">
          <div className="space-y-1.5">
            {!campaignData ? (
              <div className="text-[0.6rem] italic" style={{ color: 'var(--color-text-muted)' }}>Loading distribution...</div>
            ) : Object.entries(campaignData.distribution).filter(([, v]) => (v as number) > 0.01).length === 0 ? (
              <div className="text-[0.6rem] italic" style={{ color: 'var(--color-text-muted)' }}>
                No campaign phase detected. Select a flagged node in the Living Graph to see its probability distribution.
              </div>
            ) : (
              <>
                {Object.entries(campaignData.distribution)
                  .filter(([, v]) => (v as number) > 0.01)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([phase, prob]) => {
                    const isBenign = phase === 'benign';
                    const isDominant = phase === campaignData.dominant_phase;
                    const barColor = isBenign ? 'var(--color-accent-ot)' : (isDominant ? 'var(--color-accent-fusion)' : 'var(--color-accent-it)');
                    return (
                      <div key={phase} className="flex items-center gap-2">
                        <span className="text-[0.6rem] w-24 flex-shrink-0 truncate" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {phase.replace(/_/g, ' ')}
                        </span>
                        <div className="flex-1">
                          <ProgressBar
                            value={prob as number}
                            color={barColor}
                          />
                        </div>
                        <span className="text-[0.55rem] w-8 text-right" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {((prob as number) * 100).toFixed(0)}%
                        </span>
                      </div>
                    );
                  })}
              </>
            )}
          </div>
        </Section>

        {/* Evidence Log */}
        <Section title="Evidence Log">
          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {!evidenceLogData ? (
              <div className="text-[0.6rem] italic" style={{ color: 'var(--color-text-muted)' }}>Loading log...</div>
            ) : evidenceLogData.entries.length === 0 ? (
              <div className="text-[0.6rem] italic" style={{ color: 'var(--color-text-muted)' }}>
                No active evidence. Select a flagged node in the Living Graph to see its evidence trail.
              </div>
            ) : (
              evidenceLogData.entries.map((entry: any, i: number) => {
                const date = new Date(entry.timestamp);
                const timeStr = date.toLocaleTimeString([], { hour12: false });
                
                return (
                  <div key={i} className="flex flex-col mb-2 pb-2" style={{ borderBottom: i === evidenceLogData.entries.length - 1 ? 'none' : '1px solid rgba(255,255,255,0.05)' }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[0.55rem]" style={{ color: 'var(--color-accent-it)', fontFamily: 'var(--font-mono)' }}>
                        [{timeStr}]
                      </span>
                      <span className="text-[0.65rem] font-medium" style={{ color: 'var(--color-text-primary)' }}>
                        {SCORER_NAMES[entry.source] || entry.source}
                      </span>
                    </div>
                    <div className="text-[0.6rem]" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {entry.message}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </Section>

        {/* Response Actions */}
        <Section title="Response Actions">
          <div className="space-y-2">
            {/* Glossary strip for DS Conflict & Risk Tier */}
            <div className="flex flex-wrap gap-1.5 mb-2 pb-2" style={{ borderBottom: '1px solid var(--color-glass-border)' }}>
              <span className="text-[0.5rem] px-1.5 py-0.5 rounded font-mono flex items-center gap-1" style={{
                background: 'rgba(255,255,255,0.04)',
                color: 'var(--color-text-muted)',
              }}>
                Bel <InfoTooltip label="Belief: The mass of evidence supporting that an intrusion is real." />
              </span>
              <span className="text-[0.5rem] px-1.5 py-0.5 rounded font-mono flex items-center gap-1" style={{
                background: 'rgba(255,255,255,0.04)',
                color: 'var(--color-text-muted)',
              }}>
                Pl <InfoTooltip label="Plausibility: The upper bound on belief — accounts for uncertainty in available evidence." />
              </span>
              <span className="text-[0.5rem] px-1.5 py-0.5 rounded font-mono flex items-center gap-1" style={{
                background: 'rgba(255,255,255,0.04)',
                color: 'var(--color-text-muted)',
              }}>
                DS Conflict <InfoTooltip label="Dempster-Shafer Conflict: Measures disagreement between evidence sources. High conflict means sources contradict each other." />
              </span>
              <span className="text-[0.5rem] px-1.5 py-0.5 rounded font-mono flex items-center gap-1" style={{
                background: 'rgba(255,255,255,0.04)',
                color: 'var(--color-text-muted)',
              }}>
                Risk Tier <InfoTooltip label="Risk Tier: The computed action threshold based on confidence and mission criticality." />
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[0.6rem] flex items-center" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                Risk Tier <InfoTooltip label="Risk Tier: The computed action threshold based on confidence and criticality." />
              </span>
              <span className="text-xs font-bold" style={{ color: getTierColor(gate.risk_tier), fontFamily: 'var(--font-display)' }}>
                {gate.risk_tier.toUpperCase()}
              </span>
            </div>
            {gate.requires_human_escalation && (
              <div className="flex items-center gap-1.5 px-2 py-1.5 rounded" style={{ background: 'rgba(226,63,107,0.1)' }}>
                <span className="text-[0.6rem]">⚠️</span>
                <span className="text-[0.55rem]" style={{ color: 'var(--color-accent-fusion)', fontFamily: 'var(--font-mono)' }}>
                  Human Escalation Required
                </span>
              </div>
            )}
            {gate.blocked_actions.length > 0 && (
              <div>
                <span className="text-[0.55rem] uppercase tracking-wider" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Blocked:
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {gate.blocked_actions.map((a) => (
                    <span key={a} className="text-[0.5rem] px-1.5 py-0.5 rounded" style={{
                      background: 'rgba(226,63,107,0.1)',
                      color: 'var(--color-accent-fusion)',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {a}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {gate.blocked_actions.length === 0 && (
              <div className="text-[0.6rem] italic" style={{ color: 'var(--color-text-muted)' }}>
                No response actions currently blocked. Select a flagged node to see containment actions.
              </div>
            )}
            <div>
              <span className="text-[0.55rem] uppercase tracking-wider" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                Allowed ({gate.allowed_actions.length}):
              </span>
              <div className="flex flex-wrap gap-1 mt-1">
                {gate.allowed_actions.slice(0, 6).map((a) => (
                  <span key={a} className="text-[0.5rem] px-1.5 py-0.5 rounded" style={{
                    background: 'rgba(52,211,153,0.1)',
                    color: 'var(--color-accent-resilience)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {a}
                  </span>
                ))}
                {gate.allowed_actions.length > 6 && (
                  <span className="text-[0.5rem] px-1.5 py-0.5" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    +{gate.allowed_actions.length - 6} more
                  </span>
                )}
              </div>
            </div>

            {gate.blocked_actions.length > 0 && (
              <div className="mt-3 pt-3" style={{ borderTop: '1px solid var(--color-glass-border)' }}>
              <button
                onClick={() => showToast('Backend safety gate blocked this active-disruption action')}
                className="w-full px-3 py-2 rounded text-[0.65rem] font-mono tracking-wider text-center cursor-help transition-all"
                style={{
                  background: 'rgba(226,63,107,0.08)',
                  border: '1px solid rgba(226,63,107,0.2)',
                  color: 'var(--color-accent-fusion)',
                  fontFamily: 'var(--font-mono)',
                }}
                title="This action is blocked by safety gate policy"
              >
                Backend safety gate blocked {gate.blocked_actions[0]}
              </button>
              </div>
            )}
          </div>
        </Section>
      </div>
    </div>
  );
}

/* ── Scorer names ─────────────────────────────────────── */
const SCORER_NAMES: Record<string, string> = {
  identity: 'Identity Anomaly',
  credential: 'Credential Risk',
  process: 'Process Deviation',
  network: 'Network Flow',
  dns: 'DNS Tunneling',
  cloud_api: 'Cloud API Abuse',
  ot_physics: 'OT Physics',
};
