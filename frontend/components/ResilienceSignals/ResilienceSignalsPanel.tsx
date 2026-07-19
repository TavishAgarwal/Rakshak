'use client';

import React from 'react';
import useSWR from 'swr';
import { useDashboard } from '@/lib/store';
import { InfoTooltip } from '@/components/ui/InfoTooltip';
import { API_BASE, fetcher } from '@/lib/api';

interface EvidenceSource {
  name: string;
  type: 'IT' | 'OT' | 'THREAT';
  raw_score_100: number | null;
  status?: string;
  detail?: string;
}

interface EvidenceData {
  node_id: string;
  sources: EvidenceSource[];
  fusion: {
    belief: number;
    plausibility: number;
    uncertainty: number;
    conflict: number;
  };
}

function getSourceColor(type: 'IT' | 'OT' | 'THREAT'): string {
  switch (type) {
    case 'IT':
      return 'var(--color-aqua, #00ffff)';
    case 'OT':
      return 'var(--color-amber, #ffb000)';
    case 'THREAT':
      return 'var(--color-violet, #8b5cf6)';
    default:
      return 'var(--color-text-muted)';
  }
}

export function ResilienceSignalsPanel() {
  const { selectedEntityId } = useDashboard();

  const { data, error, isLoading } = useSWR<EvidenceData>(
    selectedEntityId ? `${API_BASE}/api/entities/${encodeURIComponent(selectedEntityId)}/evidence` : null,
    fetcher
  );

  if (!selectedEntityId) {
    return (
      <div className="glass-panel flex flex-col items-center justify-center h-full p-6 text-center">
        <span className="section-label mb-2">Resilience Signals</span>
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
          Select a node on the Living Graph to see its evidence breakdown
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
        <span className="section-label mb-1">Resilience Signals</span>
        <div className="text-[0.55rem] mb-3" style={{ color: 'var(--color-accent-it)', fontFamily: 'var(--font-mono)' }}>
          {selectedEntityId}
        </div>
        <div className="flex-1 flex items-center justify-center text-sm" style={{ color: 'var(--color-text-muted)' }}>
          Loading evidence...
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
        <span className="section-label mb-1">Resilience Signals</span>
        <div className="text-[0.55rem] mb-3 flex-1 flex items-center justify-center text-sm" style={{ color: 'var(--color-danger)', fontFamily: 'var(--font-mono)' }}>
          Failed to load evidence
        </div>
      </div>
    );
  }

  return (
    <div className="glass-panel flex flex-col h-full p-4 overflow-hidden">
      <div className="section-label mb-1">Resilience Signals</div>
      <div className="text-[0.55rem] mb-4" style={{ color: 'var(--color-accent-it)', fontFamily: 'var(--font-mono)' }}>
        {selectedEntityId}
      </div>

      <div className="flex-1 overflow-y-auto space-y-3 pr-1">
        {data.sources.map((src) => {
          const color = getSourceColor(src.type);
          return (
            <div key={src.name} className="flex flex-col gap-1.5 mb-3">
              <div className="flex justify-between items-center text-[0.65rem] font-medium" style={{ fontFamily: 'var(--font-body)' }}>
                <span>{src.name}</span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>
                  {src.raw_score_100 === null ? 'Not yet computed' : `${src.raw_score_100.toFixed(1)}%`}
                </span>
              </div>
              <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${src.raw_score_100 ?? 0}%`,
                    background: color,
                    boxShadow: `0 0 8px ${color}40`,
                  }}
                />
              </div>
              {src.detail && (
                <div className="text-[0.55rem] leading-snug" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {src.detail}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Glossary strip */}
      <div className="flex flex-wrap gap-1.5 mb-2" style={{ borderTop: '1px solid var(--color-glass-border)', paddingTop: '12px', marginTop: '12px' }}>
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
      </div>

      {/* Fusion values */}
      <div className="flex justify-between gap-2">
        <div className="glass-panel-sm flex-1 flex flex-col items-center justify-center p-2 rounded text-center border-none" style={{ background: 'rgba(255,255,255,0.02)' }}>
          <span className="text-[0.55rem] uppercase tracking-wider mb-1 flex items-center gap-1" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            Belief <InfoTooltip label="Belief: The mass of evidence supporting that an intrusion is real." />
          </span>
          <span className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>{data.fusion.belief.toFixed(1)}%</span>
        </div>
        <div className="glass-panel-sm flex-1 flex flex-col items-center justify-center p-2 rounded text-center border-none" style={{ background: 'rgba(255,255,255,0.02)' }}>
          <span className="text-[0.55rem] uppercase tracking-wider mb-1 flex items-center gap-1" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            Plausib. <InfoTooltip label="Plausibility: The upper bound on belief — accounts for uncertainty in available evidence." />
          </span>
          <span className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>{data.fusion.plausibility.toFixed(1)}%</span>
        </div>
        <div className="glass-panel-sm flex-1 flex flex-col items-center justify-center p-2 rounded text-center border-none" style={{ background: 'rgba(255,255,255,0.02)' }}>
          <span className="text-[0.55rem] uppercase tracking-wider mb-1 flex items-center gap-1" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            Uncert. <InfoTooltip label="Uncertainty: The mass of evidence that doesn't support either belief or disbelief — signals missing or ambiguous." />
          </span>
          <span className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>{data.fusion.uncertainty.toFixed(1)}%</span>
        </div>
      </div>
    </div>
  );
}
