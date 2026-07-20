'use client';

import React from 'react';
import useSWR from 'swr';
import { API_BASE, fetcher } from '@/lib/api';
import { useDashboard } from '@/lib/store';

interface ResponseDecision {
  node_id: string;
  label: string;
  action: string;
  tier: string;
  reason: string;
  requires_human_approval: boolean;
  status: string;
  is_ot: boolean;
  policy_id: string;
  playbook?: {
    automation_coverage: number;
    autonomous_steps: number;
    total_steps: number;
    steps: Array<{
      id: string;
      connector: string;
      description: string;
      status: string;
    }>;
  };
}

export function StepRespond() {
  const { selectedEntityId } = useDashboard();
  const { data, error, isLoading } = useSWR<{ decisions: ResponseDecision[] }>(
    `${API_BASE}/api/response-decisions`,
    fetcher,
    { refreshInterval: 5000 }
  );
  const { data: selectedDecision, error: selectedError, isLoading: selectedLoading } = useSWR<ResponseDecision>(
    selectedEntityId ? `${API_BASE}/api/entities/${encodeURIComponent(selectedEntityId)}/response-decision` : null,
    (url: string) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } }).then((res) => {
      if (!res.ok) throw new Error(`POST response-decision failed: ${res.status}`);
      return res.json();
    }),
    { refreshInterval: 5000 }
  );

  const filteredDecisions = selectedEntityId && selectedDecision
    ? [{
        ...selectedDecision,
        node_id: selectedEntityId,
        label: selectedEntityId,
        is_ot: selectedEntityId === 'SCADA-HMI-07',
        policy_id: selectedDecision.policy_id || 'power_grid',
      }]
    : (data?.decisions || []);
  const loading = selectedEntityId ? selectedLoading : isLoading;
  const loadError = selectedEntityId ? selectedError : error;

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-3xl flex flex-col gap-6">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <span className="text-sm animate-pulse text-white/50">Loading decisions...</span>
          </div>
        ) : loadError ? (
          <div className="flex items-center justify-center h-full text-[var(--color-accent-fusion)]">
            Error loading response decisions
          </div>
        ) : filteredDecisions.length === 0 ? (
          <div className="flex items-center justify-center h-full text-white/50 italic">
            No active threat responses pending for this entity.
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {filteredDecisions.map((decision, idx) => {
              const isBlockedOT = decision.status === 'Blocked' && decision.is_ot;
              
              let chipBg = 'rgba(255,255,255,0.05)';
              let chipColor = 'var(--color-text-muted)';
              
              if (decision.status === 'Allowed') {
                chipBg = 'rgba(52,211,153,0.1)';
                chipColor = 'var(--color-accent-resilience)';
              } else if (decision.status === 'Needs Approval') {
                chipBg = 'rgba(242,166,90,0.1)';
                chipColor = 'var(--color-warning)';
              } else if (decision.status === 'Blocked') {
                chipBg = 'rgba(226,63,107,0.1)';
                chipColor = 'var(--color-accent-fusion)';
              }

              return (
                <div 
                  key={idx} 
                  className={`glass-panel p-6 flex flex-col gap-4 transition-all ${
                    isBlockedOT ? 'border border-[var(--color-accent-fusion)]/50 shadow-[0_0_30px_rgba(226,63,107,0.15)] scale-105' : 'border border-white/5 opacity-80'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-3">
                        <span className="text-xl font-medium tracking-wide text-white">
                          {decision.label}
                        </span>
                        <span className="text-xs px-2 py-1 bg-white/5 rounded font-mono text-white/50">
                          {decision.node_id}
                        </span>
                      </div>
                      <span className="text-lg mt-2 font-mono text-[var(--color-accent-it)] flex items-center gap-2">
                        <span className="text-white/30">PROPOSED ACTION:</span> {decision.action}
                      </span>
                    </div>
                    
                    <div className="flex flex-col items-end gap-2">
                      <span 
                        className="text-sm px-4 py-2 rounded-md font-mono tracking-wider font-bold" 
                        style={{ background: chipBg, color: chipColor }}
                      >
                        {decision.status.toUpperCase()}
                        {isBlockedOT && ' ⚠️'}
                      </span>
                      <span className="text-xs font-mono text-white/40">
                        TIER: {decision.tier} · POLICY: {decision.policy_id}
                      </span>
                    </div>
                  </div>
                  
                  {/* The reason text - make it prominent, especially for OT blocked */}
                  <div className={`mt-2 p-4 rounded text-sm font-mono border-l-2 ${
                    isBlockedOT 
                      ? 'bg-[var(--color-accent-fusion)]/5 border-[var(--color-accent-fusion)] text-[var(--color-accent-fusion)]' 
                      : 'bg-white/5 border-white/20 text-white/70'
                  }`}>
                    {decision.reason}
                  </div>

                  {decision.playbook && (
                    <div className="mt-2 grid grid-cols-[120px_1fr] gap-4 items-start">
                      <div className="text-center rounded border border-white/10 bg-black/20 p-3">
                        <div className="text-2xl font-mono text-[var(--color-accent-resilience)]">
                          {(decision.playbook.automation_coverage * 100).toFixed(0)}%
                        </div>
                        <div className="text-[0.65rem] font-mono uppercase tracking-wider text-white/40 mt-1">
                          autonomous
                        </div>
                      </div>
                      <div className="flex flex-col gap-2">
                        {decision.playbook.steps.map((step) => (
                          <div key={step.id} className="flex items-center justify-between rounded bg-white/5 px-3 py-2 text-xs font-mono">
                            <span className="text-white/70 truncate">{step.connector}: {step.description}</span>
                            <span className={
                              step.status === 'executed'
                                ? 'text-[var(--color-accent-resilience)]'
                                : step.status === 'blocked'
                                  ? 'text-[var(--color-accent-fusion)]'
                                  : 'text-[var(--color-warning)]'
                            }>
                              {step.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
