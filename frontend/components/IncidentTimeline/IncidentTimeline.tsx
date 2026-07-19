'use client';

import React from 'react';
import { useDashboard } from '@/lib/store';

/* ── Kill-chain phases in order ───────────────────────── */
const KILL_CHAIN_PHASES = [
  { id: 'initial_access', label: 'Initial Access', short: 'Initial' },
  { id: 'credential_access', label: 'Credential Access', short: 'Credential' },
  { id: 'discovery', label: 'Discovery', short: 'Discovery' },
  { id: 'lateral_movement', label: 'Lateral Movement', short: 'Lateral' },
  { id: 'privilege_escalation', label: 'Privilege Escalation', short: 'Priv Esc' },
  { id: 'collection', label: 'Collection', short: 'Collection' },
  { id: 'exfiltration', label: 'Exfiltration/Impact', short: 'Exfil/Impact' },
];

/* ── Map between campaign states and phase IDs ────────── */
const CAMPAIGN_TO_PHASE: Record<string, string> = {
  initial_access: 'initial_access',
  'initial-access': 'initial_access',
  credential_access: 'credential_access',
  'credential-access': 'credential_access',
  discovery: 'discovery',
  lateral_movement: 'lateral_movement',
  'lateral-movement': 'lateral_movement',
  privilege_escalation: 'privilege_escalation',
  'privilege-escalation': 'privilege_escalation',
  collection: 'collection',
  exfiltration: 'exfiltration',
  exfiltration_impact: 'exfiltration',
  'exfiltration-impact': 'exfiltration',
  impact: 'exfiltration',
};

export function IncidentTimeline() {
  const { entityData, nodeUncertainties, graphNodes, selectedEntityId } = useDashboard();

  // Determine current dominant phase from the selected entity's campaign state
  // Fall back to scanning entityData or deriving from stream events
  const dominantPhase = React.useMemo(() => {
    // 1. Try entityData campaign_state
    if (entityData?.campaign_state?.dominant_phase) {
      const raw = entityData.campaign_state.dominant_phase.toLowerCase();
      return CAMPAIGN_TO_PHASE[raw] || raw;
    }

    // 2. Try campaign_state distribution from entityData
    if (entityData?.campaign_state?.distribution) {
      const dist = entityData.campaign_state.distribution;
      const best = Object.entries(dist).sort(([, a], [, b]) => b - a)[0];
      if (best && best[0] !== 'benign') {
        return CAMPAIGN_TO_PHASE[best[0]] || best[0];
      }
    }

    // 3. Determine from highest-uncertainty node — pick most advanced phase
    if (selectedEntityId && entityData) {
      // Already covered above
    }

    return null;
  }, [entityData]);

  const currentIdx = dominantPhase
    ? KILL_CHAIN_PHASES.findIndex((p) => p.id === dominantPhase)
    : -1;

  return (
    <div className="w-full glass-panel-sm px-2 py-1.5">
      <div className="flex items-center justify-between gap-0">
        {KILL_CHAIN_PHASES.map((phase, idx) => {
          const isActive = idx === currentIdx;
          const isPast = idx < currentIdx;
          const isFirst = idx === 0;
          const isLast = idx === KILL_CHAIN_PHASES.length - 1;

          return (
            <React.Fragment key={phase.id}>
              {/* Phase segment */}
              <div className="flex items-center flex-1 min-w-0">
                <div
                  className={`
                    flex-1 flex items-center justify-center gap-1 px-1 py-1 rounded-sm
                    transition-all duration-500 text-[0.55rem] font-medium
                    ${isActive
                      ? 'bg-[var(--color-accent-fusion)]/20 text-[var(--color-accent-fusion)] shadow-[0_0_12px_rgba(226,63,107,0.2)]'
                      : isPast
                        ? 'text-[var(--color-text-muted)]'
                        : 'text-[var(--color-text-muted)]/50'
                    }
                  `}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    borderLeft: isFirst ? 'none' : '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  {isActive && (
                    <span className="w-1 h-1 rounded-full bg-[var(--color-accent-fusion)] animate-pulse" />
                  )}
                  {/* Label — show full on wider screens */}
                  <span className="hidden sm:inline truncate">{phase.label}</span>
                  <span className="sm:hidden truncate">{phase.short}</span>
                </div>
              </div>

              {/* Connector dot between phases */}
              {!isLast && (
                <div
                  className="flex-shrink-0 w-1 h-1 rounded-full mx-0.5"
                  style={{
                    background: isPast || isActive
                      ? 'var(--color-accent-fusion)'
                      : 'rgba(137, 147, 168, 0.2)',
                    opacity: isPast || isActive ? 0.6 : 0.3,
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
