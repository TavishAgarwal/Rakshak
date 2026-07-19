'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useDashboard } from '@/lib/store';
import { AuditTrailPanel } from '@/components/AuditTrail/AuditTrailPanel';

interface HeaderProps {
  onToggleSignals?: () => void;
  onToggleInspector?: () => void;
  onToggleRedTeam?: () => void;
  redTeamActive?: boolean;
}

export function Header({ onToggleSignals, onToggleInspector, onToggleRedTeam, redTeamActive }: HeaderProps) {
  const { resilience, streamActive, startStream, stopStream, streamEvents } = useDashboard();
  const [auditOpen, setAuditOpen] = useState(false);

  const headline = resilience?.score ?? 0;
  const headlineDisplay = headline.toFixed(0);
  const prevHeadlineRef = useRef(headline);
  const [animating, setAnimating] = useState(false);

  // Animate when headline changes
  useEffect(() => {
    if (headline !== prevHeadlineRef.current) {
      prevHeadlineRef.current = headline;
      setAnimating(true);
      const timer = setTimeout(() => setAnimating(false), 600);
      return () => clearTimeout(timer);
    }
  }, [headline]);

  const headlineColor = headline >= 60 ? 'var(--color-accent-resilience)' : headline >= 40 ? 'var(--color-warning)' : 'var(--color-accent-fusion)';

  // Derived consequence string from resilience breakdown
  const consequenceString = resilience?.breakdown ? (() => {
    const { mean_recovery_time = 0, degraded_mode_availability = 0 } = resilience.breakdown;
    const recoveryHours = mean_recovery_time.toFixed(1);
    const degradedPct = degraded_mode_availability.toFixed(0);
    return `Mean recovery ${recoveryHours}h · Degraded-mode availability ${degradedPct}%`;
  })() : null;

  return (
    <header className="glass-panel flex flex-wrap sm:flex-nowrap items-center justify-between gap-2 px-3 sm:px-5 py-2.5" style={{ borderRadius: '12px' }}>
      {/* Left: Logo + toggle buttons */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <span className="text-xl">🛡️</span>
        <h1 className="text-lg font-bold tracking-tight" style={{ fontFamily: 'var(--font-display)' }}>
          RAKSHAK
        </h1>
        <span className="hidden md:inline text-[0.6rem] font-medium tracking-widest uppercase px-2 py-0.5 rounded"
          style={{ background: 'rgba(91, 141, 239, 0.12)', color: 'var(--color-accent-it)', fontFamily: 'var(--font-mono)' }}>
          CNI Defense
        </span>

        {/* Signals toggle button */}
        <button
          onClick={onToggleSignals}
          className="px-2 py-1 text-[0.6rem] font-mono border border-white/10 rounded hover:bg-white/5 transition-colors cursor-pointer"
          style={{ color: 'var(--color-text-muted)' }}
          aria-label="Toggle signals panel"
        >
          Signals
        </button>

        {/* Red Team Mode toggle button — separate from Replay/Next Event */}
        {onToggleRedTeam && (
          <button
            onClick={onToggleRedTeam}
            className={`px-2 py-1 text-[0.6rem] font-mono border rounded transition-colors cursor-pointer ${
              redTeamActive ? 'bg-[var(--color-accent-fusion)]/10' : 'hover:bg-white/5'
            }`}
            style={{
              color: redTeamActive ? 'var(--color-accent-fusion)' : 'var(--color-text-muted)',
              borderColor: redTeamActive ? 'rgba(226,63,107,0.3)' : 'rgba(255,255,255,0.1)',
            }}
            aria-label="Toggle red team mode"
          >
            {redTeamActive ? '■ Red Team' : '▶ Red Team'}
          </button>
        )}
      </div>

      {/* Center: Status + Stream control */}
      <div className="flex flex-col items-center gap-0.5 order-3 sm:order-none w-full sm:w-auto">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{
            background: streamActive ? 'var(--color-accent-fusion)' : 'var(--color-accent-resilience)',
            boxShadow: streamActive ? '0 0 8px rgba(226,63,107,0.5)' : '0 0 8px rgba(52,211,153,0.5)',
            animation: streamActive ? 'breathe-fast 1s ease-in-out infinite' : 'none',
          }} />
          <span className="text-[0.65rem] font-medium tracking-widest uppercase"
            style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            {streamActive ? `INCIDENT (${streamEvents.length}/13)` : 'MONITORING'}
          </span>
        </div>

        {/* Stream button */}
        <button
          onClick={() => streamActive ? stopStream() : startStream(5)}
          className="glass-panel-sm px-3 py-0.5 cursor-pointer text-[0.65rem] font-medium tracking-wider uppercase transition-all duration-200"
          style={{
            fontFamily: 'var(--font-mono)',
            color: streamActive ? 'var(--color-accent-fusion)' : 'var(--color-accent-it)',
            background: streamActive ? 'rgba(226,63,107,0.1)' : 'rgba(91,141,239,0.1)',
          }}
        >
          {streamActive ? '■ Stop' : '▶ Replay'}
        </button>
        </div>
      </div>

      {/* Right: Resilience Score (2x enlarged) + derived consequence + Audit button */}
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAuditOpen(true)}
            className="px-2 py-1 text-[0.6rem] font-mono border border-white/10 rounded hover:bg-white/5 transition-colors"
            style={{ color: 'var(--color-text-muted)' }}
          >
            AUDIT
          </button>

          <div className="flex flex-col items-end">
            <div className="flex items-center gap-2">
              <span className="hidden sm:inline text-[0.65rem] uppercase tracking-wider"
                style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                Resilience
              </span>
              <span
                className="text-2xl sm:text-4xl font-bold transition-all duration-300"
                style={{
                  fontFamily: 'var(--font-display)',
                  color: headlineColor,
                  transform: animating ? 'scale(1.15)' : 'scale(1)',
                  textShadow: animating ? `0 0 20px ${headlineColor}` : 'none',
                }}
              >
                {headlineDisplay}
              </span>
              {resilience && (
                <span className={`hidden md:inline score-badge ${resilience.assessment === 'healthy' ? 'normal' : resilience.assessment === 'degraded' ? 'suspicious' : resilience.assessment === 'at_risk' ? 'elevated' : 'critical'}`}>
                  {resilience.assessment}
                </span>
              )}
            </div>
            {consequenceString && (
              <div
                className="hidden lg:block text-[0.55rem] mt-0.5"
                style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', opacity: 0.8 }}
              >
                {consequenceString}
              </div>
            )}
          </div>
        </div>

        {/* Inspector toggle button */}
        <button
          onClick={onToggleInspector}
          className="px-2 py-1 text-[0.6rem] font-mono border border-white/10 rounded hover:bg-white/5 transition-colors cursor-pointer"
          style={{ color: 'var(--color-text-muted)' }}
          aria-label="Toggle inspector panel"
        >
          Inspector
        </button>
      </div>

      {/* Audit Modal */}
      {auditOpen && <AuditTrailPanel onClose={() => setAuditOpen(false)} />}
    </header>
  );
}
