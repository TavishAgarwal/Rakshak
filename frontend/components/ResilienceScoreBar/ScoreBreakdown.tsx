'use client';

import React from 'react';
import useSWR from 'swr';
import { useDashboard } from '@/lib/store';
import { InfoTooltip } from '@/components/ui/InfoTooltip';
import { API_BASE, fetcher } from '@/lib/api';

function getColor(value: number): string {
  if (value >= 70) return 'var(--color-accent-resilience)';
  if (value >= 50) return 'var(--color-warning)';
  return 'var(--color-accent-fusion)';
}

function getLabel(value: number): string {
  if (value >= 70) return 'Healthy';
  if (value >= 50) return 'Degraded';
  if (value >= 30) return 'At Risk';
  return 'Critical';
}

function fmtHours(value: number): string {
  if (value < 1) return `${Math.round(value * 60)}m`;
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)}h`;
}

const TOOLTIPS: Record<string, string> = {
  redundancy:
    'Redundancy Coverage: % of critical services with a fallback/degraded-mode path. Higher means fewer single points of failure for essential CNI operations.',
  degraded:
    'Degraded Mode Availability: % of impacted services that CAN run in reduced-capacity mode right now without full outage. Critical for maintaining minimum viable operations during an attack.',
  recovery:
    'Mean Recovery Time: Average time from incident detection to verified containment. Lower is better — fast recovery reduces operational downtime.',
  continuity:
    'Service Continuity: % of critical services that remained operational (not fully down) during recent incidents. Measures real uptime resilience, not just fallback capacity.',
};

export function ScoreBreakdown() {
  const { resilience } = useDashboard();
  const { data: evaluation } = useSWR(
    `${API_BASE}/api/evaluation/summary`,
    fetcher,
    { refreshInterval: 10000 }
  );

  const segments = resilience ? [
    { label: 'Redundancy Coverage', value: resilience.breakdown.redundancy_coverage, bar: resilience.breakdown.redundancy_coverage, unit: '%', key: 'redundancy' },
    { label: 'Degraded Mode', value: resilience.breakdown.degraded_mode_availability, bar: resilience.breakdown.degraded_mode_availability, unit: '%', key: 'degraded' },
    { label: 'Mean Recovery', value: resilience.breakdown.mean_recovery_time, bar: Math.max(0, 100 - resilience.breakdown.mean_recovery_time), unit: 'h', key: 'recovery' },
    { label: 'Service Continuity', value: resilience.breakdown.service_continuity, bar: resilience.breakdown.service_continuity, unit: '%', key: 'continuity' },
  ] : [
    { label: 'Redundancy Coverage', value: 0, bar: 0, unit: '%', key: 'redundancy' },
    { label: 'Degraded Mode', value: 0, bar: 0, unit: '%', key: 'degraded' },
    { label: 'Mean Recovery', value: 0, bar: 0, unit: 'h', key: 'recovery' },
    { label: 'Service Continuity', value: 0, bar: 0, unit: '%', key: 'continuity' },
  ];

  const headline = resilience?.score ?? 0;
  const assessment = resilience?.assessment ?? 'loading';
  const impact = evaluation?.mttd_mttr;

  return (
    <div className="glass-panel p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="section-label">Resilience Score Breakdown</div>
        <div className="flex flex-wrap items-center justify-end gap-2 sm:gap-3">
          {impact && (
            <span className="w-full sm:w-auto text-right text-[0.55rem] font-mono text-white/50">
              MTTD {fmtHours(impact.rakshak_mttd_hours)} vs{' '}
              {fmtHours(impact.baseline_soc_mttd_hours)} · MTTR{' '}
              {fmtHours(impact.rakshak_mttr_hours)} vs{' '}
              {fmtHours(impact.baseline_soc_mttr_hours)}
            </span>
          )}
          <span className="text-[0.55rem]" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            Headline
          </span>
          <span
            className="text-lg font-bold"
            style={{ fontFamily: 'var(--font-display)', color: getColor(headline) }}
          >
            {headline.toFixed(1)}
          </span>
          <span className={`score-badge ${headline >= 70 ? 'normal' : headline >= 50 ? 'elevated' : 'critical'}`} style={{ fontSize: '0.6rem' }}>
            {assessment}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {segments.map((seg) => (
          <div key={seg.key} className="glass-panel-sm p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[0.65rem] flex items-center" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-body)' }}>
                {seg.label} <InfoTooltip label={TOOLTIPS[seg.key]} />
              </span>
            </div>
            <div className="flex items-baseline gap-1.5 mb-2">
              <span
                className="text-xl font-bold"
                style={{ fontFamily: 'var(--font-display)', color: getColor(seg.bar) }}
              >
                {seg.unit === 'h' ? seg.value.toFixed(1) : seg.value.toFixed(0)}
              </span>
              <span className="text-[0.55rem]" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>{seg.unit}</span>
            </div>
            <div className="w-full h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.05)' }}>
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${seg.bar}%`,
                  background: getColor(seg.bar),
                  boxShadow: `0 0 8px ${getColor(seg.bar)}40`,
                }}
              />
            </div>
            <div className="mt-1.5 text-[0.55rem]" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
              {getLabel(seg.bar)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
