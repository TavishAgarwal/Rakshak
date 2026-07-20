'use client';

import React from 'react';
import useSWR from 'swr';
import { API_BASE, fetcher } from '@/lib/api';

interface EvaluationSummary {
  anomaly_detection: {
    recall_detection_rate: number;
    false_positive_rate: number;
    precision: number;
    f1: number;
    sample_count: number;
    methodology: string;
    per_dataset: Record<string, { sample_count: number; recall_detection_rate: number; false_positive_rate: number }>;
  };
  mitre_attack_attribution: {
    technique_level_accuracy: number;
    sample_count: number;
    prediction_method: string;
  };
  incident_response_automation: {
    automation_coverage: number;
    autonomously_executable_steps: number;
    sample_count: number;
  };
  mttd_mttr: {
    baseline_soc_mttd_hours: number;
    rakshak_mttd_hours: number;
    baseline_soc_mttr_hours: number;
    rakshak_mttr_hours: number;
  };
  auditability: {
    valid: boolean;
    total_verified?: number;
  };
  benchmark_manifest: {
    datasets: Array<{ family: string; row_count: number; source_name: string }>;
  };
}

interface AdvisoryPayload {
  advisories: Array<{
    id: string;
    title: string;
    sector: string;
  }>;
  scenarios: Array<{
    id: string;
    name: string;
    business_impact: string;
  }>;
}

function pct(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

export function StepEvidence() {
  const { data: evaluation, error: evalError } = useSWR<EvaluationSummary>(
    `${API_BASE}/api/evaluation/summary`,
    fetcher,
    { refreshInterval: 10000 }
  );
  const { data: intel } = useSWR<AdvisoryPayload>(
    `${API_BASE}/api/threat-intel/advisories`,
    fetcher
  );

  if (evalError) {
    return <div className="h-full grid place-items-center text-[var(--color-accent-fusion)] font-mono">Failed to load judge evidence.</div>;
  }

  if (!evaluation) {
    return <div className="h-full grid place-items-center text-white/50 font-mono animate-pulse">Loading PS7 evidence...</div>;
  }

  const cards = [
    ['Detection rate', pct(evaluation.anomaly_detection.recall_detection_rate), `${evaluation.anomaly_detection.sample_count} benchmark test rows`],
    ['False positives', pct(evaluation.anomaly_detection.false_positive_rate), `Precision ${pct(evaluation.anomaly_detection.precision)}`],
    ['ATT&CK accuracy', pct(evaluation.mitre_attack_attribution.technique_level_accuracy), `${evaluation.mitre_attack_attribution.sample_count} computed technique cases`],
    ['Automation coverage', pct(evaluation.incident_response_automation.automation_coverage), `${evaluation.incident_response_automation.autonomously_executable_steps}/${evaluation.incident_response_automation.sample_count} steps`],
    ['MTTD', `${evaluation.mttd_mttr.rakshak_mttd_hours}h`, `Baseline ${evaluation.mttd_mttr.baseline_soc_mttd_hours}h`],
    ['MTTR', `${evaluation.mttd_mttr.rakshak_mttr_hours}h`, `Baseline ${evaluation.mttd_mttr.baseline_soc_mttr_hours}h`],
  ];
  const perDataset = Object.entries(evaluation.anomaly_detection.per_dataset);

  return (
    <div className="w-full h-full p-4">
      <div className="glass-panel h-full max-w-6xl mx-auto p-6 overflow-hidden flex flex-col gap-5">
        <div className="flex items-center justify-between border-b border-white/10 pb-4">
          <div>
            <h2 className="text-xl font-display tracking-widest text-white">PS7 JUDGE EVIDENCE PACK</h2>
            <p className="text-xs font-mono text-white/50 mt-1">Metrics are computed from benchmark subsets, deterministic ATT&CK mapping, local SOAR state, and live audit verification.</p>
          </div>
          <div className={`px-3 py-2 rounded font-mono text-xs border ${evaluation.auditability.valid ? 'text-[var(--color-accent-resilience)] border-[var(--color-accent-resilience)]/30 bg-[var(--color-accent-resilience)]/10' : 'text-[var(--color-accent-fusion)] border-[var(--color-accent-fusion)]/30 bg-[var(--color-accent-fusion)]/10'}`}>
            AUDIT {evaluation.auditability.valid ? 'VERIFIED' : 'FAILED'} · {evaluation.auditability.total_verified || 0} BLOCKS
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3">
          {cards.map(([label, value, detail]) => (
            <div key={label} className="rounded border border-white/10 bg-black/20 p-4">
              <div className="text-[0.65rem] font-mono uppercase tracking-wider text-white/40">{label}</div>
              <div className="text-2xl font-mono text-white mt-2">{value}</div>
              <div className="text-xs text-white/50 mt-1">{detail}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-4 min-h-0">
          <div className="rounded border border-white/10 bg-white/5 p-4 overflow-y-auto">
            <div className="text-xs font-mono uppercase tracking-wider text-white/40 mb-3">Benchmark Coverage</div>
            <div className="grid grid-cols-2 gap-2">
              {evaluation.benchmark_manifest.datasets.map((dataset) => (
                <div key={dataset.family} className="rounded bg-black/20 p-3">
                  <div className="font-mono text-sm text-white">{dataset.family}</div>
                  <div className="text-xs text-white/50 mt-1">{dataset.row_count} rows · {dataset.source_name}</div>
                  <div className="text-xs text-[var(--color-accent-resilience)] mt-1">
                    {perDataset.find(([family]) => family === dataset.family)?.[1].sample_count || 0} tested
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="rounded border border-white/10 bg-white/5 p-4 overflow-y-auto">
            <div className="text-xs font-mono uppercase tracking-wider text-white/40 mb-3">CERT-In Advisory Fixtures</div>
            <div className="flex flex-col gap-2">
              {intel?.advisories.map((advisory) => (
                <div key={advisory.id} className="flex items-center justify-between rounded bg-black/20 p-3 gap-4">
                  <span className="text-sm text-white/80 truncate">{advisory.title}</span>
                  <span className="text-[0.65rem] font-mono uppercase text-[var(--color-accent-it)]">{advisory.sector}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded border border-white/10 bg-black/20 p-3 text-xs text-white/50 font-mono">
          ATT&CK: {evaluation.mitre_attack_attribution.prediction_method}
        </div>
      </div>
    </div>
  );
}
