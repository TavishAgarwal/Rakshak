'use client';

import React, { useState } from 'react';

export function BusinessImpactCalculator() {
  const [alertsPerDay, setAlertsPerDay] = useState(1500);
  const [fpReductionPct, setFpReductionPct] = useState(45);
  const [minutesPerAlert, setMinutesPerAlert] = useState(15);
  const [mttrReductionHours, setMttrReductionHours] = useState(2.5);
  const [criticalityTier, setCriticalityTier] = useState('High (Tier 1)');
  
  const tierCosts = {
    'Critical (Tier 0)': 1000000,
    'High (Tier 1)': 250000,
    'Medium (Tier 2)': 50000,
    'Low (Tier 3)': 10000,
  };

  // Calculations
  const fpAlertsReducedPerDay = alertsPerDay * (fpReductionPct / 100);
  const hoursSavedPerDay = (fpAlertsReducedPerDay * minutesPerAlert) / 60;
  const hoursSavedPerYear = hoursSavedPerDay * 365;
  
  const outageCostPerHour = tierCosts[criticalityTier as keyof typeof tierCosts];
  const avoidedOutageExposure = mttrReductionHours * outageCostPerHour;

  const [liveLatencyMs, setLiveLatencyMs] = useState<number | null>(null);

  React.useEffect(() => {
    // Ping the real-time SIEM endpoint to measure pipeline latency (MTTD benchmark)
    const interval = setInterval(async () => {
      try {
        const t0 = performance.now();
        const res = await fetch('http://localhost:8000/api/ingest/siem', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            event_id: 'test_ping_' + Math.random().toString(36).substring(7),
            timestamp: new Date().toISOString(),
            source_ip: '10.0.0.5',
            destination_ip: '10.0.0.6',
            action: 'allowed',
            protocol: 'tcp',
            bytes_in: 0,
            bytes_out: 0
          })
        });
        if (res.ok) {
          const data = await res.json();
          // Use server-side latency or client-measured if server doesn't provide it
          setLiveLatencyMs(data.processing_latency_ms || Math.round(performance.now() - t0));
        }
      } catch (e) {
        console.error('Failed to ping ingest endpoint', e);
      }
    }, 5000); // Ping every 5 seconds
    
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="rounded border border-white/10 bg-black/20 p-4 h-full flex flex-col overflow-y-auto">
      <div className="text-xs font-mono uppercase tracking-wider text-[var(--color-accent-it)] mb-3">Scenario Estimates (Business Impact)</div>
      
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-white/50 font-mono">Alerts / Day</label>
          <input type="number" value={alertsPerDay} onChange={(e) => setAlertsPerDay(Number(e.target.value))} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-white/50 font-mono">FP Reduction (%)</label>
          <input type="number" value={fpReductionPct} onChange={(e) => setFpReductionPct(Number(e.target.value))} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-white/50 font-mono">Analyst Mins / Alert</label>
          <input type="number" value={minutesPerAlert} onChange={(e) => setMinutesPerAlert(Number(e.target.value))} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30" />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-white/50 font-mono">MTTR Reduction (hrs)</label>
          <input type="number" value={mttrReductionHours} onChange={(e) => setMttrReductionHours(Number(e.target.value))} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30" />
        </div>
        <div className="flex flex-col gap-1 col-span-2">
          <label className="text-[10px] text-white/50 font-mono">Asset Criticality Tier</label>
          <select value={criticalityTier} onChange={(e) => setCriticalityTier(e.target.value)} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30">
            {Object.keys(tierCosts).map(tier => (
              <option key={tier} value={tier} className="bg-[#10151b]">{tier} (${tierCosts[tier as keyof typeof tierCosts].toLocaleString()}/hr)</option>
            ))}
          </select>
        </div>
      </div>
      
      <div className="mb-4 bg-white/5 rounded p-2 border border-white/10">
         <p className="text-[10px] text-white/50 font-mono mb-1">Cost Formula & Assumptions</p>
         <p className="text-xs text-white/80 font-mono">Exposure = MTTR Reduction × Tier Hourly Cost</p>
         <p className="text-[9px] text-[var(--color-accent-fusion)] font-mono mt-1">*Hourly costs by tier are illustrative assumptions, not sourced from a citable reference.</p>
      </div>

      <div className="mt-auto border-t border-white/10 pt-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/70 font-mono">Analyst-hours recovered/yr:</span>
          <span className="text-lg text-[var(--color-accent-resilience)] font-mono">{hoursSavedPerYear.toLocaleString(undefined, { maximumFractionDigits: 0 })}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/70 font-mono">Avoided outage exposure:</span>
          <span className="text-lg text-red-400 font-mono">${avoidedOutageExposure.toLocaleString()}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/70 font-mono">Live MTTD (Pipeline Latency):</span>
          <span className="text-sm text-green-400 font-mono">
            {liveLatencyMs !== null ? `${liveLatencyMs} ms` : 'Measuring...'}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/70 font-mono">Deployment shape:</span>
          <span className="text-xs text-[var(--color-accent-fusion)] font-mono">Small CNI SOC (Level 2)</span>
        </div>
      </div>
    </div>
  );
}
