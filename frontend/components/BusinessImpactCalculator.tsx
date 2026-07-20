'use client';

import React, { useState } from 'react';

export function BusinessImpactCalculator() {
  const [alertsPerDay, setAlertsPerDay] = useState(1500);
  const [fpReductionPct, setFpReductionPct] = useState(45);
  const [minutesPerAlert, setMinutesPerAlert] = useState(15);
  const [mttrReductionHours, setMttrReductionHours] = useState(2.5);
  const [outageCostPerHour, setOutageCostPerHour] = useState(250000);

  // Calculations
  const fpAlertsReducedPerDay = alertsPerDay * (fpReductionPct / 100);
  const hoursSavedPerDay = (fpAlertsReducedPerDay * minutesPerAlert) / 60;
  const hoursSavedPerYear = hoursSavedPerDay * 365;
  const avoidedOutageExposure = mttrReductionHours * outageCostPerHour;

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
          <label className="text-[10px] text-white/50 font-mono">Outage Cost / Hr ($)</label>
          <input type="number" value={outageCostPerHour} onChange={(e) => setOutageCostPerHour(Number(e.target.value))} className="bg-white/5 border border-white/10 rounded px-2 py-1 text-sm text-white font-mono outline-none focus:border-white/30" />
        </div>
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
          <span className="text-xs text-white/70 font-mono">Deployment shape:</span>
          <span className="text-xs text-[var(--color-accent-fusion)] font-mono">Small CNI SOC (Level 2)</span>
        </div>
      </div>
    </div>
  );
}
