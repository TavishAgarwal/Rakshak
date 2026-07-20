'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';
import { AIQueryBar } from '@/components/AIQueryBar/AIQueryBar';
import { AuditTrailPanel } from '@/components/AuditTrail/AuditTrailPanel';
import { InspectorPanel } from '@/components/EntityInspector/InspectorPanel';
import { ResilienceSignalsPanel } from '@/components/ResilienceSignals/ResilienceSignalsPanel';
import { AgentActivityFeed } from '@/components/AgentActivityFeed/AgentActivityFeed';
import { RedTeamMode } from '@/components/RedTeamMode/RedTeamMode';
import { GraphCanvas } from '@/components/LivingGraph/GraphCanvas';
import { ScoreBreakdown } from '@/components/ResilienceScoreBar/ScoreBreakdown';
import { API_BASE, fetcher, postSimulationConfigure, postSimulationDeploy } from '@/lib/api';
import { useDashboard, type GraphNode } from '@/lib/store';

type View = 'dashboard' | 'simulation' | 'intel' | 'reports';
type UtilityPanel = 'notifications' | 'settings' | 'profile' | 'inspector' | 'signals' | 'feed' | 'redteam' | 'audit' | null;

interface HealthResponse {
  status: string;
  service: string;
}

interface DemoScenario {
  id: string;
  name: string;
  sector: string;
  facility_id: string;
  business_impact: string;
  default_policy: string;
}

interface DemoContext {
  scenario_id: string;
  facility_id: string;
  sector: string;
  policy_id: string;
  scenarios: DemoScenario[];
}

interface Advisory {
  id: string;
  title: string;
  sector: string;
  published: string;
  domains: string[];
  techniques: string[];
  recommended_mitigation: string;
  india_context: string;
}

interface ThreatIntelResponse {
  advisories: Advisory[];
  scenarios: DemoScenario[];
}

const NAV_ITEMS: Array<{ id: View; label: string }> = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'simulation', label: 'Simulations' },
  { id: 'intel', label: 'Threat Intel' },
  { id: 'reports', label: 'Reports' },
];

const FALLBACK_SCENARIOS: DemoScenario[] = [
  {
    id: 'power_grid_ot_pivot',
    name: 'Power-grid IT-to-OT pivot',
    sector: 'power',
    facility_id: 'grid-west-01',
    business_impact: 'Maintain grid operations in degraded mode while blocking unsafe OT actions.',
    default_policy: 'power_grid',
  },
  {
    id: 'aiims_like_hospital',
    name: 'AIIMS-like hospital service disruption',
    sector: 'hospital',
    facility_id: 'hospital-delhi-01',
    business_impact: 'Protect patient-care continuity while containing ransomware precursors.',
    default_policy: 'hospital',
  },
  {
    id: 'cbse_like_exam_board',
    name: 'CBSE-like exam data compromise',
    sector: 'exam_board',
    facility_id: 'exam-cloud-01',
    business_impact: 'Protect exam data confidentiality and integrity during cloud API abuse.',
    default_policy: 'exam_board',
  },
];


function Icon({ name, className = '' }: { name: string; className?: string }) {
  const common = {
    className,
    width: 20,
    height: 20,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };

  switch (name) {
    case 'shield':
      return <svg {...common}><path d="M12 3 5 6v5c0 5 3.4 8.4 7 10 3.6-1.6 7-5 7-10V6l-7-3Z" /><path d="M9.5 12.5 11 14l3.5-4" /></svg>;
    case 'grid':
      return <svg {...common}><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z" /></svg>;
    case 'network':
      return <svg {...common}><circle cx="12" cy="12" r="2.4" /><circle cx="5" cy="6" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="5" cy="18" r="2" /><circle cx="19" cy="18" r="2" /><path d="m7 7.5 3.1 2.7M17 7.5l-3.1 2.7M7 16.5l3.1-2.7M17 16.5l-3.1-2.7" /></svg>;
    case 'bars':
      return <svg {...common}><path d="M5 20V10M12 20V4M19 20v-7" /><path d="M3 20h18" /></svg>;
    case 'search':
      return <svg {...common}><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>;
    case 'bell':
      return <svg {...common}><path d="M6 9a6 6 0 0 1 12 0c0 7 3 6 3 8H3c0-2 3-1 3-8Z" /><path d="M10 21h4" /></svg>;
    case 'settings':
      return <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1-2 3.4-.2-.1a1.8 1.8 0 0 0-2.1.3l-.2.2-3.8-2.2.1-.3a1.8 1.8 0 0 0-.9-1.8h-.2l-3.8 2.2-.2-.2a1.8 1.8 0 0 0-2.1-.3l-.2.1-2-3.4.1-.1a1.8 1.8 0 0 0 .4-2V12a1.8 1.8 0 0 0-.4-2l-.1-.1 2-3.4.2.1a1.8 1.8 0 0 0 2.1-.3l.2-.2 3.8 2.2-.1.3a1.8 1.8 0 0 0 .9 1.8h.2l3.8-2.2.2.2a1.8 1.8 0 0 0 2.1.3l.2-.1 2 3.4-.1.1a1.8 1.8 0 0 0-.4 2Z" /></svg>;
    case 'download':
      return <svg {...common}><path d="M12 3v11" /><path d="m8 10 4 4 4-4" /><path d="M5 19h14" /></svg>;
    case 'filter':
      return <svg {...common}><path d="M4 6h16M7 12h10M10 18h4" /></svg>;
    case 'play':
      return <svg {...common}><path d="M8 5v14l11-7-11-7Z" /></svg>;
    case 'pause':
      return <svg {...common}><path d="M9 5v14M15 5v14" /></svg>;
    case 'refresh':
      return <svg {...common}><path d="M20 12a8 8 0 1 1-2.3-5.7" /><path d="M20 5v7h-7" /></svg>;
    case 'file':
      return <svg {...common}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" /><path d="M14 3v5h5" /><path d="M9 13h6M9 17h4" /></svg>;
    case 'close':
      return <svg {...common}><path d="M6 6l12 12M18 6 6 18" /></svg>;
    default:
      return <svg {...common}><circle cx="12" cy="12" r="8" /></svg>;
  }
}

function toneColor(tone: string) {
  if (tone === 'danger') return 'var(--color-danger)';
  if (tone === 'safe') return 'var(--color-accent-resilience)';
  if (tone === 'violet') return 'var(--color-violet)';
  return 'var(--color-text-muted)';
}

function pct(value?: number | null) {
  return `${Math.round((value ?? 0) * 100)}%`;
}

function rawPct(value?: number | null) {
  return `${Math.round(value ?? 0)}%`;
}

function labelFromId(value: string) {
  return value.replace(/[_-]/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function uniqueNodes(nodes: GraphNode[]) {
  return Array.from(new Map(nodes.map((node) => [node.id, node])).values());
}

function RiskBar({ label, value, tone }: { label: string; value: number; tone: string }) {
  const color = toneColor(tone);
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-3 text-xs font-semibold uppercase tracking-[0.08em]">
        <span className="truncate text-white/70">{label}</span>
        <span style={{ color }}>{rawPct(value)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/10">
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: color, boxShadow: `0 0 16px ${color}55` }} />
      </div>
    </div>
  );
}

export function GuidedFlow() {
  const [activeView, setActiveView] = useState<View>('dashboard');
  const [utilityPanel, setUtilityPanel] = useState<UtilityPanel>(null);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('System active');
  const [intelCriticalOnly, setIntelCriticalOnly] = useState(false);
  const [attackIntensity, setAttackIntensity] = useState(7);
  const [stealthLevel, setStealthLevel] = useState(5);
  const [payloadEditable, setPayloadEditable] = useState(false);
  const [payloadDraft, setPayloadDraft] = useState('INIT THREAD_POOL [8]\nINJECT module_crypto_v4.dll\nBYPASS heuristics_engine.sig\nTARGET .mdf, .ldf, .dcm');
  const [simulationTargets, setSimulationTargets] = useState<string[]>([]);
  const [configSynced, setConfigSynced] = useState(true);
  const statusTimer = useRef<number | null>(null);

  const {
    selectedEntityId,
    setSelectedEntityId,
    entityData,
    entityLoading,
    graphNodes,
    resilience,
    streamActive,
    streamEvents,
    startStream,
    stopStream,
    refreshSelectedEntity,
    refreshResilience,
    feedLines,
  } = useDashboard();

  const { data: health, mutate: refreshHealth } = useSWR<HealthResponse>(`${API_BASE}/health`, fetcher, { refreshInterval: 10000 });
  const { data: demoContext, mutate: refreshDemoContext } = useSWR<DemoContext>(`${API_BASE}/api/demo/context`, fetcher);
  const { data: intel } = useSWR<ThreatIntelResponse>(`${API_BASE}/api/threat-intel/advisories`, fetcher);
  const { data: evaluation } = useSWR<any>(`${API_BASE}/api/evaluation/summary`, fetcher, { refreshInterval: 15000 });

  const allNodes = useMemo(() => uniqueNodes(graphNodes), [graphNodes]);
  const filteredNodes = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return allNodes.slice(0, 8);
    return allNodes.filter((node) => {
      const haystack = `${node.id} ${node.label ?? ''} ${node.node_type} ${node.graph_domain}`.toLowerCase();
      return haystack.includes(query);
    }).slice(0, 8);
  }, [allNodes, search]);

  const scenarios = demoContext?.scenarios?.length ? demoContext.scenarios : (intel?.scenarios?.length ? intel.scenarios : FALLBACK_SCENARIOS);
  const activeScenarioId = demoContext?.scenario_id ?? FALLBACK_SCENARIOS[0].id;
  const activeScenario = scenarios.find((scenario) => scenario.id === activeScenarioId) ?? scenarios[0];
  const advisories = intel?.advisories ?? [];
  const visibleAdvisories = intelCriticalOnly
    ? advisories.filter((item) => item.sector === 'power' || item.domains.includes('OT') || item.domains.includes('IT+OT'))
    : advisories;
  const pushStatus = useCallback((message: string) => {
    setStatus(message);
    if (statusTimer.current) window.clearTimeout(statusTimer.current);
    statusTimer.current = window.setTimeout(() => setStatus('System active'), 4500);
  }, []);

  useEffect(() => {
    if (simulationTargets.length === 0 && allNodes.length > 0) {
      setSimulationTargets(allNodes.slice(0, 3).map((node) => node.id));
    }
  }, [allNodes, simulationTargets.length]);

  useEffect(() => {
    if (selectedEntityId && activeView === 'dashboard') {
      setUtilityPanel('inspector');
    }
  }, [selectedEntityId, activeView]);

  useEffect(() => {
    setConfigSynced(false);
    const timer = setTimeout(() => {
      postSimulationConfigure({
        scenario_id: activeScenarioId,
        attack_intensity: attackIntensity,
        stealth_vector: stealthLevel,
        target_node_ids: simulationTargets,
        payload_summary: payloadDraft,
      }).then(() => {
        setConfigSynced(true);
        pushStatus('Configuration saved & synced');
      }).catch((err) => {
        pushStatus(err instanceof Error ? err.message : 'Sync failed');
      });
    }, 500);
    return () => clearTimeout(timer);
  }, [activeScenarioId, attackIntensity, stealthLevel, simulationTargets, payloadDraft, pushStatus]);

  const refreshAll = useCallback(async () => {
    await Promise.all([
      refreshHealth(),
      refreshDemoContext(),
      refreshResilience(),
      selectedEntityId ? refreshSelectedEntity(selectedEntityId) : Promise.resolve(),
    ]);
    pushStatus('Backend data refreshed');
  }, [pushStatus, refreshDemoContext, refreshHealth, refreshResilience, refreshSelectedEntity, selectedEntityId]);

  const handleDeploy = useCallback(() => {
    if (streamActive) {
      stopStream();
      pushStatus('Sentinel stream paused');
      return;
    }
    startStream(8);
    pushStatus('Sentinel stream deployed');
  }, [pushStatus, startStream, stopStream, streamActive]);

  const handleAdvance = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/demo/advance`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Advance failed');
      const affected = data.affected_entities ?? [];
      if (affected[0]) {
        setSelectedEntityId(affected[0]);
        await refreshSelectedEntity(affected[0]);
      }
      await refreshResilience();
      pushStatus(data.status === 'complete' ? 'Simulation complete' : `Stage ${data.stage} released`);
    } catch (err) {
      pushStatus(err instanceof Error ? err.message : 'Simulation failed');
    }
  }, [pushStatus, refreshResilience, refreshSelectedEntity, setSelectedEntityId]);

  const handleSimDeploy = useCallback(async () => {
    try {
      pushStatus('Deploying simulation...');
      await postSimulationDeploy();
      setActiveView('dashboard');
      pushStatus('Simulation deployed');
      startStream(8);
    } catch (err) {
      pushStatus(err instanceof Error ? err.message : 'Simulation deploy failed');
    }
  }, [pushStatus, startStream]);

  const handleScenarioSelect = useCallback(async (scenarioId: string) => {
    pushStatus(`Switching scenario: ${labelFromId(scenarioId)}`);
    try {
      const res = await fetch(`${API_BASE}/api/demo/context`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Scenario switch failed');
      await refreshDemoContext();
      await refreshResilience();
      pushStatus('Scenario connected to backend');
    } catch (err) {
      pushStatus(err instanceof Error ? err.message : 'Scenario switch failed');
    }
  }, [pushStatus, refreshDemoContext, refreshResilience]);

  const toggleTarget = useCallback((nodeId: string) => {
    setSimulationTargets((current) => current.includes(nodeId)
      ? current.filter((id) => id !== nodeId)
      : [...current, nodeId]);
  }, []);

  const handleSearchKey = useCallback((event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== 'Enter') return;
    const first = filteredNodes[0];
    if (!first) {
      pushStatus('No matching node found');
      return;
    }
    setSelectedEntityId(first.id);
    setActiveView('dashboard');
    pushStatus(`Selected ${first.id}`);
  }, [filteredNodes, pushStatus, setSelectedEntityId]);

  const handleExport = useCallback(() => {
    const report = {
      generated_at: new Date().toISOString(),
      status,
      demo_context: demoContext,
      selected_entity: entityData,
      resilience,
      evaluation,
      advisories,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `rakshak-report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    pushStatus('Report exported');
  }, [advisories, demoContext, entityData, evaluation, pushStatus, resilience, status]);

  const healthOk = health?.status === 'ok';
  const headline = resilience?.score ?? 0;
  const latestEvent = streamEvents.at(-1)?.event;
  const riskTier = entityData?.response_gate?.risk_tier ?? 'monitoring';
  const currentPhase = entityData?.campaign_state?.dominant_phase ?? 'benign';

  return (
    <main className="min-h-screen overflow-x-hidden bg-[var(--color-bg-void)] text-[var(--color-text-primary)]">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(120deg,rgba(190,246,255,0.05),transparent_35%,rgba(139,92,246,0.06)_72%,transparent)]" />
      <div className="relative mx-auto flex min-h-screen w-full max-w-[1720px] flex-col px-4 py-3 sm:px-6 lg:px-8">
        <header className="glass-panel mb-5 flex flex-col gap-4 rounded-[28px] px-5 py-4 shadow-2xl shadow-cyan-950/20 lg:flex-row lg:flex-wrap lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-cyan-100 text-slate-950 shadow-[0_0_24px_rgba(190,246,255,0.2)]">
              <Icon name="shield" className="h-5 w-5" />
            </div>
            <button
              onClick={() => setActiveView('dashboard')}
              className="whitespace-nowrap text-left text-2xl font-bold uppercase tracking-[0.02em] text-cyan-50 sm:text-4xl"
              style={{ fontFamily: 'var(--font-display)' }}
            >
              RAKSHAK
            </button>
          </div>

          <nav className="flex flex-wrap items-center gap-2">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`rounded-full px-4 py-2 text-xs font-bold uppercase tracking-[0.16em] transition ${activeView === item.id ? 'bg-white/10 text-cyan-100' : 'text-white/55 hover:bg-white/5 hover:text-white'}`}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="flex min-w-0 flex-wrap items-center gap-3 lg:justify-end">
            <label className="flex min-w-[220px] flex-1 items-center gap-2 rounded-full border border-white/10 bg-black/25 px-4 py-2 text-sm lg:max-w-[340px]">
              <Icon name="search" className="h-4 w-4 shrink-0 text-white/60" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                onKeyDown={handleSearchKey}
                placeholder="Search intelligence..."
                className="min-w-0 flex-1 bg-transparent text-sm text-white outline-none placeholder:text-white/40"
              />
            </label>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'notifications' ? null : 'notifications')}
              className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 text-white/70 hover:bg-white/10 hover:text-cyan-100"
              aria-label="Open notifications"
              title="Notifications"
            >
              <Icon name="bell" className="h-5 w-5" />
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'settings' ? null : 'settings')}
              className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 text-white/70 hover:bg-white/10 hover:text-cyan-100"
              aria-label="Open settings"
              title="Settings"
            >
              <Icon name="settings" className="h-5 w-5" />
            </button>
            <div className="mx-2 h-6 w-px bg-white/20" />
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'inspector' ? null : 'inspector')}
              className={`flex h-10 px-4 items-center justify-center rounded-full border border-white/10 ${utilityPanel === 'inspector' ? 'bg-cyan-100/20 text-cyan-100' : 'text-white/70 hover:bg-white/10 hover:text-cyan-100'}`}
              title="Inspect Entity"
            >
              <span className="text-xs font-bold tracking-widest uppercase">Inspect</span>
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'signals' ? null : 'signals')}
              className={`flex h-10 px-4 items-center justify-center rounded-full border border-white/10 ${utilityPanel === 'signals' ? 'bg-cyan-100/20 text-cyan-100' : 'text-white/70 hover:bg-white/10 hover:text-cyan-100'}`}
              title="Signals"
            >
              <span className="text-xs font-bold tracking-widest uppercase">Signals</span>
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'feed' ? null : 'feed')}
              className={`flex h-10 px-4 items-center justify-center rounded-full border border-white/10 ${utilityPanel === 'feed' ? 'bg-cyan-100/20 text-cyan-100' : 'text-white/70 hover:bg-white/10 hover:text-cyan-100'}`}
              title="Agent Feed"
            >
              <span className="text-xs font-bold tracking-widest uppercase">Feed</span>
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'redteam' ? null : 'redteam')}
              className={`flex h-10 px-4 items-center justify-center rounded-full border border-white/10 ${utilityPanel === 'redteam' ? 'bg-cyan-100/20 text-cyan-100' : 'text-white/70 hover:bg-white/10 hover:text-cyan-100'}`}
              title="Red Team Mode"
            >
              <span className="text-xs font-bold tracking-widest uppercase">Red Team</span>
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'audit' ? null : 'audit')}
              className={`flex h-10 px-4 items-center justify-center rounded-full border border-white/10 ${utilityPanel === 'audit' ? 'bg-cyan-100/20 text-cyan-100' : 'text-white/70 hover:bg-white/10 hover:text-cyan-100'}`}
              title="Audit"
            >
              <span className="text-xs font-bold tracking-widest uppercase">Audit</span>
            </button>
            <div className="mx-2 h-6 w-px bg-white/20" />
            <button
              onClick={handleDeploy}
              disabled={!configSynced && !streamActive}
              className="flex min-h-10 items-center gap-2 rounded-full bg-cyan-100 px-5 py-2 text-sm font-bold uppercase tracking-[0.14em] text-slate-950 shadow-[0_0_28px_rgba(190,246,255,0.22)] transition hover:bg-white disabled:opacity-50 disabled:cursor-wait"
            >
              <Icon name={streamActive ? 'pause' : 'play'} className="h-4 w-4" />
              <span>{streamActive ? 'Pause Sentinel' : (configSynced ? 'Deploy Sentinel' : 'Saving...')}</span>
            </button>
            <button
              onClick={() => setUtilityPanel(utilityPanel === 'profile' ? null : 'profile')}
              className="flex h-10 w-10 items-center justify-center rounded-full border border-cyan-100/20 bg-cyan-100/10 text-cyan-100"
              aria-label="Open operator panel"
              title="Operator"
            >
              <Icon name="shield" className="h-5 w-5" />
            </button>
          </div>
        </header>

        {utilityPanel && (
          <UtilityPanelCard
            panel={utilityPanel}
            onClose={() => setUtilityPanel(null)}
            onRefresh={refreshAll}
            onReports={() => {
              setActiveView('reports');
              setUtilityPanel(null);
            }}
            healthOk={healthOk}
            streamEvents={streamEvents}
            selectedEntityId={selectedEntityId}
            status={status}
            feedLines={feedLines}
          />
        )}

        <div className="flex-1">
          <section className="min-w-0">
            {activeView === 'dashboard' && (
              <DashboardView
                activeScenario={activeScenario}
                totalNodes={allNodes.length}
                filteredNodes={filteredNodes}
                selectedEntityId={selectedEntityId}
                entityLoading={entityLoading}
                healthOk={healthOk}
                headline={headline}
                riskTier={riskTier}
                currentPhase={currentPhase}
                latestEvent={latestEvent}
                onSelectNode={(id) => {
                  setSelectedEntityId(id);
                  pushStatus(`Selected ${id}`);
                }}
                onRefresh={refreshAll}
                onAdvance={handleAdvance}
                onReports={() => setActiveView('reports')}
              />
            )}

            {activeView === 'simulation' && (
              <SimulationView
                scenarios={scenarios}
                activeScenarioId={activeScenarioId}
                activeScenario={activeScenario}
                attackIntensity={attackIntensity}
                stealthLevel={stealthLevel}
                payloadDraft={payloadDraft}
                payloadEditable={payloadEditable}
                nodes={allNodes.slice(0, 8)}
                targets={simulationTargets}
                onScenarioSelect={handleScenarioSelect}
                onAttackIntensity={setAttackIntensity}
                onStealthLevel={setStealthLevel}
                onPayloadDraft={setPayloadDraft}
                onTogglePayload={() => setPayloadEditable((value) => !value)}
                onToggleTarget={toggleTarget}
                onAdvance={handleSimDeploy}
              />
            )}

            {activeView === 'intel' && (
              <IntelView
                activeScenario={activeScenario}
                totalNodes={allNodes.length}
                advisories={visibleAdvisories}
                criticalOnly={intelCriticalOnly}
                onToggleFilter={() => setIntelCriticalOnly((value) => !value)}
                onExport={handleExport}
              />
            )}

            {activeView === 'reports' && (
              <ReportsView
                onExport={handleExport}
                onRefresh={refreshAll}
                evaluation={evaluation}
                selectedEntityId={selectedEntityId}
              />
            )}
          </section>
        </div>

        <footer className="mt-5 flex flex-col gap-2 text-xs uppercase tracking-[0.18em] text-white/45 sm:flex-row sm:items-center sm:justify-between">
          <span>RAKSHAK Sovereign Systems</span>
          <span>{healthOk ? 'Status: Active' : 'Status: Backend Pending'} - {status}</span>
        </footer>
      </div>
    </main>
  );
}

function DashboardView({
  activeScenario,
  totalNodes,
  filteredNodes,
  selectedEntityId,
  entityLoading,
  healthOk,
  headline,
  riskTier,
  currentPhase,
  latestEvent,
  onSelectNode,
  onRefresh,
  onAdvance,
  onReports,
}: {
  activeScenario: any;
  totalNodes: number;
  filteredNodes: GraphNode[];
  selectedEntityId: string | null;
  entityLoading: boolean;
  healthOk: boolean;
  headline: number;
  riskTier: string;
  currentPhase: string;
  latestEvent?: { mitre_tactic: string; event_type: string; description: string } | null;
  onSelectNode: (id: string) => void;
  onRefresh: () => void;
  onAdvance: () => void;
  onReports: () => void;
}) {
  const { entityData, streamEvents } = useDashboard();

  return (
    <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)_360px]">
      <div className="space-y-5">
        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-8">
            <p className="mb-2 text-xs font-bold uppercase tracking-[0.22em] text-white/45">Sovereign Architecture</p>
            <h2 className="text-3xl font-bold uppercase text-cyan-50" style={{ fontFamily: 'var(--font-display)' }}>RAKSHAK</h2>
            <p className="mt-3 text-sm leading-7 text-white/65">Interdependency map for critical national infrastructure integrity.</p>
          </div>

          <div className="rounded-3xl border border-white/10 bg-black/20 px-5 py-4">
            <p className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-white/45">System Status</p>
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-3 rounded-full border border-white/10 bg-white/5 px-4 py-3">
                <span className={`h-3 w-3 rounded-full ${healthOk ? 'bg-emerald-300' : 'bg-rose-300'}`} />
                <span className="text-sm font-bold uppercase tracking-[0.18em]">{healthOk ? 'Nominal' : 'Connecting'}</span>
              </div>
              {streamEvents.length > 0 && streamEvents[0].event.run_id && (
                <div className="flex items-center justify-between rounded-full border border-cyan-500/20 bg-cyan-500/5 px-4 py-2 mt-1">
                  <span className="text-xs uppercase tracking-[0.15em] text-cyan-100/60">Run ID</span>
                  <span className="text-xs font-mono text-cyan-200">{streamEvents[0].event.run_id}</span>
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-5 flex items-center justify-between gap-3">
            <p className="text-xs font-bold uppercase tracking-[0.22em] text-white/45">Critical Nodes</p>
            <button
              onClick={onRefresh}
              className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 text-white/60 hover:bg-white/10 hover:text-cyan-100"
              aria-label="Refresh backend data"
              title="Refresh"
            >
              <Icon name="refresh" className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-3">
            {filteredNodes.map((node) => {
              const active = selectedEntityId === node.id;
              return (
                <button
                  key={`${node.graph_domain}-${node.id}`}
                  onClick={() => onSelectNode(node.id)}
                  className={`w-full rounded-3xl border px-5 py-4 text-left transition ${active ? 'border-cyan-300/45 bg-cyan-400/10 text-cyan-50' : 'border-white/10 bg-black/20 text-white/70 hover:border-white/20 hover:bg-white/5'}`}
                >
                  <div className="mb-3 flex items-start justify-between gap-3">
                    <span className="min-w-0 break-words text-sm font-bold">{node.label ?? node.id}</span>
                    <span className="shrink-0 rounded-full bg-white/10 px-2 py-1 text-[0.65rem] uppercase tracking-[0.12em] text-white/70">{node.graph_domain}</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/10">
                    <div
                      className="h-full rounded-full bg-cyan-100"
                      style={{ width: `${Math.max(12, Math.round(((node.belief ?? node.uncertainty ?? 0.24) as number) * 100))}%` }}
                    />
                  </div>
                </button>
              );
            })}
            {filteredNodes.length === 0 && (
              <div className="rounded-3xl border border-white/10 bg-black/20 p-5 text-sm text-white/50">No nodes match the current search.</div>
            )}
          </div>
        </section>
      </div>

      <div className="min-h-[620px] space-y-5">
        <div className="h-[620px] min-h-[56vh]">
          <GraphCanvas />
        </div>
        <AIQueryBar />
        <ScoreBreakdown />
      </div>

      <div className="space-y-5">
        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-5 flex items-start justify-between gap-3">
            <div>
              <p className="mb-2 text-xs font-bold uppercase tracking-[0.22em] text-white/45">Downstream Impact</p>
              <h3 className="break-words text-2xl font-bold text-cyan-50">{selectedEntityId ?? 'No Node Selected'}</h3>
            </div>
            <span className="rounded-full bg-violet-500/20 px-3 py-1 text-xs font-bold uppercase tracking-[0.12em] text-violet-200">{riskTier}</span>
          </div>
          <div className="grid gap-3">
            <div className="rounded-3xl border border-white/10 bg-black/25 p-5">
              <p className="text-xs uppercase tracking-[0.18em] text-white/40">Criticality</p>
              <div className="mt-2 flex items-end gap-2">
                <span className="text-5xl font-bold text-cyan-100" style={{ fontFamily: 'var(--font-display)' }}>{entityLoading ? '-' : ((entityData?.mission_criticality?.composite_score ?? 0) * 10).toFixed(1)}</span>
                <span className="pb-2 text-sm uppercase tracking-[0.14em] text-white/45">/ 10</span>
              </div>
            </div>
            <div className="rounded-3xl border border-white/10 bg-black/25 p-5">
              <p className="text-xs uppercase tracking-[0.18em] text-white/40">Campaign Phase</p>
              <p className="mt-2 break-words text-lg font-semibold text-white">{labelFromId(currentPhase)}</p>
              <p className="mt-1 text-sm text-white/55">{entityLoading ? 'Loading evidence...' : `${pct(entityData?.fusion?.belief)} belief - ${pct(entityData?.fusion?.uncertainty)} uncertainty`}</p>
            </div>
          </div>
        </section>

        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h3 className="text-xl font-semibold">Sector Risk Map</h3>
            <button
              onClick={onAdvance}
              className="rounded-full border border-cyan-200/20 px-3 py-1.5 text-xs font-bold uppercase tracking-[0.12em] text-cyan-100 hover:bg-cyan-100/10"
            >
              Live Sync
            </button>
          </div>
          <div className="mb-5 flex h-44 items-center justify-center rounded-3xl border border-white/10 bg-black/25">
            <div className="text-center">
              <div className="text-5xl font-bold text-cyan-200">{totalNodes}</div>
              <div className="mt-2 text-xs font-bold uppercase tracking-[0.2em] text-white/50">Nodes Active</div>
            </div>
          </div>
        </section>

        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-5 flex items-center justify-between gap-3">
            <h3 className="text-xl font-semibold">Active Scenario</h3>
            <button
              onClick={onReports}
              className="rounded-full bg-violet-500/20 px-3 py-1.5 text-xs font-bold uppercase tracking-[0.12em] text-violet-100 hover:bg-violet-500/30"
            >
              Audit
            </button>
          </div>
          <div className="space-y-4">
            <div className="flex min-w-0 flex-col gap-2 rounded-3xl border border-white/10 bg-black/20 p-5">
              <div className="text-sm font-bold uppercase tracking-[0.1em] text-cyan-200">{activeScenario?.name ?? 'No active scenario'}</div>
              <div className="text-xs text-white/60">{activeScenario?.business_impact ?? 'No details available'}</div>
            </div>
          </div>
        </section>
      </div>

      {latestEvent && (
        <div className="xl:col-span-3">
          <section className="glass-panel rounded-[28px] p-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-sm text-white/70"><span className="font-semibold text-cyan-100">{latestEvent.mitre_tactic}</span> - {latestEvent.description}</p>
              <span className="shrink-0 rounded-full bg-rose-400/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-rose-200">{latestEvent.event_type}</span>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function SimulationView({
  scenarios,
  activeScenarioId,
  activeScenario,
  attackIntensity,
  stealthLevel,
  payloadDraft,
  payloadEditable,
  nodes,
  targets,
  onScenarioSelect,
  onAttackIntensity,
  onStealthLevel,
  onPayloadDraft,
  onTogglePayload,
  onToggleTarget,
  onAdvance,
}: {
  scenarios: DemoScenario[];
  activeScenarioId: string;
  activeScenario?: DemoScenario;
  attackIntensity: number;
  stealthLevel: number;
  payloadDraft: string;
  payloadEditable: boolean;
  nodes: GraphNode[];
  targets: string[];
  onScenarioSelect: (id: string) => void;
  onAttackIntensity: (value: number) => void;
  onStealthLevel: (value: number) => void;
  onPayloadDraft: (value: string) => void;
  onTogglePayload: () => void;
  onToggleTarget: (id: string) => void;
  onAdvance: () => void;
}) {
  return (
    <div className="grid gap-5 xl:grid-cols-[330px_minmax(0,1fr)]">
      <section className="glass-panel rounded-[28px] p-6">
        <div className="mb-6 flex items-center justify-between gap-3">
          <h2 className="text-2xl font-bold text-violet-200">Scenario Library</h2>
          <Icon name="file" className="h-5 w-5 text-violet-200/70" />
        </div>
        <div className="space-y-4">
          {scenarios.map((scenario) => {
            const active = scenario.id === activeScenarioId;
            return (
              <button
                key={scenario.id}
                onClick={() => onScenarioSelect(scenario.id)}
                className={`w-full rounded-3xl border p-5 text-left transition ${active ? 'border-violet-400/60 bg-violet-600/25 text-white' : 'border-white/10 bg-black/20 text-white/62 hover:border-white/20 hover:bg-white/5'}`}
              >
                <div className="mb-3 flex items-start justify-between gap-3">
                  <span className="break-words text-lg font-bold">{scenario.name}</span>
                  <span className="shrink-0 rounded-full bg-white/10 px-2 py-1 text-[0.65rem] uppercase tracking-[0.12em]">{scenario.sector}</span>
                </div>
                <p className="line-clamp-3 text-sm leading-6 text-white/62">{scenario.business_impact}</p>
              </button>
            );
          })}
        </div>
      </section>

      <div className="space-y-5">
        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-7 flex flex-col gap-4 border-b border-white/10 pb-6 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <h1 className="text-4xl font-bold text-white/75 sm:text-6xl" style={{ fontFamily: 'var(--font-display)' }}>Simulation Parameters</h1>
              <p className="mt-3 break-words text-sm font-bold uppercase tracking-[0.12em] text-white/35">Scenario: {activeScenario?.name ?? 'Loading'} [{activeScenario?.facility_id ?? 'facility'}]</p>
            </div>
            <span className="w-fit rounded-full border border-rose-300/15 bg-rose-300/10 px-4 py-2 text-xs font-bold uppercase tracking-[0.14em] text-rose-200">System Armed</span>
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <div className="space-y-5">
              <ControlPanel
                label="Attack Intensity"
                value={attackIntensity}
                minLabel="Recon"
                maxLabel="Destructive"
                badge={`Level ${attackIntensity} ${attackIntensity > 6 ? '(High)' : '(Moderate)'}`}
                onChange={onAttackIntensity}
              />
              <ControlPanel
                label="Stealth Vector"
                value={stealthLevel}
                minLabel="Noisy"
                maxLabel="APT Level"
                badge={stealthLevel > 6 ? 'Obfuscated' : 'Visible'}
                onChange={onStealthLevel}
              />
            </div>

            <div className="rounded-[28px] border border-white/10 bg-black/20 p-6">
              <div className="mb-5 flex items-center justify-between gap-3 border-b border-white/10 pb-4">
                <h3 className="text-2xl font-bold text-white/65">Payload Matrix</h3>
                <button
                  onClick={onTogglePayload}
                  className="rounded-full bg-white/8 px-4 py-2 text-xs font-bold uppercase tracking-[0.12em] text-white/70 hover:bg-white/12"
                >
                  {payloadEditable ? 'Lock Payload' : 'Edit Payload'}
                </button>
              </div>
              {payloadEditable ? (
                <textarea
                  value={payloadDraft}
                  onChange={(event) => onPayloadDraft(event.target.value)}
                  className="min-h-48 w-full resize-y rounded-2xl border border-cyan-200/20 bg-black/35 p-4 font-mono text-sm leading-7 text-cyan-100 outline-none"
                />
              ) : (
                <pre className="min-h-48 whitespace-pre-wrap break-words rounded-2xl bg-black/25 p-4 font-mono text-sm leading-8 text-white/45">{payloadDraft}</pre>
              )}
              <button
                onClick={onAdvance}
                className="mt-5 w-full rounded-full bg-cyan-400/15 px-5 py-3 text-sm font-bold uppercase tracking-[0.14em] text-cyan-200 hover:bg-cyan-400/25"
              >
                Ready To Execute On Signal
              </button>
            </div>
          </div>
        </section>

        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-5 flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-4">
            <h2 className="text-2xl font-bold">Target Infrastructure Nodes</h2>
            <span className="rounded-full bg-white/5 px-4 py-2 text-xs font-bold uppercase tracking-[0.12em] text-white/40">{targets.length} nodes selected</span>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {nodes.map((node) => {
              const selected = targets.includes(node.id);
              return (
                <button
                  key={`${node.graph_domain}-${node.id}`}
                  onClick={() => onToggleTarget(node.id)}
                  className={`min-h-40 rounded-3xl border p-5 text-left transition ${selected ? 'border-cyan-300/60 bg-cyan-400/12 text-cyan-100' : 'border-white/10 bg-black/20 text-white/45 hover:border-white/20 hover:text-white/75'}`}
                >
                  <div className="mb-4 flex items-start justify-between gap-3">
                    <span className="break-words text-lg font-bold uppercase">{node.id}</span>
                    {selected && <span className="h-3 w-3 shrink-0 rounded-full bg-cyan-300" />}
                  </div>
                  <p className="break-words text-sm text-white/55">{node.label ?? node.node_type}</p>
                  <div className="mt-5 border-t border-white/10 pt-3 text-xs font-bold uppercase tracking-[0.12em] text-white/35">{node.graph_domain} - {node.node_type}</div>
                </button>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}

function ControlPanel({
  label,
  value,
  minLabel,
  maxLabel,
  badge,
  onChange,
}: {
  label: string;
  value: number;
  minLabel: string;
  maxLabel: string;
  badge: string;
  onChange: (value: number) => void;
}) {
  return (
    <div className="rounded-[28px] border border-white/10 bg-black/20 p-6">
      <div className="mb-6 flex items-center justify-between gap-3">
        <h3 className="text-xl font-bold text-white/70">{label}</h3>
        <span className="rounded-full bg-cyan-400/15 px-4 py-2 text-xs font-bold text-cyan-200">{badge}</span>
      </div>
      <input
        type="range"
        min={1}
        max={10}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="w-full accent-cyan-200"
      />
      <div className="mt-4 flex items-center justify-between text-sm font-semibold text-white/35">
        <span>{minLabel}</span>
        <span>{maxLabel}</span>
      </div>
    </div>
  );
}

function IntelView({
  activeScenario,
  totalNodes,
  advisories,
  criticalOnly,
  onToggleFilter,
  onExport,
}: {
  activeScenario: any;
  totalNodes: number;
  advisories: Advisory[];
  criticalOnly: boolean;
  onToggleFilter: () => void;
  onExport: () => void;
}) {
  return (
    <div className="space-y-5">
      <section className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-4xl font-bold uppercase text-white/85 sm:text-6xl" style={{ fontFamily: 'var(--font-display)' }}>Threat Intel Feed</h1>
          <p className="mt-3 text-sm font-bold uppercase tracking-[0.16em] text-cyan-100">Monitoring critical sectors: IND</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={onToggleFilter}
            className={`flex items-center gap-2 rounded-full border px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] ${criticalOnly ? 'border-cyan-200/35 bg-cyan-100/10 text-cyan-100' : 'border-white/10 bg-white/5 text-white/70 hover:bg-white/10'}`}
          >
            <Icon name="filter" className="h-4 w-4" />
            {criticalOnly ? 'Filtered' : 'Filter'}
          </button>
          <button
            onClick={onExport}
            className="flex items-center gap-2 rounded-full border border-violet-400/50 bg-violet-600/25 px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] text-violet-100 hover:bg-violet-600/35"
          >
            <Icon name="download" className="h-4 w-4" />
            Export Report
          </button>
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.8fr)]">
        <section className="glass-panel rounded-[28px] p-6">
          <div className="mb-5 flex items-center justify-between gap-3 border-b border-white/10 pb-5">
            <h2 className="text-2xl font-semibold">Fused Intelligence Alerts</h2>
            <span className="rounded-full border border-cyan-100/20 bg-cyan-100/10 px-4 py-1.5 text-xs font-bold uppercase tracking-[0.12em] text-cyan-100">Live Sync</span>
          </div>
          <div className="space-y-5">
            {advisories.map((item, index) => {
              const critical = item.domains.includes('OT') || item.domains.includes('IT+OT') || item.sector === 'power';
              return (
                <article
                  key={item.id}
                  className={`rounded-[28px] border bg-black/20 p-6 ${critical ? 'border-rose-300/30 shadow-[-6px_0_0_rgba(253,164,175,0.85)]' : 'border-emerald-300/25 shadow-[-6px_0_0_rgba(167,243,208,0.75)]'}`}
                >
                  <div className="mb-5 flex flex-wrap items-center gap-3">
                    <span className={`rounded-full border px-3 py-1 text-xs font-bold uppercase tracking-[0.12em] ${critical ? 'border-rose-300/30 bg-rose-300/10 text-rose-200' : 'border-emerald-300/25 bg-emerald-300/10 text-emerald-200'}`}>
                      {critical ? 'Critical' : 'High'}
                    </span>
                    <span className="text-sm font-bold uppercase tracking-[0.12em] text-white/60">ID: {item.id}</span>
                    <span className="ml-auto rounded-full bg-white/8 px-3 py-1 text-xs text-white/55">{index === 0 ? 'Just now' : item.published}</span>
                  </div>
                  <h3 className="break-words text-2xl text-white/90">{item.title}</h3>
                  <p className="mt-4 break-words text-base leading-8 text-white/68">{item.india_context}</p>
                  <div className="mt-6 grid gap-4 rounded-3xl bg-black/30 p-5 sm:grid-cols-3">
                    <div>
                      <p className="mb-2 text-xs uppercase tracking-[0.14em] text-white/35">MITRE ATT&CK</p>
                      <p className="break-words text-sm text-white">{item.techniques.join(', ')}</p>
                    </div>
                    <div>
                      <p className="mb-2 text-xs uppercase tracking-[0.14em] text-white/35">Sector</p>
                      <p className="text-sm font-bold uppercase text-cyan-100">{item.sector}</p>
                    </div>
                  </div>
                </article>
              );
            })}
            {advisories.length === 0 && (
              <div className="rounded-[28px] border border-white/10 bg-black/20 p-8 text-white/55">Threat intelligence is loading from the backend.</div>
            )}
          </div>
        </section>

        <div className="space-y-5">
          <section className="glass-panel rounded-[28px] p-6">
            <h2 className="mb-5 text-2xl font-semibold">Network Summary</h2>
            <div className="mb-5 flex h-52 items-center justify-center rounded-3xl border border-white/10 bg-black/25">
              <div className="text-center">
                <div className="text-6xl font-bold text-cyan-200">{totalNodes}</div>
                <div className="mt-3 text-sm font-bold uppercase tracking-[0.2em] text-white/50">Nodes Active</div>
              </div>
            </div>
          </section>
          <section className="glass-panel rounded-[28px] p-6">
            <h2 className="mb-5 text-2xl font-semibold">Active Scenario</h2>
            <div className="space-y-4">
              <div className="flex min-w-0 flex-col gap-2 rounded-3xl border border-white/10 bg-black/20 p-5">
                <div className="text-sm font-bold uppercase tracking-[0.1em] text-cyan-200">{activeScenario.name}</div>
                <div className="text-xs text-white/60">{activeScenario.business_impact}</div>
                <div className="mt-2 flex gap-4 text-xs font-mono text-white/40">
                  <div>Sector: <span className="text-white/80">{activeScenario.sector.toUpperCase()}</span></div>
                  <div>Policy: <span className="text-white/80">{activeScenario.default_policy}</span></div>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function ReportsView({
  onExport,
  onRefresh,
  evaluation,
  selectedEntityId,
}: {
  onExport: () => void;
  onRefresh: () => void;
  evaluation: any;
  selectedEntityId: string | null;
}) {
  const mttd = evaluation?.mttd_mttr;
  return (
    <div className="space-y-5">
      <section className="glass-panel rounded-[28px] p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h1 className="text-4xl font-bold uppercase text-white/85 sm:text-6xl" style={{ fontFamily: 'var(--font-display)' }}>Reports</h1>
            <p className="mt-3 text-sm font-bold uppercase tracking-[0.16em] text-cyan-100">Auditability and resilience evidence</p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={onRefresh}
              className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] text-white/70 hover:bg-white/10"
            >
              <Icon name="refresh" className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={onExport}
              className="flex items-center gap-2 rounded-full border border-violet-400/50 bg-violet-600/25 px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] text-violet-100 hover:bg-violet-600/35"
            >
              <Icon name="download" className="h-4 w-4" />
              Export Report
            </button>
          </div>
        </div>
      </section>

      <section className="grid gap-5 md:grid-cols-3">
        <MetricCard label="RAKSHAK MTTD" value={mttd ? `${mttd.rakshak_mttd_hours.toFixed(1)}h` : 'Live'} detail="Detection evidence" />
        <MetricCard label="RAKSHAK MTTR" value={mttd ? `${mttd.rakshak_mttr_hours.toFixed(1)}h` : 'Live'} detail="Recovery evidence" />
        <MetricCard label="Selected Entity" value={selectedEntityId ?? 'None'} detail="Audit filter context" />
      </section>

      <AuditTrailPanel embedded entityId={selectedEntityId} />
    </div>
  );
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="glass-panel rounded-[28px] p-6">
      <p className="mb-3 text-xs font-bold uppercase tracking-[0.2em] text-white/40">{label}</p>
      <p className="break-words text-3xl font-bold text-cyan-100" style={{ fontFamily: 'var(--font-display)' }}>{value}</p>
      <p className="mt-2 text-sm text-white/55">{detail}</p>
    </div>
  );
}

function UtilityPanelCard({
  panel,
  onClose,
  onRefresh,
  onReports,
  healthOk,
  streamEvents,
  selectedEntityId,
  status,
  feedLines,
}: {
  panel: Exclude<UtilityPanel, null>;
  onClose: () => void;
  onRefresh: () => void;
  onReports: () => void;
  healthOk: boolean;
  streamEvents: Array<{ timestamp: number; event: { event_type: string; description: string } }>;
  selectedEntityId: string | null;
  status: string;
  feedLines: import('@/components/AgentActivityFeed/AgentActivityFeed').FeedLine[];
}) {
  const getWidthClass = (p: UtilityPanel) => {
    if (p === 'audit' || p === 'redteam') return 'w-[min(900px,calc(100vw-32px))]';
    if (p === 'inspector' || p === 'signals' || p === 'feed') return 'w-[min(500px,calc(100vw-32px))]';
    return 'w-[min(420px,calc(100vw-32px))]';
  };
  return (
    <div className={`fixed right-4 top-24 z-50 ${getWidthClass(panel)} rounded-[28px] border border-white/12 bg-[#10151b]/95 p-5 shadow-2xl shadow-black/40 backdrop-blur-xl`}>
      <div className="mb-4 flex items-center justify-between gap-3 border-b border-white/10 pb-3">
        <h2 className="text-lg font-bold uppercase tracking-[0.14em] text-cyan-100">{labelFromId(panel)}</h2>
        <button
          onClick={onClose}
          className="flex h-8 w-8 items-center justify-center rounded-full border border-white/10 text-white/60 hover:bg-white/10 hover:text-white"
          aria-label="Close panel"
        >
          <Icon name="close" className="h-4 w-4" />
        </button>
      </div>

      {panel === 'notifications' && (
        <div className="space-y-3">
          {streamEvents.slice(-5).reverse().map((entry) => (
            <div key={`${entry.timestamp}-${entry.event.event_type}`} className="rounded-2xl border border-white/10 bg-black/25 p-4">
              <p className="text-xs font-bold uppercase tracking-[0.14em] text-violet-200">{entry.event.event_type}</p>
              <p className="mt-2 break-words text-sm leading-6 text-white/65">{entry.event.description}</p>
            </div>
          ))}
          {streamEvents.length === 0 && <p className="rounded-2xl border border-white/10 bg-black/25 p-4 text-sm text-white/55">No live stream events yet.</p>}
        </div>
      )}

      {panel === 'settings' && (
        <div className="space-y-3">
          <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
            <p className="text-xs font-bold uppercase tracking-[0.14em] text-white/40">Backend</p>
            <p className="mt-2 break-all font-mono text-sm text-cyan-100">{API_BASE}</p>
            <p className="mt-2 text-sm text-white/55">{healthOk ? 'Connected' : 'Waiting for health check'}</p>
          </div>
          <button
            onClick={onRefresh}
            className="flex w-full items-center justify-center gap-2 rounded-full bg-cyan-100 px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] text-slate-950 hover:bg-white"
          >
            <Icon name="refresh" className="h-4 w-4" />
            Refresh Backend Data
          </button>
        </div>
      )}

      {panel === 'profile' && (
        <div className="space-y-3">
          <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
            <p className="text-xs font-bold uppercase tracking-[0.14em] text-white/40">Operator Context</p>
            <p className="mt-2 break-words text-sm text-white/75">{selectedEntityId ?? 'No entity selected'}</p>
            <p className="mt-1 break-words text-sm text-white/50">{status}</p>
          </div>
          <button
            onClick={onReports}
            className="flex w-full items-center justify-center gap-2 rounded-full border border-violet-400/50 bg-violet-600/25 px-5 py-3 text-sm font-bold uppercase tracking-[0.12em] text-violet-100 hover:bg-violet-600/35"
          >
            <Icon name="file" className="h-4 w-4" />
            Open Audit Reports
          </button>
        </div>
      )}

      {panel === 'inspector' && (
        <div className="h-[75vh] w-full max-h-[800px] -mx-5 -my-5 px-5 py-5 overflow-y-auto overflow-x-hidden rounded-[28px]">
          <InspectorPanel />
        </div>
      )}

      {panel === 'signals' && (
        <div className="h-[75vh] w-full max-h-[800px] -mx-5 -my-5 px-5 py-5 overflow-y-auto overflow-x-hidden rounded-[28px]">
          <ResilienceSignalsPanel />
        </div>
      )}

      {panel === 'feed' && (
        <div className="h-[75vh] w-full max-h-[800px] -mx-5 -my-5 px-5 py-5 overflow-hidden rounded-[28px] bg-black/40">
          <AgentActivityFeed lines={feedLines} />
        </div>
      )}

      {panel === 'redteam' && (
        <div className="h-[75vh] w-full max-h-[800px] -mx-5 -my-5 px-5 py-5 overflow-y-auto overflow-x-hidden rounded-[28px]">
          <RedTeamMode onClose={onClose} />
        </div>
      )}

      {panel === 'audit' && (
        <div className="h-[75vh] w-full max-h-[800px] -mx-5 -my-5 px-5 py-5 overflow-y-auto overflow-x-hidden rounded-[28px]">
          <AuditTrailPanel />
        </div>
      )}
    </div>
  );
}
