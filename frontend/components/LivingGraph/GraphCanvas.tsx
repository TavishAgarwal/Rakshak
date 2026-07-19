'use client';

import React from 'react';
import useSWR from 'swr';
import { ForceGraph } from './ForceGraph';
import { useDashboard } from '@/lib/store';
import { API_BASE, fetcher } from '@/lib/api';

export function GraphCanvas() {
  const { selectedEntityId, graphNodes, graphEdges, nodeUncertainties, streamActive, streamEvents } = useDashboard();

  const { data: liveState } = useSWR(
    `${API_BASE}/api/graph/live-state`,
    fetcher,
    { refreshInterval: 3000 }
  );

  // Merge live uncertainties and belief from stream/polling into graph nodes
  const liveNodesMap = React.useMemo(() => {
    const map: Record<string, any> = {};
    if (liveState?.nodes) {
      liveState.nodes.forEach((n: any) => {
        map[n.id] = { uncertainty: n.uncertainty, belief: n.belief };
      });
    }
    return map;
  }, [liveState]);

  const nodesWithMetrics = React.useMemo(() => {
    return graphNodes.map(n => ({
      ...n,
      uncertainty: liveNodesMap[n.id]?.uncertainty ?? nodeUncertainties[n.id] ?? n.uncertainty ?? 0.05,
      belief: liveNodesMap[n.id]?.belief ?? n.belief ?? 0,
    }));
  }, [graphNodes, liveNodesMap, nodeUncertainties]);

  const lastEvent = streamEvents.length > 0 ? streamEvents[streamEvents.length - 1] : null;

  return (
    <div className="glass-panel flex flex-col h-full p-4 relative overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <div className="section-label">Living Graph</div>
          {streamActive && lastEvent && (
            <span className="text-[0.55rem] px-2 py-0.5 rounded animate-pulse" style={{
              background: 'rgba(226,63,107,0.1)',
              color: 'var(--color-accent-fusion)',
              fontFamily: 'var(--font-mono)',
            }}>
              {lastEvent.event.mitre_tactic} · {lastEvent.event.event_type}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {selectedEntityId && (
            <span className="text-[0.6rem] px-2 py-0.5 rounded" style={{
              background: 'rgba(255,255,255,0.08)',
              color: 'var(--color-text-primary)',
              fontFamily: 'var(--font-mono)',
            }}>
              {selectedEntityId}
            </span>
          )}
          <span className="text-[0.55rem]" style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            {graphNodes.length} nodes · {graphEdges.length} edges
          </span>
        </div>
      </div>

      {/* D3 Force Graph */}
      <div id="graph-canvas" className="flex-1 rounded-lg relative overflow-hidden" style={{ background: 'rgba(10, 14, 23, 0.6)' }}>
        {graphNodes.length > 0 ? (
          <ForceGraph nodes={nodesWithMetrics} edges={graphEdges} />
        ) : (
          <div className="flex items-center justify-center h-full">
            <span className="text-sm animate-pulse" style={{ color: 'var(--color-text-muted)' }}>
              Loading graph...
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
