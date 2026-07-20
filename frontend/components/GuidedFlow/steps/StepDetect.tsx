'use client';

import React, { useEffect } from 'react';
import useSWR from 'swr';
import { GraphCanvas } from '@/components/LivingGraph/GraphCanvas';
import { useDashboard } from '@/lib/store';
import { API_BASE, fetcher } from '@/lib/api';

export function StepDetect() {
  const { setSelectedEntityId, selectedEntityId } = useDashboard();
  
  const { data: liveState } = useSWR(
    `${API_BASE}/api/graph/live-state`,
    fetcher,
    { refreshInterval: 5000 }
  );

  useEffect(() => {
    // Only auto-select if no entity is currently selected
    if (selectedEntityId) return;
    if (liveState?.nodes && liveState.nodes.length > 0) {
      const highest = liveState.nodes.reduce((prev: any, current: any) => {
        return ((prev.uncertainty || 0) > (current.uncertainty || 0)) ? prev : current;
      });
      
      setSelectedEntityId(highest.id);
    }
  }, [liveState, selectedEntityId, setSelectedEntityId]);

  return (
    <div className="w-full h-full p-2">
      <div className="w-full h-full rounded-xl overflow-hidden shadow-2xl border border-white/5">
        <GraphCanvas />
      </div>
    </div>
  );
}
