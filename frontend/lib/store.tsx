'use client';

import React, { createContext, useContext, useState, useCallback, useMemo, useEffect, useRef } from 'react';
import type { EntityData, ResilienceData, GraphSnapshot } from '@/lib/api';
import { fetchGraph, fetchEntity, fetchResilience } from '@/lib/api';
import { connectStream, type StreamEvent, type StreamResilienceUpdate } from '@/lib/ws';
import type { FeedLine, FeedSource } from '@/components/AgentActivityFeed/AgentActivityFeed';
import { FeedQueue, deriveLinesFromResult, deriveLinesFromStreamEvent } from '@/components/AgentActivityFeed/AgentActivityFeed';

/* ── Graph node/edge types for D3 ─────────────────────── */

export interface GraphNode {
  id: string;
  node_type: string;
  graph_domain: string;
  label?: string;
  mission_criticality?: number;
  safety_rated?: boolean;
  uncertainty?: number;
  belief?: number;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  edge_type: string;
}

/* ── Stream event log entry ───────────────────────────── */

export interface StreamLogEntry {
  timestamp: number;
  event: StreamEvent;
}

/* ── Context ──────────────────────────────────────────── */

interface DashboardState {
  // Selection
  selectedEntityId: string | null;
  setSelectedEntityId: (id: string | null) => void;

  // Entity data (loaded on selection)
  entityData: EntityData | null;
  entityLoading: boolean;
  refreshSelectedEntity: (id?: string | null) => Promise<void>;

  // Resilience
  resilience: ResilienceData | null;
  refreshResilience: () => Promise<void>;

  // Graph data
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];

  // Stream
  streamActive: boolean;
  streamEvents: StreamLogEntry[];
  startStream: (speed?: number) => void;
  stopStream: () => void;

  // Node uncertainty map (updated by stream)
  nodeUncertainties: Record<string, number>;

  // Drawer states
  signalsDrawerOpen: boolean;
  setSignalsDrawerOpen: (open: boolean) => void;
  inspectorDrawerOpen: boolean;
  setInspectorDrawerOpen: (open: boolean) => void;

  // Narration
  latestNarration: string | null;
  setLatestNarration: (narration: string | null) => void;

  // Agent Activity Feed
  feedLines: FeedLine[];
  feedMinimized: boolean;
  setFeedMinimized: (min: boolean) => void;
  feedQueue: FeedQueue | null;
  addFeedLines: (lines: FeedLine[]) => void;
  clearFeed: () => void;
}

const DashboardContext = createContext<DashboardState>({
  selectedEntityId: null,
  setSelectedEntityId: () => {},
  entityData: null,
  entityLoading: false,
  refreshSelectedEntity: async () => {},
  resilience: null,
  refreshResilience: async () => {},
  graphNodes: [],
  graphEdges: [],
  streamActive: false,
  streamEvents: [],
  startStream: () => {},
  stopStream: () => {},
  nodeUncertainties: {},
  signalsDrawerOpen: false,
  setSignalsDrawerOpen: () => {},
  inspectorDrawerOpen: false,
  setInspectorDrawerOpen: () => {},
  latestNarration: null,
  setLatestNarration: () => {},
  feedLines: [],
  feedMinimized: false,
  setFeedMinimized: () => {},
  feedQueue: null,
  addFeedLines: () => {},
  clearFeed: () => {},
});

function noteApiFailure(label: string, err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  console.warn(`${label}: ${message}`);
}

function normalizeResilienceUpdate(data: any): ResilienceData | null {
  const score = data.score ?? data.headline_score;
  const breakdown = data.breakdown ?? data.components;
  if (typeof score !== 'number' || !breakdown) return null;
  return {
    headline_score: score,
    score,
    assessment: data.assessment,
    breakdown: breakdown as any,
  };
}

/* ── Provider ─────────────────────────────────────────── */

export function DashboardProvider({ children }: { children: React.ReactNode }) {
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [entityData, setEntityData] = useState<EntityData | null>(null);
  const [entityLoading, setEntityLoading] = useState(false);
  const [resilience, setResilience] = useState<ResilienceData | null>(null);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [streamActive, setStreamActive] = useState(false);
  const [streamEvents, setStreamEvents] = useState<StreamLogEntry[]>([]);
  const [nodeUncertainties, setNodeUncertainties] = useState<Record<string, number>>({});
  const [signalsDrawerOpen, setSignalsDrawerOpen] = useState(false);
  const [inspectorDrawerOpen, setInspectorDrawerOpen] = useState(false);
  const [latestNarration, setLatestNarration] = useState<string | null>(null);
  const [feedLines, setFeedLines] = useState<FeedLine[]>([]);
  const [feedMinimized, setFeedMinimized] = useState(false);
  const feedQueueRef = useRef<FeedQueue | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // ── Feed queue setup ──────────────────────────────────
  const addFeedLines = useCallback((lines: FeedLine[]) => {
    if (feedQueueRef.current) {
      feedQueueRef.current.enqueue(lines);
    }
  }, []);

  const clearFeed = useCallback(() => {
    setFeedLines([]);
    if (feedQueueRef.current) {
      feedQueueRef.current.clear();
    }
  }, []);

  // Initialize feed queue once
  useEffect(() => {
    feedQueueRef.current = new FeedQueue(
      (line: FeedLine) => {
        setFeedLines((prev) => [line, ...prev].slice(0, 150));
      },
      600,
    );
    return () => {
      feedQueueRef.current?.clear();
    };
  }, []);

  const refreshResilience = useCallback(async () => {
    try {
      setResilience(await fetchResilience());
    } catch (err) {
      noteApiFailure('Failed to load resilience', err);
    }
  }, []);

  const refreshSelectedEntity = useCallback(async (id?: string | null) => {
    const target = id ?? selectedEntityId;
    if (!target) return;
    setSelectedEntityId(target);
    setEntityLoading(true);
    try {
      setEntityData(await fetchEntity(target));
    } catch (err) {
      noteApiFailure('Failed to load entity', err);
      setEntityData(null);
    } finally {
      setEntityLoading(false);
    }
  }, [selectedEntityId]);

  // ── Auto-open inspector drawer when entity selected ────
  useEffect(() => {
    setInspectorDrawerOpen(selectedEntityId !== null);
  }, [selectedEntityId]);

  // ── Load graph on mount ────────────────────────────────
  useEffect(() => {
    fetchGraph()
      .then((snap: GraphSnapshot) => {
        const itNodes: GraphNode[] = snap.it_graph.nodes.map((n) => ({
          ...n,
          graph_domain: 'IT' as const,
          uncertainty: n.uncertainty ?? 0.05,
        }));
        const otNodes: GraphNode[] = snap.ot_graph.nodes.map((n) => ({
          ...n,
          graph_domain: 'OT' as const,
          uncertainty: n.uncertainty ?? 0.05,
        }));
        const allNodes = [...itNodes, ...otNodes];
        setGraphNodes(allNodes);
        setGraphEdges([...snap.it_graph.edges, ...snap.ot_graph.edges]);
        if (!selectedEntityId && allNodes.some((node) => node.id === 'AuthServer-03')) {
          setSelectedEntityId('AuthServer-03');
        }
      })
      .catch((err) => noteApiFailure('Failed to load graph', err));
  }, [selectedEntityId]);

  // ── Load resilience on mount ───────────────────────────
  useEffect(() => {
    refreshResilience();
  }, [refreshResilience]);

  // ── Load entity on selection ───────────────────────────
  useEffect(() => {
    if (!selectedEntityId) {
      setEntityData(null);
      return;
    }
    setEntityLoading(true);
    let cancelled = false;
    const load = () => fetchEntity(selectedEntityId)
      .then((data) => {
        if (cancelled) return;
        setEntityData(data);
        setEntityLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        noteApiFailure('Failed to load entity', err);
        setEntityData(null);
        setEntityLoading(false);
      });
    load();
    const timer = setInterval(load, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [selectedEntityId]);

  // ── Stream controls ────────────────────────────────────
  const startStream = useCallback((speed: number = 5) => {
    if (wsRef.current) wsRef.current.close();
    setStreamEvents([]);
    setStreamActive(true);

    const ws = connectStream(speed, {
      onEvent: (evt, ts) => {
        setStreamEvents((prev) => [...prev, { timestamp: ts, event: evt }]);

        // Update narration from stream event description
        if (evt.description) {
          setLatestNarration(evt.description);
        }

        const primaryNode = evt.affected_nodes.find((node) => node.node_id)?.node_id
          ?? evt.target_node
          ?? evt.source_node;
        if (primaryNode) {
          setSelectedEntityId(primaryNode);
          fetchEntity(primaryNode).then(setEntityData).catch((err) => noteApiFailure('Failed to reload entity', err));
        }

        // Update node uncertainties from fusion beliefs
        const updates: Record<string, number> = {};
        for (const node of evt.affected_nodes) {
          if (node.fusion) updates[node.node_id] = node.fusion.belief;
        }
        setNodeUncertainties((prev) => ({ ...prev, ...updates }));

        // ── Feed the Agent Activity Feed with stream event data ──
        if (feedQueueRef.current && evt.affected_nodes.length > 0) {
          const lines = deriveLinesFromStreamEvent(evt);
          if (lines.length > 0) {
            feedQueueRef.current.enqueue(lines);
          }
        }
        
        // ── Apply Resilience Update if present ──
        if (evt.resilience_update && evt.resilience_update.after) {
          const normalized = normalizeResilienceUpdate(evt.resilience_update.after);
          if (normalized) setResilience(normalized);
        }
      },
      onResilience: (data: StreamResilienceUpdate) => {
        const normalized = normalizeResilienceUpdate(data);
        if (normalized) setResilience(normalized);
      },
      onEnd: (data) => {
        setStreamActive(false);
        const normalized = normalizeResilienceUpdate(data.final_resilience);
        if (normalized) setResilience(normalized);
        // Reload entity if one is selected
        if (selectedEntityId) {
          fetchEntity(selectedEntityId).then(setEntityData).catch((err) => noteApiFailure('Failed to reload entity', err));
        }
        refreshResilience();
      },
      onClose: () => setStreamActive(false),
      onError: (err) => {
        noteApiFailure('Stream error', err);
        setStreamActive(false);
      },
    });
    wsRef.current = ws;
  }, [selectedEntityId, refreshResilience]);

  const stopStream = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStreamActive(false);
  }, []);

  // ── Cleanup on unmount ─────────────────────────────────
  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const handleSelect = useCallback((id: string | null) => {
    setSelectedEntityId(id);
  }, []);

  const contextValue = useMemo(() => ({
    selectedEntityId,
    setSelectedEntityId: handleSelect,
    entityData,
    entityLoading,
    refreshSelectedEntity,
    resilience,
    refreshResilience,
    graphNodes,
    graphEdges,
    streamActive,
    streamEvents,
    startStream,
    stopStream,
    nodeUncertainties,
    signalsDrawerOpen,
    setSignalsDrawerOpen,
    inspectorDrawerOpen,
    setInspectorDrawerOpen,
    latestNarration,
    setLatestNarration,
    feedLines,
    feedMinimized,
    setFeedMinimized,
    feedQueue: feedQueueRef.current,
    addFeedLines,
    clearFeed,
  }), [
    selectedEntityId, handleSelect, entityData, entityLoading,
    refreshSelectedEntity, resilience, refreshResilience, graphNodes, graphEdges, streamActive, streamEvents,
    startStream, stopStream, nodeUncertainties,
    signalsDrawerOpen, inspectorDrawerOpen, latestNarration,
    feedLines, feedMinimized, setFeedMinimized, addFeedLines, clearFeed,
  ]);

  return (
    <DashboardContext.Provider value={contextValue}>
      {children}
    </DashboardContext.Provider>
  );
}

export function useDashboard() {
  return useContext(DashboardContext);
}
