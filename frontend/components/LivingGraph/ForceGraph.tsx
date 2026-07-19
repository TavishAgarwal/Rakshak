'use client';

import React, { useRef, useEffect, useState, useCallback } from 'react';
import * as d3 from 'd3';
import type { GraphNode, GraphEdge } from '@/lib/store';
import { useDashboard } from '@/lib/store';

/* ── Design tokens ────────────────────────────────────── */
const COLORS = {
  IT: '#5B8DEF',
  OT: '#F2A65A',
  BRIDGE: '#8B5CF6',
  SELECTED: '#FFFFFF',
  EDGE_DEFAULT: 'rgba(137, 147, 168, 0.15)',
  EDGE_HIGHLIGHT: 'rgba(226, 63, 107, 0.4)',
  TEXT: '#8993A8',
};

const NODE_RADIUS: Record<string, number> = {
  USER: 5,
  ENDPOINT: 6,
  CLOUD_RESOURCE: 6,
  APPLICATION: 7,
  API: 5,
  IT_OT_BRIDGE: 10,
  PLC: 7,
  RTU: 6,
  HMI: 6,
  SCADA_SERVER: 8,
  SENSOR: 4,
  ACTUATOR: 5,
};

function getNodeColor(node: GraphNode): string {
  if (node.node_type === 'IT_OT_BRIDGE') return COLORS.BRIDGE;
  return node.graph_domain === 'IT' ? COLORS.IT : COLORS.OT;
}

function getNodeRadius(node: GraphNode): number {
  return NODE_RADIUS[node.node_type] || 6;
}

/* ── Breathing / pulse parameters ─────────────────────── */
function getBreatheCycle(uncertainty: number): number {
  // Idle: ~4s cycle. High uncertainty: ~1s cycle.
  return 4000 - uncertainty * 3000; // 4000ms → 1000ms
}

function getGlowRadius(uncertainty: number, baseRadius: number): number {
  // Idle: radius + 2. High uncertainty: radius + 12.
  return baseRadius + 2 + uncertainty * 10;
}

/* ── Props ────────────────────────────────────────────── */
interface ForceGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* ── Component ────────────────────────────────────────── */
export function ForceGraph({ nodes, edges }: ForceGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { selectedEntityId, setSelectedEntityId } = useDashboard();
  const [reducedMotion, setReducedMotion] = useState(false);
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphEdge> | null>(null);

  // Check prefers-reduced-motion
  useEffect(() => {
    const mql = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mql.matches);
    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, []);

  // D3 force simulation
  useEffect(() => {
    const svg = svgRef.current;
    const container = containerRef.current;
    if (!svg || !container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    // Clear previous
    d3.select(svg).selectAll('*').remove();

    // Deep copy data for D3 mutation
    const simNodes: GraphNode[] = nodes.map(n => ({ ...n }));
    const simEdges: GraphEdge[] = edges.map(e => ({ ...e }));

    // SVG setup
    const svgSel = d3.select(svg)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`);

    // Defs for glow filters
    const defs = svgSel.append('defs');

    // Glow filter per domain
    ['it', 'ot', 'bridge', 'selected'].forEach((domain) => {
      const color = domain === 'it' ? COLORS.IT
        : domain === 'ot' ? COLORS.OT
        : domain === 'bridge' ? COLORS.BRIDGE
        : COLORS.SELECTED;

      const filter = defs.append('filter')
        .attr('id', `glow-${domain}`)
        .attr('x', '-100%').attr('y', '-100%')
        .attr('width', '300%').attr('height', '300%');

      filter.append('feGaussianBlur')
        .attr('stdDeviation', '4')
        .attr('result', 'blur');

      filter.append('feFlood')
        .attr('flood-color', color)
        .attr('flood-opacity', '0.6');

      filter.append('feComposite')
        .attr('in2', 'blur')
        .attr('operator', 'in');

      const merge = filter.append('feMerge');
      merge.append('feMergeNode');
      merge.append('feMergeNode').attr('in', 'SourceGraphic');
    });

    // Edge layer
    const edgeGroup = svgSel.append('g').attr('class', 'edges');
    const linkSel = edgeGroup.selectAll('line')
      .data(simEdges)
      .enter()
      .append('line')
      .attr('stroke', (d: GraphEdge) => {
        if (d.edge_type === 'DATA_FLOW' &&
            ((typeof d.source === 'object' ? (d.source as GraphNode).node_type : '') === 'IT_OT_BRIDGE' ||
             (typeof d.target === 'object' ? (d.target as GraphNode).node_type : '') === 'IT_OT_BRIDGE')) {
          return COLORS.EDGE_HIGHLIGHT;
        }
        return COLORS.EDGE_DEFAULT;
      })
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', (d: GraphEdge) =>
        d.edge_type === 'LATERAL_MOVEMENT' ? '4 2' : 'none'
      );

    // Node layer
    const nodeGroup = svgSel.append('g').attr('class', 'nodes');
    const nodeSel = nodeGroup.selectAll('g')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('cursor', 'pointer')
      .on('click', (_event: MouseEvent, d: GraphNode) => {
        setSelectedEntityId(d.id === selectedEntityId ? null : d.id);
      })
      .call(
        d3.drag<SVGGElement, GraphNode>()
          .on('start', (event, d) => {
            if (!event.active) simulationRef.current?.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulationRef.current?.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          }) as any
      );

    // Glow circle (behind main circle)
    nodeSel.append('circle')
      .attr('class', (d: GraphNode) => d.node_type === 'IT_OT_BRIDGE' ? 'node-glow bridge-node-glow' : 'node-glow dynamic-node-glow')
      .attr('r', (d: GraphNode) => getGlowRadius(d.uncertainty || 0, getNodeRadius(d)))
      .attr('fill', (d: GraphNode) => d.node_type === 'IT_OT_BRIDGE' ? 'transparent' : getNodeColor(d))
      .style('--pulse-speed', (d: GraphNode) => `${3 - (d.uncertainty || 0) * 2}s`)
      .style('--pulse-opacity', (d: GraphNode) => Math.max(0.2, d.belief || 0).toString());

    // Main circle
    nodeSel.append('circle')
      .attr('class', 'node-core')
      .attr('r', (d: GraphNode) => getNodeRadius(d))
      .attr('fill', (d: GraphNode) => getNodeColor(d))
      .attr('stroke', (d: GraphNode) =>
        d.node_type === 'IT_OT_BRIDGE' ? COLORS.BRIDGE : 'none'
      )
      .attr('stroke-width', (d: GraphNode) =>
        d.node_type === 'IT_OT_BRIDGE' ? 2 : 0
      )
      .attr('opacity', 0.85);

    // Labels
    nodeSel.append('text')
      .attr('class', 'node-label')
      .attr('dy', (d: GraphNode) => getNodeRadius(d) + 12)
      .attr('text-anchor', 'middle')
      .attr('fill', COLORS.TEXT)
      .attr('font-size', '8px')
      .attr('font-family', "'JetBrains Mono', monospace")
      .style('pointer-events', 'none')
      .attr('opacity', (d: GraphNode) => {
        const isCritical = (d.uncertainty || 0) >= 0.7;
        const isBridge = d.node_type === 'IT_OT_BRIDGE';
        return (isCritical || isBridge) ? 0.7 : 0;
      })
      .text((d: GraphNode) => d.label || d.id.split('-').pop() || d.id);

    nodeSel
      .on('mouseenter', function(event, d) {
        d3.select(this).select('.node-label').attr('opacity', 1);
      })
      .on('mouseleave', function(event, d) {
        const isCritical = (d.uncertainty || 0) >= 0.7;
        const isBridge = d.node_type === 'IT_OT_BRIDGE';
        const isSelected = d.id === selectedEntityId;
        if (!isCritical && !isBridge && !isSelected) {
          d3.select(this).select('.node-label').attr('opacity', 0);
        } else {
          d3.select(this).select('.node-label').attr('opacity', 0.7);
        }
      });

    // Force simulation
    const simulation = d3.forceSimulation<GraphNode>(simNodes)
      .force('link', d3.forceLink<GraphNode, GraphEdge>(simEdges)
        .id((d: GraphNode) => d.id)
        .distance(60)
        .strength(0.4))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<GraphNode>()
        .radius((d: GraphNode) => getNodeRadius(d) + 8))
      .force('x', d3.forceX<GraphNode>(width / 2).strength(0.05))
      .force('y', d3.forceY<GraphNode>(height / 2).strength(0.05));

    // Separate IT and OT clusters slightly
    simulation.force('domain', d3.forceX<GraphNode>((d: GraphNode) => {
      if (d.node_type === 'IT_OT_BRIDGE') return width / 2;
      return d.graph_domain === 'IT' ? width * 0.38 : width * 0.62;
    }).strength(0.08));

    simulationRef.current = simulation;

    simulation.on('tick', () => {
      linkSel
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      nodeSel.attr('transform', (d: GraphNode) =>
        `translate(${d.x || 0},${d.y || 0})`
      );

      // Basic label collision avoidance
      const texts = nodeSel.selectAll<SVGTextElement, GraphNode>('.node-label').nodes();
      for (let i = 0; i < texts.length; i++) {
        const t1 = texts[i];
        if (parseFloat(d3.select(t1).attr('opacity')) === 0) continue;
        
        const d1 = d3.select(t1).datum() as GraphNode;
        let dy = getNodeRadius(d1) + 12;
        
        for (let j = 0; j < i; j++) {
          const t2 = texts[j];
          if (parseFloat(d3.select(t2).attr('opacity')) === 0) continue;
          
          const d2 = d3.select(t2).datum() as GraphNode;
          const dx = (d1.x || 0) - (d2.x || 0);
          const distY = (d1.y || 0) - (d2.y || 0);
          
          if (Math.abs(dx) < 35 && Math.abs(distY) < 20) {
            dy += 12; // offset overlapping label downwards
          }
        }
        d3.select(t1).attr('dy', dy);
      }
    });

    // ── CSS Breathing handles animation now ──────────────────────────────

    // Cleanup
    return () => {
      simulation.stop();
    };
  }, [nodes, edges, reducedMotion]); // eslint-disable-line react-hooks/exhaustive-deps

  // Update selection highlight
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    d3.select(svg).selectAll<SVGGElement, GraphNode>('.nodes g')
      .select('.node-core')
      .attr('stroke', (d: GraphNode) => {
        if (d.id === selectedEntityId) return COLORS.SELECTED;
        if (d.node_type === 'IT_OT_BRIDGE') return COLORS.BRIDGE;
        return 'none';
      })
      .attr('stroke-width', (d: GraphNode) => {
        if (d.id === selectedEntityId) return 2.5;
        if (d.node_type === 'IT_OT_BRIDGE') return 2;
        return 0;
      })
      .attr('filter', (d: GraphNode) => {
        if (d.id === selectedEntityId) return 'url(#glow-selected)';
        if (d.node_type === 'IT_OT_BRIDGE') return 'url(#glow-bridge)';
        return 'none';
      });
  }, [selectedEntityId]);

  return (
    <div ref={containerRef} className="w-full h-full relative">
      <svg
        ref={svgRef}
        className="w-full h-full"
        style={{ background: 'transparent' }}
      />
      {/* Legend */}
      <div className="absolute bottom-2 left-2 flex items-center gap-4" style={{ opacity: 0.5 }}>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: COLORS.IT }} />
          <span className="text-[0.55rem]" style={{ fontFamily: "'JetBrains Mono', monospace", color: COLORS.TEXT }}>IT</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: COLORS.OT }} />
          <span className="text-[0.55rem]" style={{ fontFamily: "'JetBrains Mono', monospace", color: COLORS.TEXT }}>OT</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full" style={{ background: COLORS.BRIDGE, boxShadow: `0 0 6px ${COLORS.BRIDGE}` }} />
          <span className="text-[0.55rem]" style={{ fontFamily: "'JetBrains Mono', monospace", color: COLORS.TEXT }}>Bridge</span>
        </div>
      </div>
    </div>
  );
}
