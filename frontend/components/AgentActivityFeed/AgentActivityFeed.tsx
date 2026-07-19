'use client';

import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';

/* ── Types ────────────────────────────────────────────── */

export interface FeedLine {
  /** Unique id for React key / stagger dedup */
  id: string;
  /** Agent prefix label */
  agent: 'Behavioral' | 'Fusion' | 'Campaign' | 'Response';
  /** The message body */
  text: string;
  /** ISO timestamp */
  timestamp: string;
  /** Optional numeric value for a mini bar */
  value?: number;
  /** Visual accent color override */
  color?: string;
}

export interface FeedSource {
  /** Raw behavior scores dict, e.g. { identity: 0.8, network: 0.3 } */
  scores?: Record<string, number>;
  /** Fusion result */
  fusion?: { belief: number; plausibility: number; uncertainty: number; conflict?: number };
  /** Campaign state */
  campaign?: { dominant_phase: string; dominant_probability: number; distribution?: Record<string, number> };
  /** Response gate */
  gate?: { risk_tier: string; allowed_actions?: string[]; blocked_actions?: string[]; requires_human_escalation?: boolean; rationale?: string[] };
  /** Optional entity label */
  label?: string;
  /** Optional timestamp (defaults to now) */
  timestamp?: string;
}

/* ── Derive feed lines from a RedTeam-style result payload ─── */

const AGENT_COLORS: Record<FeedLine['agent'], string> = {
  Behavioral: '#5B8DEF',
  Fusion: '#E23F6B',
  Campaign: '#F2A65A',
  Response: '#34D399',
};

const SCORER_LABELS: Record<string, string> = {
  identity: 'Identity Anomaly',
  credential: 'Credential Risk',
  process: 'Process Deviation',
  network: 'Network Flow',
  dns: 'DNS Tunneling',
  cloud_api: 'Cloud API Abuse',
  ot_physics: 'OT Physics',
};

let _lineCounter = 0;

export function deriveLinesFromResult(
  source: FeedSource & { id?: string },
): FeedLine[] {
  const ts = source.timestamp || new Date().toISOString();
  const label = source.label || '';
  const lines: FeedLine[] = [];

  // ── Behavioral Agent lines (raw scores) ──────────
  if (source.scores && Object.keys(source.scores).length > 0) {
    const active = Object.entries(source.scores)
      .filter(([, v]) => v > 0)
      .sort(([, a], [, b]) => b - a);

    for (const [scorer, score] of active) {
      _lineCounter++;
      const name = SCORER_LABELS[scorer] || scorer;
      const pct = (score * 100).toFixed(1);
      const severity = score > 0.7 ? 'elevated' : score > 0.3 ? 'suspicious' : 'normal';
      lines.push({
        id: `beh-${_lineCounter}`,
        agent: 'Behavioral',
        text: `${name} — ${pct}% (${severity})${label ? ` on ${label}` : ''}`,
        timestamp: ts,
        value: score,
        color: AGENT_COLORS.Behavioral,
      });
    }
  }

  // ── Fusion Agent lines ───────────────────────────
  if (source.fusion) {
    const f = source.fusion;
    _lineCounter++;
    const bel = (f.belief * 100).toFixed(1);
    const pl = (f.plausibility * 100).toFixed(1);
    const unc = (f.uncertainty * 100).toFixed(1);
    const conflictStr = f.conflict !== undefined ? ` · Conflict: ${(f.conflict * 100).toFixed(1)}%` : '';
    lines.push({
      id: `fus-${_lineCounter}`,
      agent: 'Fusion',
      text: `Belief ${bel}% · Plausibility ${pl}% · Uncertainty ${unc}%${conflictStr}${label ? ` [${label}]` : ''}`,
      timestamp: ts,
      value: f.belief,
      color: AGENT_COLORS.Fusion,
    });
  }

  // ── Campaign Agent lines ─────────────────────────
  if (source.campaign) {
    const c = source.campaign;
    _lineCounter++;
    const prob = (c.dominant_probability * 100).toFixed(0);
    lines.push({
      id: `cmp-${_lineCounter}`,
      agent: 'Campaign',
      text: `Phase: ${c.dominant_phase} (${prob}% confidence)${label ? ` on ${label}` : ''}`,
      timestamp: ts,
      value: c.dominant_probability,
      color: AGENT_COLORS.Campaign,
    });

    if (c.distribution) {
      const entries = Object.entries(c.distribution)
        .filter(([, v]) => v > 0.01)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 4);
      for (const [phase, probVal] of entries) {
        if (phase === c.dominant_phase) continue;
        _lineCounter++;
        lines.push({
          id: `cmp-${_lineCounter}`,
          agent: 'Campaign',
          text: `  ${phase}: ${(probVal * 100).toFixed(0)}%`,
          timestamp: ts,
          value: probVal,
          color: AGENT_COLORS.Campaign,
        });
      }
    }
  }

  // ── Response Agent lines ─────────────────────────
  if (source.gate) {
    const g = source.gate;
    _lineCounter++;
    const tierColor = g.risk_tier === 'critical' ? AGENT_COLORS.Fusion : g.risk_tier === 'high' ? AGENT_COLORS.Campaign : AGENT_COLORS.Response;
    lines.push({
      id: `rsp-${_lineCounter}`,
      agent: 'Response',
      text: `Risk tier: ${g.risk_tier.toUpperCase()}${g.requires_human_escalation ? ' ⚠ Human escalation required' : ''}`,
      timestamp: ts,
      color: tierColor,
    });

    if (g.blocked_actions && g.blocked_actions.length > 0) {
      _lineCounter++;
      lines.push({
        id: `rsp-${_lineCounter}`,
        agent: 'Response',
        text: `Blocked: ${g.blocked_actions.join(', ')}`,
        timestamp: ts,
        color: AGENT_COLORS.Response,
      });
    }

    if (g.allowed_actions && g.allowed_actions.length > 0) {
      _lineCounter++;
      lines.push({
        id: `rsp-${_lineCounter}`,
        agent: 'Response',
        text: `Allowed: ${g.allowed_actions.slice(0, 4).join(', ')}${g.allowed_actions.length > 4 ? ` +${g.allowed_actions.length - 4} more` : ''}`,
        timestamp: ts,
        color: AGENT_COLORS.Response,
      });
    }
  }

  return lines;
}

/* ── Derive lines from a StreamEvent ──────────────────── */

import type { StreamEvent } from '@/lib/ws';

export function deriveLinesFromStreamEvent(event: StreamEvent): FeedLine[] {
  const ts = new Date().toISOString();
  const lines: FeedLine[] = [];

  // Grab the first affected node
  const primaryNode = event.affected_nodes[0];
  if (!primaryNode) return lines;

  const label = primaryNode.node_id;

  // Behavioral: from scores
  if (primaryNode.scores) {
    const active = Object.entries(primaryNode.scores)
      .filter(([, v]) => v > 0)
      .sort(([, a], [, b]) => b - a);
    for (const [scorer, score] of active) {
      _lineCounter++;
      const name = SCORER_LABELS[scorer] || scorer;
      const pct = (score * 100).toFixed(1);
      lines.push({
        id: `str-beh-${_lineCounter}`,
        agent: 'Behavioral',
        text: `${name}: ${pct}% on ${label}`,
        timestamp: ts,
        value: score,
        color: AGENT_COLORS.Behavioral,
      });
    }
  }

  // Fusion
  if (primaryNode.fusion) {
    _lineCounter++;
    const f = primaryNode.fusion;
    const bel = (f.belief * 100).toFixed(1);
    const pl = (f.plausibility * 100).toFixed(1);
    const unc = (f.uncertainty * 100).toFixed(1);
    lines.push({
      id: `str-fus-${_lineCounter}`,
      agent: 'Fusion',
      text: `Fused: Belief ${bel}% · Plausibility ${pl}% · Uncertainty ${unc}% [${label}]`,
      timestamp: ts,
      value: f.belief,
      color: AGENT_COLORS.Fusion,
    });
  }

  // Campaign
  if (primaryNode.campaign) {
    _lineCounter++;
    const c = primaryNode.campaign;
    const prob = (c.dominant_probability * 100).toFixed(0);
    lines.push({
      id: `str-cmp-${_lineCounter}`,
      agent: 'Campaign',
      text: `Phase: ${c.dominant_phase} (${prob}%) on ${label}`,
      timestamp: ts,
      value: c.dominant_probability,
      color: AGENT_COLORS.Campaign,
    });
  }

  // Response gate
  if (primaryNode.gate) {
    _lineCounter++;
    const g = primaryNode.gate;
    lines.push({
      id: `str-rsp-${_lineCounter}`,
      agent: 'Response',
      text: `Gate: ${g.risk_tier.toUpperCase()} · Blocked: ${(g.blocked_actions || []).join(', ') || 'none'}`,
      timestamp: ts,
      color: AGENT_COLORS.Response,
    });
  }

  // Add the event description as a general line
  if (event.description) {
    _lineCounter++;
    lines.push({
      id: `str-ev-${_lineCounter}`,
      agent: 'Campaign',
      text: `Event: ${event.description}`,
      timestamp: ts,
      color: AGENT_COLORS.Campaign,
    });
  }

  return lines;
}

/* ── FeedQueue: manages staggered reveal ──────────────── */

export class FeedQueue {
  private queue: FeedLine[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private onLine: (line: FeedLine) => void;
  private staggerMs: number;

  constructor(onLine: (line: FeedLine) => void, staggerMs = 600) {
    this.onLine = onLine;
    this.staggerMs = staggerMs;
  }

  /** Enqueue a batch of lines — they'll be revealed one at a time */
  enqueue(lines: FeedLine[]) {
    this.queue.push(...lines);
    if (!this.timer) this.drain();
  }

  clear() {
    this.queue = [];
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private drain() {
    if (this.queue.length === 0) {
      this.timer = null;
      return;
    }
    const line = this.queue.shift()!;
    this.onLine(line);
    // Use varying stagger between 500-700ms for a natural feel
    const jitter = Math.floor(Math.random() * 200) + 500;
    this.timer = setTimeout(() => this.drain(), jitter);
  }
}

/* ── Props ────────────────────────────────────────────── */

interface AgentActivityFeedProps {
  /** Array of fully revealed feed lines (from queue) */
  lines: FeedLine[];
  /** Max lines to keep visible */
  maxLines?: number;
  /** If true, show a collapsed/minimized state */
  minimized?: boolean;
  /** Toggle minimized */
  onToggleMinimize?: () => void;
  /** Optional title */
  title?: string;
  /** Extra class name */
  className?: string;
  /** Allow the feed to auto-expand when new lines arrive */
  autoExpand?: boolean;
}

/* ── Component ────────────────────────────────────────── */

export function AgentActivityFeed({
  lines,
  maxLines = 80,
  minimized = false,
  onToggleMinimize,
  title = 'Agent Activity Feed',
  className = '',
  autoExpand = false,
}: AgentActivityFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [justAnimated, setJustAnimated] = useState(false);

  // Auto-scroll to top when new lines arrive (newest at top)
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
    // Flash effect for new lines
    setJustAnimated(true);
    const t = setTimeout(() => setJustAnimated(false), 400);
    return () => clearTimeout(t);
  }, [lines.length]);

  const displayedLines = useMemo(
    () => lines.slice(0, maxLines),
    [lines, maxLines],
  );

  return (
    <div
      className={`flex flex-col overflow-hidden transition-all duration-300 ${className}`}
      style={{
        background: 'rgba(10, 14, 23, 0.85)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 10,
        fontFamily: 'var(--font-mono)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2 cursor-pointer select-none"
        style={{
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          background: 'rgba(255,255,255,0.02)',
        }}
        onClick={onToggleMinimize}
      >
        <div className="flex items-center gap-2">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{
              background: lines.length > 0 ? '#34D399' : '#8993A8',
              boxShadow: lines.length > 0 ? '0 0 6px rgba(52,211,153,0.5)' : 'none',
              animation: lines.length > 0 ? 'breathe-fast 1s ease-in-out infinite' : 'none',
            }}
          />
          <span
            className="text-[0.6rem] font-bold uppercase tracking-wider"
            style={{ color: '#E7EBF5' }}
          >
            {title}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="text-[0.5rem] px-1.5 py-0.5 rounded"
            style={{
              background: 'rgba(255,255,255,0.06)',
              color: '#8993A8',
            }}
          >
            {lines.length}
          </span>
          <span className="text-xs" style={{ color: '#8993A8' }}>
            {minimized ? '▸' : '▾'}
          </span>
        </div>
      </div>

      {/* Body */}
      {!minimized && (
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto px-2 py-1.5"
          style={{
            maxHeight: 'inherit',
            scrollBehavior: 'smooth',
          }}
        >
          {displayedLines.length === 0 ? (
            <div
              className="flex items-center justify-center py-6 text-[0.55rem] italic"
              style={{ color: '#8993A8' }}
            >
              Waiting for agent activity...
            </div>
          ) : (
            <div className="flex flex-col-reverse gap-0.5">
              {displayedLines.map((line, idx) => (
                <FeedLineRow key={line.id} line={line} isNew={idx === 0} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Single feed line with typewriter/fade effect ─────── */

function FeedLineRow({ line, isNew }: { line: FeedLine; isNew: boolean }) {
  const [visible, setVisible] = useState(!isNew);
  const [typedText, setTypedText] = useState(isNew ? '' : line.text);

  useEffect(() => {
    if (!isNew) {
      setVisible(true);
      setTypedText(line.text);
      return;
    }

    // Fade in
    setVisible(false);
    const fadeTimer = setTimeout(() => {
      setVisible(true);
    }, 50);

    // Typewriter effect on the new line
    let idx = 0;
    setTypedText('');
    const typeTimer = setInterval(() => {
      idx++;
      setTypedText(line.text.slice(0, idx));
      if (idx >= line.text.length) {
        clearInterval(typeTimer);
      }
    }, 12);

    return () => {
      clearTimeout(fadeTimer);
      clearInterval(typeTimer);
    };
  }, [line.text, isNew]);

  const agentColor = line.color || AGENT_COLORS[line.agent];

  return (
    <div
      className="flex items-start gap-1.5 py-0.5 transition-all duration-300"
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateX(0)' : 'translateX(-8px)',
      }}
    >
      {/* Agent badge */}
      <span
        className="shrink-0 text-[0.5rem] font-bold uppercase tracking-wider px-1 py-0.5 rounded mt-[1px]"
        style={{
          background: `${agentColor}18`,
          color: agentColor,
          border: `1px solid ${agentColor}30`,
          lineHeight: 1.2,
        }}
      >
        {line.agent}
      </span>

      {/* Message */}
      <span
        className="text-[0.6rem] leading-snug break-words min-w-0"
        style={{ color: '#C8CCD8' }}
      >
        {typedText}
        {isNew && typedText.length < line.text.length && (
          <span className="animate-pulse" style={{ color: agentColor }}>▊</span>
        )}
      </span>

      {/* Mini bar for values */}
      {line.value !== undefined && (
        <span
          className="shrink-0 ml-auto w-10 h-1 rounded-full self-center"
          style={{
            background: 'rgba(255,255,255,0.06)',
          }}
        >
          <span
            className="block h-full rounded-full transition-all duration-500"
            style={{
              width: `${Math.min(line.value * 100, 100)}%`,
              background: agentColor,
              boxShadow: `0 0 4px ${agentColor}40`,
            }}
          />
        </span>
      )}
    </div>
  );
}
