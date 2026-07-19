'use client';

import React, { useEffect, useRef, useState } from 'react';
import { useDashboard } from '@/lib/store';

export function NarrationBanner() {
  const { latestNarration, streamActive } = useDashboard();
  const [tickerVisible, setTickerVisible] = useState(true);
  const tickerRef = useRef<HTMLDivElement>(null);

  const text = latestNarration?.trim()
    ? latestNarration
    : 'Monitoring — no active narration';

  // Re-trigger animation on text change by briefly toggling visibility
  useEffect(() => {
    setTickerVisible(false);
    const t = setTimeout(() => setTickerVisible(true), 50);
    return () => clearTimeout(t);
  }, [text]);

  // Auto-scroll ticker: scroll text horizontally if too long
  useEffect(() => {
    const el = tickerRef.current;
    if (!el || !tickerVisible) return;

    const textWidth = el.scrollWidth;
    const containerWidth = el.clientWidth;

    // Only scroll if text overflows
    if (textWidth <= containerWidth) return;

    let pos = containerWidth;
    let raf: number;
    const step = () => {
      pos -= 0.5;
      if (pos < -textWidth) pos = containerWidth;
      el.style.transform = `translateX(${pos}px)`;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [text, tickerVisible]);

  return (
    <div className="w-full glass-panel-sm overflow-hidden relative" style={{ height: '28px' }}>
      {/* Glowing dot */}
      <div className="absolute left-2 top-1/2 -translate-y-1/2 z-10 flex items-center gap-2">
        <span
          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{
            background: streamActive
              ? 'var(--color-accent-fusion)'
              : 'var(--color-accent-resilience)',
            boxShadow: streamActive
              ? '0 0 6px rgba(226,63,107,0.6)'
              : '0 0 6px rgba(52,211,153,0.4)',
          }}
        />
      </div>

      {/* Ticker content */}
      <div className="flex items-center h-full ml-6 pr-4 overflow-hidden">
        <div
          ref={tickerRef}
          className="text-[0.65rem] whitespace-nowrap transition-opacity duration-200"
          style={{
            color: streamActive
              ? 'var(--color-text-primary)'
              : 'var(--color-text-muted)',
            fontFamily: 'var(--font-mono)',
            opacity: tickerVisible ? 1 : 0,
          }}
        >
          {streamActive ? (
            <span className="flex items-center gap-2">
              <span className="text-[0.55rem] uppercase tracking-wider" style={{ color: 'var(--color-accent-fusion)' }}>
                [NARRATION]
              </span>
              {text}
            </span>
          ) : text === 'Monitoring — no active narration' ? (
            <span>{text}</span>
          ) : (
            <span>{text}</span>
          )}
        </div>
      </div>

      {/* Fade-out on right */}
      <div
        className="absolute right-0 top-0 bottom-0 w-8 pointer-events-none"
        style={{
          background: 'linear-gradient(to right, transparent, var(--color-bg-void))',
        }}
      />
    </div>
  );
}
