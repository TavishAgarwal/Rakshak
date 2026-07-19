'use client';

import React, { useState, useCallback } from 'react';
import { useDashboard } from '@/lib/store';
import { fetchQuery, type QueryResult } from '@/lib/api';

/**
 * AIQueryBar — docked glass pill under the Living Graph.
 *
 * Response renders as a narration card (not a chat thread).
 * The LLM receives real structured evidence — never invents one.
 */
export function AIQueryBar() {
  const { selectedEntityId, setLatestNarration } = useDashboard();
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async (event?: React.FormEvent) => {
    event?.preventDefault();
    if (!query.trim() || !selectedEntityId) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetchQuery(selectedEntityId, query.trim());
      setResult(res);
      setLatestNarration(res.narration);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  }, [query, selectedEntityId, setLatestNarration]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  }, [handleSubmit]);

  const handleDismiss = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  return (
    <div className="mt-3 relative z-50">
      {/* Narration card — shown above the input when result exists */}
      {(result || error) && (
        <div className="mb-3 glass-panel p-4 relative" style={{ borderRadius: '12px' }}>
          {/* Dismiss button */}
          <button
            onClick={handleDismiss}
            className="absolute top-2 right-2 text-xs cursor-pointer"
            style={{ color: 'var(--color-text-muted)', opacity: 0.6 }}
          >
            ✕
          </button>

          {error && !result && (
            <div className="text-sm" style={{ color: 'var(--color-accent-fusion)' }}>
              {error}
            </div>
          )}

          {result && (
            <>
              {/* Header */}
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[0.6rem] px-1.5 py-0.5 rounded" style={{
                  background: 'rgba(91, 141, 239, 0.12)',
                  color: 'var(--color-accent-it)',
                  fontFamily: 'var(--font-mono)',
                }}>
                  AI Narration
                </span>
                <span className="text-[0.55rem]" style={{
                  color: 'var(--color-text-muted)',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {result.node_id}
                </span>
                <span className="text-[0.5rem] ml-auto" style={{
                  color: 'var(--color-text-muted)',
                  fontFamily: 'var(--font-mono)',
                  opacity: 0.6,
                }}>
                  {result.model} · {result.tokens_used} tokens
                </span>
              </div>

              {/* Narration body */}
              <div
                className="text-sm leading-relaxed narration-content"
                style={{
                  color: 'var(--color-text-primary)',
                  fontFamily: 'var(--font-body)',
                }}
              >
                {renderNarration(result.narration)}
              </div>

              {/* Error badge */}
              {result.error && (
                <div className="mt-2 text-[0.55rem] px-2 py-1 rounded" style={{
                  background: 'rgba(242, 166, 90, 0.1)',
                  color: 'var(--color-accent-ot)',
                  fontFamily: 'var(--font-mono)',
                }}>
                  ⚠ {result.error} — using fallback narration
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Input pill */}
      <form
        onSubmit={handleSubmit}
        className="glass-panel-sm flex items-center gap-2 px-4 py-2.5"
        style={{ borderRadius: '24px' }}
      >
        {/* Search icon */}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-text-muted)" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <path d="M21 21l-4.35-4.35" />
        </svg>

        {/* Input */}
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            selectedEntityId
              ? `Ask RAKSHAK about ${selectedEntityId}...`
              : 'Select a node first, then ask RAKSHAK...'
          }
          disabled={!selectedEntityId || loading}
          className="flex-1 bg-transparent border-none outline-none text-sm"
          style={{
            color: 'var(--color-text-primary)',
            fontFamily: 'var(--font-body)',
            opacity: selectedEntityId ? 1 : 0.5,
          }}
        />

        {/* Loading spinner or submit */}
        {loading ? (
          <span className="text-[0.6rem] animate-pulse" style={{
            color: 'var(--color-accent-it)',
            fontFamily: 'var(--font-mono)',
          }}>
            Narrating...
          </span>
        ) : (
          <button
            type="submit"
            disabled={!selectedEntityId || !query.trim()}
            className="min-h-8 min-w-12 text-[0.65rem] px-3 py-1.5 rounded cursor-pointer transition-all duration-200 disabled:cursor-not-allowed"
            style={{
              background: selectedEntityId && query.trim()
                ? 'rgba(91, 141, 239, 0.15)'
                : 'rgba(91, 141, 239, 0.05)',
              color: selectedEntityId && query.trim()
                ? 'var(--color-accent-it)'
                : 'var(--color-text-muted)',
              fontFamily: 'var(--font-mono)',
            }}
          >
            AI
          </button>
        )}
      </form>
    </div>
  );
}

/* ── Render narration markdown-lite without injecting HTML ───────────────────── */

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*.+?\*\*)/g);
  return parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    return <React.Fragment key={index}>{part}</React.Fragment>;
  });
}

function renderNarration(text: string): React.ReactNode[] {
  const lines = text.split('\n');
  return lines.flatMap((line, index) => {
    const renderedLine = (
      <React.Fragment key={`line-${index}`}>
        {renderInlineMarkdown(line)}
      </React.Fragment>
    );

    if (index === lines.length - 1) {
      return [renderedLine];
    }
    return [renderedLine, <br key={`br-${index}`} />];
  });
}
