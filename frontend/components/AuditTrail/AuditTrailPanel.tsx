'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import { InfoTooltip } from '@/components/ui/InfoTooltip';
import { API_BASE, fetcher, type AuditEntry, type AuditVerificationResult } from '@/lib/api';

interface AuditTrailPanelProps {
  onClose?: () => void;
  entityId?: string | null;
  embedded?: boolean;
}

export function AuditTrailPanel({ onClose, entityId, embedded = false }: AuditTrailPanelProps) {
  const url = entityId ? `${API_BASE}/api/audit?entity_id=${encodeURIComponent(entityId)}` : `${API_BASE}/api/audit`;
  const { data, error } = useSWR<{ entries: AuditEntry[] }>(
    url,
    fetcher,
    embedded ? { refreshInterval: 5000 } : undefined
  );

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<AuditVerificationResult | null>(null);

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/audit/verify`);
      const result: AuditVerificationResult = await res.json();
      setVerifyResult(result);
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'Verification request failed';
      setVerifyResult({ valid: false, invalid_at_index: null, reason });
    } finally {
      setVerifying(false);
    }
  };

  const content = (
    <div className={`glass-panel w-full ${embedded ? 'max-w-5xl h-[80vh] min-h-[500px]' : 'max-w-5xl h-[85vh]'} flex flex-col overflow-hidden relative shadow-2xl border border-white/10`} style={{ background: 'var(--color-bg-void)' }}>
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 border-b border-white/5 bg-white/5">
          <div className="flex items-center gap-3 min-w-0">
            <h2 className="text-sm sm:text-lg font-display tracking-wider text-white truncate">CRYPTOGRAPHIC AUDIT TRAIL {entityId && `- ${entityId}`}</h2>
            <InfoTooltip label="Append-only hash-chained ledger of all automated response decisions." />
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleVerify}
              disabled={verifying}
              className={`px-3 sm:px-4 py-1.5 rounded text-[0.65rem] sm:text-xs font-mono transition-colors flex items-center gap-2 ${
                verifyResult?.valid 
                  ? 'bg-[var(--color-accent-resilience)]/20 text-[var(--color-accent-resilience)] border border-[var(--color-accent-resilience)]/30'
                  : verifyResult?.valid === false
                  ? 'bg-[var(--color-accent-fusion)]/20 text-[var(--color-accent-fusion)] border border-[var(--color-accent-fusion)]/30'
                  : 'bg-white/5 text-white/70 hover:bg-white/10 hover:text-white border border-white/10'
              }`}
            >
              {verifying ? 'VERIFYING...' : 'VERIFY CHAIN INTEGRITY'}
            </button>
            {onClose && <button onClick={onClose} className="text-white/50 hover:text-white p-1">x</button>}
          </div>
        </div>

        {/* Verify Banner */}
        {verifyResult && (
          <div className={`p-3 text-xs font-mono text-center flex items-center justify-center gap-2 ${verifyResult.valid ? 'bg-[var(--color-accent-resilience)]/10 text-[var(--color-accent-resilience)]' : 'bg-[var(--color-accent-fusion)]/10 text-[var(--color-accent-fusion)]'}`}>
            {verifyResult.valid ? (
              <>
                <span className="w-2 h-2 rounded-full bg-[var(--color-accent-resilience)] shadow-[0_0_8px_var(--color-accent-resilience)]"></span>
                CHAIN INTEGRITY VERIFIED. {verifyResult.total_verified} BLOCKS SECURE.
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-[var(--color-accent-fusion)] shadow-[0_0_8px_var(--color-accent-fusion)]"></span>
                COMPROMISE DETECTED: {verifyResult.reason} AT INDEX {verifyResult.invalid_at_index}
              </>
            )}
          </div>
        )}

        {/* Table Body */}
        <div className="flex-1 overflow-y-auto p-4">
          {error ? (
            <div className="text-center text-[var(--color-accent-fusion)] mt-10 font-mono text-sm">Failed to load audit trail.</div>
          ) : !data ? (
            <div className="text-center text-white/40 mt-10 font-mono text-sm animate-pulse">Loading ledger...</div>
          ) : data.entries.length === 0 ? (
            <div className="text-center text-white/40 mt-10 font-mono text-sm">Ledger is empty. No automated actions have been taken.</div>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="grid grid-cols-[110px_1fr_120px] sm:grid-cols-[160px_1fr_180px_160px_100px] gap-3 sm:gap-4 px-3 py-2 text-[0.65rem] font-mono text-white/40 uppercase tracking-widest border-b border-white/5">
                <div>Timestamp</div>
                <div>Entity ID</div>
                <div>Action Taken</div>
                <div className="hidden sm:block">Hash</div>
                <div className="hidden sm:block text-right">Approval</div>
              </div>
              
              {data.entries.map((entry) => {
                const isExpanded = expandedId === entry.decision_id;
                const isAuto = entry.human_approval.approved_by === 'auto_executed';
                
                return (
                  <div key={entry.decision_id} className="flex flex-col bg-white/5 rounded overflow-hidden border border-white/5 hover:border-white/10 transition-colors">
                    <div 
                      className="grid grid-cols-[110px_1fr_120px] sm:grid-cols-[160px_1fr_180px_160px_100px] gap-3 sm:gap-4 px-3 py-3 items-center cursor-pointer"
                      onClick={() => setExpandedId(isExpanded ? null : entry.decision_id)}
                    >
                      <div className="text-[0.65rem] text-white/70 font-mono whitespace-nowrap">
                        {new Date(entry.timestamp).toLocaleString(undefined, {
                          hour12: false,
                          month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
                        })}
                      </div>
                      <div className="text-[0.7rem] text-white font-medium truncate" title={entry.entity_id}>{entry.entity_id}</div>
                      <div className="text-[0.7rem] text-[var(--color-accent-it)] font-mono truncate">{entry.action_taken}</div>
                      <div className="hidden sm:block text-[0.65rem] text-white/40 font-mono truncate" title={entry.hash}>
                        {entry.hash.substring(0, 16)}...
                      </div>
                      <div className="hidden sm:flex text-right justify-end">
                        <span className={`text-[0.55rem] px-1.5 py-0.5 rounded font-mono ${isAuto ? 'bg-[var(--color-accent-it)]/10 text-[var(--color-accent-it)]' : 'bg-[var(--color-warning)]/10 text-[var(--color-warning)]'}`}>
                          {isAuto ? 'AUTO' : 'HUMAN'}
                        </span>
                      </div>
                    </div>
                    
                    {isExpanded && (
                      <div className="px-3 pb-3 pt-2 bg-black/40 border-t border-white/5 text-[0.65rem] font-mono flex flex-col gap-3">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <span className="text-white/40 mb-1 block" title="Dempster-Shafer Data Fusion (Belief/Plausibility/Uncertainty)">Evidence Sources (Dempster-Shafer Fusion)</span>
                            {entry.evidence_sources && entry.evidence_sources.length > 0 ? entry.evidence_sources.map((s, i) => (
                              <div key={i} className="flex justify-between border-b border-white/5 py-1">
                                <span className="text-[var(--color-accent-it)]">{s.source}</span>
                                <span className="text-white/70">{(s.weight * 100).toFixed(1)}%</span>
                              </div>
                            )) : <div className="text-white/30 italic py-1">No sources</div>}
                          </div>
                          <div>
                            <span className="text-white/40 mb-1 block">Alternatives Considered</span>
                            {entry.alternatives_considered && entry.alternatives_considered.length > 0 ? entry.alternatives_considered.map((alt, i) => (
                              <div key={i} className="text-white/70 border-b border-white/5 py-1 truncate" title={alt}>- {alt}</div>
                            )) : <div className="text-white/30 italic py-1">None rejected</div>}
                          </div>
                        </div>
                        {entry.metadata && (
                          <div className="mt-2 pt-2 border-t border-white/5">
                            <span className="text-white/40 mb-1 block uppercase tracking-wider">Event Metadata</span>
                            <div className="grid grid-cols-2 gap-2 text-[0.6rem] text-white/60">
                              {Object.entries(entry.metadata).map(([key, value]) => {
                                if (typeof value === 'object' && value !== null) {
                                  return (
                                    <div key={key} className="col-span-2">
                                      <span className="text-cyan-200/50">{key}:</span> 
                                      <pre className="inline-block ml-1 align-top">{JSON.stringify(value)}</pre>
                                    </div>
                                  );
                                }
                                return (
                                  <div key={key} className="truncate" title={String(value)}>
                                    <span className="text-cyan-200/50">{key}:</span> {String(value)}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                        <div className="pt-2 mt-2 border-t border-white/5 flex flex-wrap gap-4 text-white/40">
                          <div><span className="uppercase mr-1">Decision ID:</span> {entry.decision_id}</div>
                          <div><span className="uppercase mr-1">Previous Hash:</span> <span className="truncate w-32 inline-block align-bottom">{entry.previous_hash.substring(0,16)}...</span></div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
  );

  if (embedded) {
    return <div className="w-full h-full flex flex-col items-center justify-center p-4">{content}</div>;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/60 backdrop-blur-sm">
      {content}
    </div>
  );
}
