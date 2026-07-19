'use client';

import React, { useState } from 'react';

interface InfoTooltipProps {
  label: string;
}

export function InfoTooltip({ label }: InfoTooltipProps) {
  const [show, setShow] = useState(false);

  return (
    <div 
      className="relative inline-flex items-center ml-1"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
    >
      <span 
        className="inline-flex items-center justify-center w-3 h-3 rounded-full text-[0.55rem] cursor-help"
        style={{ 
          background: 'rgba(255,255,255,0.1)', 
          color: 'var(--color-text-muted)',
          fontFamily: 'var(--font-mono)'
        }}
      >
        ?
      </span>
      {show && (
        <div 
          className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-1.5 px-2 py-1 rounded w-max max-w-[200px]"
          style={{ 
            background: 'var(--color-bg-void)', 
            border: '1px solid var(--color-glass-border)',
            color: 'var(--color-text-primary)',
            fontSize: '0.65rem',
            fontFamily: 'var(--font-body)',
            boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
            whiteSpace: 'normal',
            textAlign: 'center'
          }}
        >
          {label}
        </div>
      )}
    </div>
  );
}
