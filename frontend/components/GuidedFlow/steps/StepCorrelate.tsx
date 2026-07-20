'use client';

import React from 'react';
import { ResilienceSignalsPanel } from '@/components/ResilienceSignals/ResilienceSignalsPanel';

export function StepCorrelate() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-lg h-[80vh] min-h-[500px]">
        <ResilienceSignalsPanel />
      </div>
    </div>
  );
}
