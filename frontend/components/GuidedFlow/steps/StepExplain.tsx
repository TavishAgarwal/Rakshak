'use client';

import React from 'react';
import { InspectorPanel } from '@/components/EntityInspector/InspectorPanel';

export function StepExplain() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-lg h-[80vh] min-h-[500px]">
        <InspectorPanel />
      </div>
    </div>
  );
}
