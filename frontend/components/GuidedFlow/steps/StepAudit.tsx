'use client';

import { AuditTrailPanel } from '@/components/AuditTrail/AuditTrailPanel';
import { useDashboard } from '@/lib/store';

export function StepAudit() {
  const { selectedEntityId } = useDashboard();
  return <AuditTrailPanel entityId={selectedEntityId} embedded />;
}
