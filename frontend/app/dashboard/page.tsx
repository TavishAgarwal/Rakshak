import { GuidedFlow } from '@/components/GuidedFlow/GuidedFlow';
import { DashboardProvider } from '@/lib/store';

export default function DashboardPage() {
  return (
    <DashboardProvider>
      <GuidedFlow />
    </DashboardProvider>
  );
}
