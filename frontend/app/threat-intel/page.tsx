import { redirect } from 'next/navigation';

export default function ThreatIntelPage() {
  redirect('/dashboard?view=intel');
}
