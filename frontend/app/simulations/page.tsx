import { redirect } from 'next/navigation';

export default function SimulationsPage() {
  redirect('/dashboard?view=simulation');
}
