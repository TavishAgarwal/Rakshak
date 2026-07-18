const features = [
  {
    title: 'Living Graph',
    body: 'A real-time map of your IT and OT systems that visibly reacts as behavior changes — so a judge or analyst can see risk building before it becomes an incident, not just read about it after.',
  },
  {
    title: 'Evidence Fusion, Not Guesswork',
    body: 'Five independent signals — identity, network, threat intel, structural rarity, and attack-pattern match — are combined mathematically using Dempster-Shafer theory. Never one opaque score. Belief, plausibility, and uncertainty are all shown, so confidence is never overstated.',
  },
  {
    title: 'Safety-Gated Response',
    body: 'The system never takes an aggressive action on physical infrastructure alone. Every response is gated by mission criticality and asset type — active disruption to OT/physical systems is structurally blocked and always requires human sign-off.',
  },
  {
    title: 'Full Audit Trail',
    body: 'Every score, every fused decision, and every action taken is logged with its contributing evidence and timestamp — reviewable after the fact, not just claimed.',
  },
];

const steps = [
  {
    title: 'Detect',
    body: 'Behavior across users, devices, and physical systems is continuously scored against their own baseline — no reliance on known attack signatures.',
  },
  {
    title: 'Decide',
    body: "Independent signals are fused into a single, honest confidence picture, and matched against known attack progression patterns (MITRE ATT&CK) to predict what's likely next.",
  },
  {
    title: 'Respond',
    body: "The system recommends or executes only what's safe given the asset and mission criticality — keeping critical infrastructure running in a degraded mode wherever possible, instead of defaulting to shutdown.",
  },
];

function LaunchSimulationLink() {
  return (
    <a
      href="/dashboard"
      className="inline-flex min-h-12 items-center justify-center rounded-lg bg-[var(--color-accent-resilience)] px-5 py-3 text-sm font-bold text-slate-950 transition hover:bg-emerald-200 focus:outline-none focus:ring-2 focus:ring-[var(--color-accent-resilience)] focus:ring-offset-2 focus:ring-offset-[var(--color-bg-void)]"
    >
      Launch Simulation
    </a>
  );
}

function ShieldIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="h-9 w-9 text-[var(--color-accent-resilience)]">
      <path
        d="M12 3.2 19 6v5.2c0 4.5-2.8 7.9-7 9.6-4.2-1.7-7-5.1-7-9.6V6l7-2.8Z"
        fill="none"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <path d="M9 12.1 11.1 14l4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <p className="section-label mb-4">{children}</p>;
}

export default function HomePage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[var(--color-bg-void)] text-[var(--color-text-primary)]">
      <section className="relative mx-auto flex min-h-[92svh] max-w-7xl flex-col justify-center px-5 py-10 sm:px-8 lg:px-12">
        <div className="pointer-events-none absolute inset-0 opacity-55">
          <div className="absolute inset-0 bg-[linear-gradient(rgba(231,235,245,0.055)_1px,transparent_1px),linear-gradient(90deg,rgba(231,235,245,0.055)_1px,transparent_1px)] bg-[size:76px_76px]" />
        </div>

        <div className="relative grid items-center gap-12 lg:grid-cols-[1fr_0.86fr]">
          <div className="max-w-3xl">
            <div className="mb-8 flex items-center gap-4">
              <ShieldIcon />
              <div>
                <p className="font-display text-2xl font-bold tracking-normal text-cyan-50">RAKSHAK</p>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-[var(--color-text-muted)]">CNI Defense</p>
              </div>
            </div>

            <h1 className="font-display text-4xl font-bold leading-tight tracking-normal text-cyan-50 sm:text-6xl">
              Resilience over detection — for India&apos;s critical infrastructure
            </h1>
            <p className="mt-6 max-w-2xl text-base leading-8 text-white/68 sm:text-lg">
              Built for hospitals, power grids, and government systems still running on end-of-life infrastructure — where a breach isn&apos;t found for weeks, and every response has to be safe before it&apos;s fast.
            </p>
            <div className="mt-9">
              <LaunchSimulationLink />
            </div>
          </div>

          <div className="glass-panel p-5 shadow-2xl shadow-black/25">
            <div className="mb-5 flex items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div>
                <p className="section-label mb-1">Living Graph</p>
                <p className="text-sm text-white/58">IT/OT bridge risk view</p>
              </div>
              <span className="score-badge normal">Continuous</span>
            </div>
            <div className="relative min-h-[300px] overflow-hidden rounded-lg border border-white/10 bg-black/25">
              <div className="absolute left-[13%] top-[25%] h-3 w-3 rounded-full bg-[var(--color-accent-it)] shadow-[0_0_20px_rgba(91,141,239,0.75)] dynamic-node-glow" />
              <div className="absolute left-[31%] top-[57%] h-3 w-3 rounded-full bg-[var(--color-accent-it)] shadow-[0_0_20px_rgba(91,141,239,0.65)] dynamic-node-glow" />
              <div className="absolute left-[49%] top-[42%] h-4 w-4 rounded-full bg-[var(--color-accent-fusion)] shadow-[0_0_28px_rgba(226,63,107,0.85)] bridge-node-glow" />
              <div className="absolute right-[24%] top-[28%] h-3 w-3 rounded-full bg-[var(--color-accent-ot)] shadow-[0_0_20px_rgba(242,166,90,0.72)] dynamic-node-glow" />
              <div className="absolute right-[13%] top-[67%] h-3 w-3 rounded-full bg-[var(--color-accent-ot)] shadow-[0_0_20px_rgba(242,166,90,0.64)] dynamic-node-glow" />
              <div className="absolute left-[15%] top-[28%] h-px w-[36%] origin-left rotate-[28deg] bg-cyan-100/20" />
              <div className="absolute left-[33%] top-[59%] h-px w-[19%] origin-left -rotate-[26deg] bg-cyan-100/20" />
              <div className="absolute right-[25%] top-[31%] h-px w-[25%] origin-left rotate-[153deg] bg-amber-100/20" />
              <div className="absolute right-[14%] top-[68%] h-px w-[40%] origin-left rotate-[201deg] bg-amber-100/20" />
              <div className="absolute bottom-5 left-5 right-5 grid gap-2 text-xs font-mono text-white/55 sm:grid-cols-3">
                <span className="rounded border border-[var(--color-accent-it)]/25 bg-[var(--color-accent-it)]/10 px-3 py-2 text-[var(--color-accent-it)]">IT</span>
                <span className="rounded border border-[var(--color-accent-fusion)]/25 bg-[var(--color-accent-fusion)]/10 px-3 py-2 text-[var(--color-accent-fusion)]">IT_OT_BRIDGE</span>
                <span className="rounded border border-[var(--color-accent-ot)]/25 bg-[var(--color-accent-ot)]/10 px-3 py-2 text-[var(--color-accent-ot)]">OT</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-20 sm:px-8 lg:px-12">
        <SectionLabel>Why this exists</SectionLabel>
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr_1.1fr]">
          <div className="glass-panel-sm p-5">
            <p className="font-display text-3xl font-bold text-cyan-50">1.59M+</p>
            <p className="mt-3 text-sm leading-6 text-white/65">
              CERT-In handled 1.59M+ cybersecurity incidents in 2023 — a number that kept climbing through 2024-25.
            </p>
            <p className="mt-4 font-mono text-[0.68rem] uppercase tracking-[0.12em] text-white/38">Source: CERT-In 2023</p>
          </div>
          <div className="glass-panel-sm p-5">
            <p className="font-display text-3xl font-bold text-cyan-50">70%+</p>
            <p className="mt-3 text-sm leading-6 text-white/65">
              70%+ of government entities still run end-of-life IT infrastructure.
            </p>
            <p className="mt-4 font-mono text-[0.68rem] uppercase tracking-[0.12em] text-white/38">Source: PS7 context</p>
          </div>
          <div className="glass-panel-sm p-5">
            <p className="text-sm leading-7 text-white/70">
              Most breaches are found weeks or months after the intrusion — because attackers move slowly enough to look normal, one step at a time.
            </p>
            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/10 bg-black/20 p-4">
                <p className="font-mono text-xs uppercase tracking-[0.14em] text-white/42">Traditional SOC</p>
                <p className="mt-2 text-sm font-semibold text-white/72">days to weeks to detect</p>
              </div>
              <div className="rounded-lg border border-[var(--color-accent-resilience)]/25 bg-[var(--color-accent-resilience)]/10 p-4">
                <p className="font-mono text-xs uppercase tracking-[0.14em] text-[var(--color-accent-resilience)]">RAKSHAK</p>
                <p className="mt-2 text-sm font-semibold text-white/85">real-time, continuous scoring</p>
                <p className="mt-2 text-xs text-white/48">Measured MTTD: 0.17h</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-20 sm:px-8 lg:px-12">
        <SectionLabel>Core features</SectionLabel>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {features.map((feature) => (
            <article key={feature.title} className="glass-panel-sm p-5">
              <h2 className="font-display text-xl font-semibold tracking-normal text-cyan-50">{feature.title}</h2>
              <p className="mt-4 text-sm leading-7 text-white/62">{feature.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-20 sm:px-8 lg:px-12">
        <SectionLabel>How it works</SectionLabel>
        <div className="grid gap-4 lg:grid-cols-3">
          {steps.map((step, index) => (
            <article key={step.title} className="glass-panel p-6">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-[var(--color-accent-resilience)]">
                0{index + 1}
              </p>
              <h2 className="mt-4 font-display text-2xl font-semibold tracking-normal text-cyan-50">{step.title}</h2>
              <p className="mt-4 text-sm leading-7 text-white/64">{step.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-20 sm:px-8 lg:px-12">
        <div className="glass-panel grid gap-8 p-6 lg:grid-cols-[0.9fr_1.1fr] lg:p-8">
          <div>
            <SectionLabel>IT / OT distinction</SectionLabel>
            <p className="text-base leading-8 text-white/70">
              RAKSHAK treats IT systems (computers, servers, logins) and OT systems (physical equipment — PLCs, sensors, control systems) as fundamentally different, fusing them only at explicitly identified bridge points — because a login anomaly and a pressure sensor anomaly are not the same kind of risk, and shouldn&apos;t be scored as if they were.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-[1fr_auto_1fr] md:items-center">
            <div className="rounded-lg border border-[var(--color-accent-it)]/25 bg-[var(--color-accent-it)]/10 p-5">
              <p className="font-mono text-xs uppercase tracking-[0.16em] text-[var(--color-accent-it)]">IT systems</p>
              <div className="mt-5 space-y-3">
                {['computers', 'servers', 'logins'].map((item) => (
                  <p key={item} className="rounded border border-white/10 bg-black/20 px-3 py-2 text-sm text-white/68">
                    {item}
                  </p>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-center">
              <div className="rounded-lg border border-[var(--color-accent-fusion)]/30 bg-[var(--color-accent-fusion)]/10 px-4 py-3 text-center font-mono text-xs uppercase tracking-[0.14em] text-[var(--color-accent-fusion)]">
                bridge points
              </div>
            </div>
            <div className="rounded-lg border border-[var(--color-accent-ot)]/25 bg-[var(--color-accent-ot)]/10 p-5">
              <p className="font-mono text-xs uppercase tracking-[0.16em] text-[var(--color-accent-ot)]">OT systems</p>
              <div className="mt-5 space-y-3">
                {['PLCs', 'sensors', 'control systems'].map((item) => (
                  <p key={item} className="rounded border border-white/10 bg-black/20 px-3 py-2 text-sm text-white/68">
                    {item}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-14 sm:px-8 lg:px-12">
        <div className="border-y border-white/10 py-6 text-center">
          <p className="font-mono text-xs uppercase tracking-[0.16em] text-white/48">
            Built for ET AI Hackathon 2026 — Problem Statement 7: AI-Driven Cyber Resilience for Critical National Infrastructure.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-24 pt-16 text-center sm:px-8 lg:px-12">
        <p className="font-display text-3xl font-bold leading-tight tracking-normal text-cyan-50 sm:text-5xl">
          Resilience over detection — for India&apos;s critical infrastructure
        </p>
        <div className="mt-8">
          <LaunchSimulationLink />
        </div>
      </section>
    </main>
  );
}
