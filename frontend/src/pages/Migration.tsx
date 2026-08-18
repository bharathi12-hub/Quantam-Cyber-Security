import { useEffect, useState } from "react";
import {
  CalendarDays,
  Gauge,
  GitPullRequestArrow,
  Network,
  Route,
  ShieldCheck,
  Timer,
  TrendingDown,
  Undo2,
  Users,
} from "lucide-react";
import { api, type MigrationPlan, type SimulationPlan } from "../lib/api";
import { Card, CardHeader, EmptyState, ErrorState, Loading, StatCard } from "../components/primitives";

const PHASE_COLOR = ["#6366f1", "#dc2626", "#ea580c", "#0891b2"];

function complexityChip(c: string) {
  const m: Record<string, string> = {
    Low: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-300",
    Medium: "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300",
    High: "bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300",
  };
  return m[c] ?? "bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-300";
}

export default function Migration() {
  const [plan, setPlan] = useState<MigrationPlan | null>(null);
  const [sim, setSim] = useState<SimulationPlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.migrationPlan(), api.simulationPlan().catch(() => null)])
      .then(([p, s]) => {
        setPlan(p);
        setSim(s);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Loading label="Generating migration roadmap…" />;
  if (error) return <ErrorState message={error} />;
  if (!plan || plan.phases.length === 0)
    return <EmptyState title="No migration plan" body="Run a scan first — the roadmap is generated from real findings." />;

  const weeks = Math.max(plan.estimated_weeks, 1);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Estimated Timeline" value={`${plan.estimated_weeks} wk`} sub={`${plan.total_effort_days} person-days`} icon={<CalendarDays className="h-6 w-6" />} />
        <StatCard label="Team Size" value={plan.team_size} sub="engineers (assumed)" icon={<Users className="h-6 w-6" />} accent="text-sky-500" />
        <StatCard label="Risk Reduction" value={`${plan.total_risk_reduction}%`} sub="if fully executed" icon={<TrendingDown className="h-6 w-6" />} accent="text-emerald-500" />
        <StatCard label="Migration Phases" value={plan.phases.length} sub={`${plan.total_findings} findings`} icon={<Route className="h-6 w-6" />} />
      </div>

      {/* Timeline */}
      <Card>
        <CardHeader title="Migration Timeline" />
        <div className="space-y-3">
          <div className="flex text-[10px] text-slate-400">
            {Array.from({ length: weeks }, (_, i) => (
              <div key={i} className="flex-1 border-l border-slate-200/60 pl-1 dark:border-white/5">W{i + 1}</div>
            ))}
          </div>
          {plan.phases.map((ph, i) => {
            const left = ((ph.start_week - 1) / weeks) * 100;
            const width = ((ph.end_week - ph.start_week + 1) / weeks) * 100;
            return (
              <div key={ph.id} className="relative h-9">
                <div className="absolute inset-0 rounded bg-slate-100/60 dark:bg-white/[0.03]" />
                <div
                  className="absolute top-0 flex h-9 items-center justify-between rounded px-3 text-xs font-semibold text-white shadow"
                  style={{ left: `${left}%`, width: `${width}%`, backgroundColor: PHASE_COLOR[i % 4] }}
                  title={ph.name}
                >
                  <span className="truncate">P{ph.id} · {ph.name}</span>
                  <span className="ml-2 shrink-0 opacity-90">{ph.effort_days}d</span>
                </div>
              </div>
            );
          })}
        </div>
        <p className="mt-4 flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-xs text-amber-800 dark:bg-amber-500/10 dark:text-amber-200">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
          {plan.priority_note}
        </p>
      </Card>

      {sim && <SimulationSection sim={sim} />}

      {/* Phase detail cards */}
      <div className="space-y-4">
        {plan.phases.map((ph, i) => (
          <Card key={ph.id} className="animate-fade-in">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-bold text-white" style={{ backgroundColor: PHASE_COLOR[i % 4] }}>
                  {ph.id}
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 dark:text-white">{ph.name}</h3>
                  <p className="max-w-2xl text-sm text-slate-500 dark:text-slate-400">{ph.goal}</p>
                </div>
              </div>
              <span className={`chip ${complexityChip(ph.complexity)}`}>{ph.complexity} complexity</span>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Metric label="Findings" value={`${ph.findings}`} sub={`${ph.affected_files} files`} />
              <Metric label="Effort" value={`${ph.effort_days}d`} sub={`~${ph.duration_weeks} wk`} />
              <Metric label="Risk ↓" value={`${ph.risk_reduction}%`} sub="of total" />
              <Metric label="Compatibility" value={`${ph.compatibility_score}%`} sub="post-migration" />
            </div>

            {ph.targets.length > 0 && (
              <div className="mt-4">
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">Target algorithms</p>
                <div className="flex flex-wrap gap-2">
                  {ph.targets.map((t) => (
                    <span key={t.target} className="inline-flex items-center gap-1.5 rounded-lg border border-green-200 bg-green-50 px-2.5 py-1 text-xs font-medium text-green-700 dark:border-green-500/25 dark:bg-green-500/10 dark:text-green-300">
                      <GitPullRequestArrow className="h-3.5 w-3.5" />
                      {t.target} <span className="opacity-60">×{t.count}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-4 flex items-start gap-2 rounded-lg bg-slate-50 p-3 text-xs text-slate-600 dark:bg-white/[0.03] dark:text-slate-300">
              <Undo2 className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
              <span><span className="font-semibold">Rollback: </span>{ph.rollback}</span>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

function Metric({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded-lg bg-slate-50 p-3 dark:bg-white/[0.03]">
      <p className="text-xl font-bold text-slate-900 dark:text-white">{value}</p>
      <p className="text-xs text-slate-400">{label} · {sub}</p>
    </div>
  );
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function SimulationSection({ sim }: { sim: SimulationPlan }) {
  return (
    <Card>
      <CardHeader title="Impact Simulation (pre-migration)" />
      <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">{sim.summary}</p>

      {/* Before/after metric bars */}
      <div className="space-y-4">
        {sim.metrics.map((m) => {
          const ratio = m.before > 0 ? Math.min(1, m.before / m.after) : 0;
          return (
            <div key={m.name}>
              <div className="mb-1 flex items-center justify-between text-sm">
                <span className="font-medium text-slate-700 dark:text-slate-200">{m.name}</span>
                <span className="tabular-nums text-slate-500 dark:text-slate-400">
                  {fmtBytes(m.before)} → {fmtBytes(m.after)}{" "}
                  <span className="font-semibold text-orange-500">+{m.delta_pct}%</span>
                </span>
              </div>
              <div className="flex h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-white/10">
                <div className="h-full bg-slate-400/70" style={{ width: `${ratio * 100}%` }} title="before" />
                <div className="h-full bg-brand-500" style={{ width: `${(1 - ratio) * 100}%` }} title="after (added)" />
              </div>
              <p className="mt-1 text-xs text-slate-400">{m.note}</p>
            </div>
          );
        })}
      </div>

      {/* Impact tiles */}
      <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SimTile icon={<Network className="h-5 w-5" />} label="Bandwidth / handshake"
          value={`+${sim.bandwidth.per_handshake_delta_b} B`}
          sub={`~+${sim.bandwidth.projected_daily_increase_mb} MB/day`} accent="text-sky-500" />
        <SimTile icon={<Gauge className="h-5 w-5" />} label="Compatibility risk"
          value={`${sim.compatibility_risk}%`} sub="ecosystem support" accent="text-amber-500" />
        <SimTile icon={<Timer className="h-5 w-5" />} label="Downtime"
          value={sim.downtime.estimate.split("(")[0]} sub="with hybrid rollout" accent="text-emerald-500" />
        <SimTile icon={<Route className="h-5 w-5" />} label="API sites to update"
          value={`${sim.api_sites_to_update}`} sub="crypto call sites" accent="text-brand-500" />
      </div>

      <div className="mt-4 rounded-lg bg-slate-50 p-3 dark:bg-white/[0.03]">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Latency — {sim.latency.rating}</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-slate-500 dark:text-slate-400">
          {sim.latency.notes.map((n, i) => <li key={i}>{n}</li>)}
        </ul>
      </div>
    </Card>
  );
}

function SimTile({ icon, label, value, sub, accent }: { icon: React.ReactNode; label: string; value: string; sub: string; accent: string }) {
  return (
    <div className="rounded-lg border border-slate-200/70 bg-white/50 p-3 dark:border-white/10 dark:bg-white/[0.02]">
      <div className={accent}>{icon}</div>
      <p className="mt-1.5 text-lg font-bold text-slate-900 dark:text-white">{value}</p>
      <p className="text-xs text-slate-400">{label}</p>
      <p className="text-[11px] text-slate-400">{sub}</p>
    </div>
  );
}
