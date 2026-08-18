import { useEffect, useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight, ShieldX, TriangleAlert } from "lucide-react";
import { api, type CompliancePlan, type ComplianceFramework } from "../lib/api";
import { Card, CardHeader, EmptyState, ErrorState, Loading, SeverityBadge, StatCard } from "../components/primitives";

const STATUS: Record<string, { color: string; chip: string; icon: any }> = {
  Pass: { color: "#16a34a", chip: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-300", icon: CheckCircle2 },
  Partial: { color: "#d97706", chip: "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300", icon: TriangleAlert },
  Fail: { color: "#dc2626", chip: "bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300", icon: ShieldX },
};

export default function Compliance() {
  const [plan, setPlan] = useState<CompliancePlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    api.compliancePlan().then(setPlan).catch((e) => setError((e as Error).message)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Loading label="Mapping findings to compliance controls…" />;
  if (error) return <ErrorState message={error} />;
  if (!plan || plan.total_findings === 0)
    return <EmptyState title="No compliance data" body="Run a scan first — compliance posture is derived from findings." />;

  const o = plan.overall;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Frameworks" value={plan.frameworks.length} />
        <StatCard label="Passing" value={o.passed} accent="text-emerald-500" icon={<CheckCircle2 className="h-6 w-6" />} />
        <StatCard label="Partial" value={o.partial} accent="text-amber-500" icon={<TriangleAlert className="h-6 w-6" />} />
        <StatCard label="Failing" value={o.failed} accent="text-red-500" icon={<ShieldX className="h-6 w-6" />} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {plan.frameworks.map((fw) => (
          <FrameworkCard key={fw.name} fw={fw} open={open === fw.name} onToggle={() => setOpen(open === fw.name ? null : fw.name)} />
        ))}
      </div>
    </div>
  );
}

function FrameworkCard({ fw, open, onToggle }: { fw: ComplianceFramework; open: boolean; onToggle: () => void }) {
  const st = STATUS[fw.status] ?? STATUS.Fail;
  return (
    <Card className="animate-fade-in">
      <button className="flex w-full items-start justify-between text-left" onClick={onToggle}>
        <div className="flex items-start gap-3">
          <st.icon className="mt-0.5 h-5 w-5" style={{ color: st.color }} />
          <div>
            <h3 className="font-bold text-slate-900 dark:text-white">{fw.name}</h3>
            <p className="text-xs text-slate-400">
              {fw.controls_impacted} control(s) impacted · {fw.findings} finding(s)
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-2xl font-bold" style={{ color: st.color }}>{fw.score}</p>
            <span className={`chip ${st.chip}`}>{fw.status}</span>
          </div>
          {fw.controls.length > 0 && (open ? <ChevronDown className="mt-1 h-4 w-4 text-slate-400" /> : <ChevronRight className="mt-1 h-4 w-4 text-slate-400" />)}
        </div>
      </button>

      {/* score bar */}
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-white/10">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${fw.score}%`, backgroundColor: st.color }} />
      </div>

      {open && fw.controls.length > 0 && (
        <div className="mt-4 space-y-2 border-t border-slate-100 pt-3 dark:border-white/10">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Impacted controls</p>
          {fw.controls.map((c) => (
            <div key={c.id} className="flex items-center justify-between gap-3 text-sm">
              <div className="min-w-0">
                <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-200">{c.id}</span>
                <span className="ml-2 text-slate-500 dark:text-slate-400">{c.title}</span>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <span className="text-xs tabular-nums text-slate-400">{c.findings}</span>
                <SeverityBadge severity={c.severity} />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
