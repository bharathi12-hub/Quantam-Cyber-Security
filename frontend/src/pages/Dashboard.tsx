import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Atom,
  Boxes,
  FileWarning,
  Files,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api, type Dashboard as DashboardData, type DependencyReport } from "../lib/api";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Loading,
  SeverityBadge,
  StatCard,
} from "../components/primitives";
import { RiskGauge } from "../components/RiskGauge";
import { BarsChart, DonutChart, RankedBars } from "../components/charts";
import { SEVERITY_HEX, THREAT_DESC, THREAT_HEX, THREAT_LABEL, timeAgo, toEntries } from "../lib/ui";
import type { QuantumThreat } from "../lib/api";

const THREAT_COLOR: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Elevated: "#d97706",
  Guarded: "#0ea5e9",
  Low: "#16a34a",
};

function RadialTile({ label, value, color, suffix = "/100" }: { label: string; value: number; color: string; suffix?: string }) {
  const r = 34;
  const circ = 2 * Math.PI * r;
  const off = circ * (1 - Math.min(100, Math.max(0, value)) / 100);
  return (
    <div className="card flex items-center gap-4 p-5">
      <svg viewBox="0 0 84 84" className="h-20 w-20 -rotate-90">
        <circle cx="42" cy="42" r={r} fill="none" strokeWidth="8" className="stroke-slate-200 dark:stroke-white/10" />
        <circle
          cx="42"
          cy="42"
          r={r}
          fill="none"
          strokeWidth="8"
          stroke={color}
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={off}
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
      </svg>
      <div>
        <p className="text-2xl font-bold text-slate-900 dark:text-white">
          {value}
          <span className="text-sm text-slate-400">{suffix}</span>
        </p>
        <p className="card-title mt-0.5">{label}</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [dep, setDep] = useState<DependencyReport | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [d, deps] = await Promise.all([api.dashboard(), api.dependencyReports().catch(() => [])]);
      setData(d);
      setDep((deps as DependencyReport[])[0] ?? null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const runDemo = async () => {
    setRunning(true);
    try {
      await api.runDemo();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  if (loading) return <Loading label="Loading executive dashboard…" />;
  if (error) return <ErrorState message={error} />;
  if (!data || data.scans === 0)
    return (
      <EmptyState
        title="No scans yet"
        body={
          <div className="flex flex-col items-center gap-4">
            <span>Run a scan of the bundled sample application to populate the dashboard with real findings.</span>
            <button className="btn-primary" onClick={runDemo} disabled={running}>
              <Play className="h-4 w-4" /> {running ? "Scanning…" : "Run demo scan"}
            </button>
          </div>
        }
      />
    );

  const p = data.posture;
  const certs = data.certificates;
  const severityData = (["Critical", "High", "Medium", "Low"] as const)
    .map((k) => ({ name: k, value: p.by_severity[k] }))
    .filter((d) => d.value > 0);
  const algoData = toEntries(p.by_algorithm).slice(0, 8);
  const targetData = toEntries(p.recommended_targets);
  const langData = toEntries(p.by_language);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <button className="btn-ghost" onClick={load}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Findings" value={p.total_findings} sub={`across ${data.projects} project(s)`} icon={<FileWarning className="h-7 w-7" />} />
        <StatCard label="Quantum-Vulnerable" value={p.quantum_vulnerable} sub={`${p.quantum_vulnerable_pct}% broken by Shor`} icon={<Atom className="h-7 w-7" />} accent="text-red-500" />
        <StatCard label="Critical Issues" value={p.by_severity.Critical} sub={`${p.by_severity.High} high severity`} icon={<ShieldAlert className="h-7 w-7" />} accent="text-orange-500" />
        <StatCard label="Files Scanned" value={data.recent_scans.reduce((s, x) => s + x.files_scanned, 0)} sub={`${data.scans} scan(s) total`} icon={<Files className="h-7 w-7" />} accent="text-sky-500" />
      </div>

      {/* Enterprise scores */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <RadialTile label="Quantum Readiness" value={p.quantum_readiness} color={p.quantum_readiness >= 60 ? "#16a34a" : p.quantum_readiness >= 30 ? "#d97706" : "#dc2626"} />
        <RadialTile label="Compliance Score" value={p.compliance_score} color={p.compliance_score >= 60 ? "#16a34a" : p.compliance_score >= 30 ? "#d97706" : "#dc2626"} />
        <RadialTile label="Migration Effort" value={p.migration_effort} color="#6366f1" />
        <div className="card flex flex-col justify-center p-5">
          <p className="card-title">Threat Level</p>
          <p className="mt-1 text-3xl font-bold" style={{ color: THREAT_COLOR[p.threat_level] ?? "#64748b" }}>
            {p.threat_level}
          </p>
          <p className="mt-1 text-sm text-slate-400">Detection confidence {p.confidence}%</p>
        </div>
      </div>

      {/* Posture row */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card>
          <CardHeader title="Quantum Risk Posture" />
          <RiskGauge score={p.risk_score} grade={p.grade} />
        </Card>
        <Card>
          <CardHeader title="Findings by Severity" />
          <DonutChart data={severityData} colors={severityData.map((d) => SEVERITY_HEX[d.name as keyof typeof SEVERITY_HEX])} centerLabel="findings" />
        </Card>
        <Card>
          <CardHeader title="Quantum Threat Exposure" />
          <div className="space-y-4 pt-2">
            {(["shor", "grover", "classical"] as QuantumThreat[]).map((t) => {
              const count = p.by_quantum_threat[t];
              const pct = p.total_findings ? Math.round((100 * count) / p.total_findings) : 0;
              return (
                <div key={t}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="font-medium text-slate-700 dark:text-slate-200">{THREAT_LABEL[t]}</span>
                    <span className="tabular-nums text-slate-500 dark:text-slate-400">{count} · {pct}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-white/10">
                    <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: THREAT_HEX[t] }} />
                  </div>
                  <p className="mt-1 text-xs leading-snug text-slate-400">{THREAT_DESC[t]}</p>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* Distribution row */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title="Vulnerable Algorithms Detected" />
          <BarsChart data={algoData} />
        </Card>
        <Card>
          <CardHeader title="Recommended PQC / Hardened Targets" />
          <RankedBars data={targetData} color="#16a34a" />
        </Card>
      </div>

      {/* Asset summary row */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Card className="card-hover">
          <CardHeader title="Certificate Intelligence" action={<Link to="/certificates" className="text-xs font-semibold text-brand-500 hover:underline">Open →</Link>} />
          <div className="grid grid-cols-2 gap-3">
            <Mini label="Certificates" value={certs.total} />
            <Mini label="Expired" value={certs.expired} danger={certs.expired > 0} />
            <Mini label="Quantum-vulnerable" value={certs.quantum_vulnerable} danger={certs.quantum_vulnerable > 0} />
            <Mini label="Expiring ≤30d" value={certs.expiring_soon} warn={certs.expiring_soon > 0} />
          </div>
        </Card>

        <Card className="card-hover">
          <CardHeader title="Dependencies & SBOM" action={<Link to="/dependencies" className="text-xs font-semibold text-brand-500 hover:underline">Open →</Link>} />
          {dep ? (
            <div className="grid grid-cols-2 gap-3">
              <Mini label="Packages" value={dep.total_packages} />
              <Mini label="Flagged" value={dep.flagged} warn={dep.flagged > 0} />
              <Mini label="Risk score" value={dep.risk_score} danger={dep.risk_score >= 60} />
              <Mini label="Manifests" value={dep.manifests.length} />
            </div>
          ) : (
            <div className="flex h-full items-center gap-2 text-sm text-slate-400">
              <Boxes className="h-5 w-5" /> No dependency analysis yet.
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title="Recent Scans" />
          <ul className="divide-y divide-slate-100 dark:divide-white/5">
            {data.recent_scans.map((s) => (
              <li key={s.id} className="flex items-center justify-between py-2.5 text-sm">
                <div>
                  <p className="font-medium text-slate-700 dark:text-slate-200">Scan #{s.id}</p>
                  <p className="text-xs text-slate-400">{timeAgo(s.completed_at)}</p>
                </div>
                <span className="tabular-nums text-slate-500 dark:text-slate-400">{s.total_findings} findings</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      {/* Priority findings */}
      <Card>
        <CardHeader title="Priority Findings" action={<Link to="/findings" className="text-xs font-semibold text-brand-500 hover:underline">View all →</Link>} />
        <div className="-mx-2 overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wide text-slate-400">
                <th className="px-2 py-2 font-semibold">Location</th>
                <th className="px-2 py-2 font-semibold">Algorithm</th>
                <th className="px-2 py-2 font-semibold">Severity</th>
                <th className="px-2 py-2 font-semibold">Migrate to</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {data.top_findings.slice(0, 8).map((f) => (
                <tr key={f.id} className="text-slate-700 dark:text-slate-200">
                  <td className="px-2 py-2"><span className="font-mono text-xs text-slate-500 dark:text-slate-400">{f.file}:{f.line}</span></td>
                  <td className="px-2 py-2 font-medium">{f.algorithm}</td>
                  <td className="px-2 py-2"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-2 py-2"><span className="flex items-center gap-1 font-medium text-green-600 dark:text-green-400"><ShieldCheck className="h-3.5 w-3.5" />{f.pqc_primary}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {langData.length > 0 && (
        <Card>
          <CardHeader title="Findings by Language / File Type" />
          <BarsChart data={langData} color="#06b6d4" height={220} />
        </Card>
      )}
    </div>
  );
}

function Mini({ label, value, danger, warn }: { label: string; value: number; danger?: boolean; warn?: boolean }) {
  const color = danger ? "text-red-500" : warn ? "text-amber-500" : "text-slate-900 dark:text-white";
  return (
    <div className="rounded-lg bg-slate-50 p-3 dark:bg-white/[0.03]">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-slate-400">{label}</p>
    </div>
  );
}
