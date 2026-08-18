import { useEffect, useMemo, useState } from "react";
import { Boxes, Download, PackageX, ShieldAlert } from "lucide-react";
import { api, type DependencyReport } from "../lib/api";
import { Card, CardHeader, EmptyState, ErrorState, Loading, SeverityBadge, StatCard } from "../components/primitives";
import { gradeColor } from "../lib/ui";

const ECO_LABEL: Record<string, string> = {
  pypi: "PyPI", npm: "npm", golang: "Go", maven: "Maven", cargo: "Cargo", composer: "Composer", gem: "RubyGems",
};

export default function Dependencies() {
  const [report, setReport] = useState<DependencyReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [flaggedOnly, setFlaggedOnly] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const list = await api.dependencyReports();
      setReport(list[0] ?? null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const seed = async () => {
    setBusy(true);
    try {
      await api.seedDependencies();
      await load();
    } finally {
      setBusy(false);
    }
  };

  const packages = useMemo(() => {
    if (!report) return [];
    const list = report.report.packages;
    return flaggedOnly ? list.filter((p) => p.advisory) : list;
  }, [report, flaggedOnly]);

  if (loading) return <Loading label="Loading dependency analysis…" />;
  if (error) return <ErrorState message={error} />;
  if (!report)
    return (
      <EmptyState
        title="No dependency analysis yet"
        body={
          <div className="flex flex-col items-center gap-4">
            <span>Analyze the bundled demo manifests (requirements.txt, package.json, go.mod, Cargo.toml).</span>
            <button className="btn-primary" onClick={seed} disabled={busy}>
              <Boxes className="h-4 w-4" /> {busy ? "Analyzing…" : "Analyze demo manifests"}
            </button>
          </div>
        }
      />
    );

  const r = report.report;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Packages" value={report.total_packages} icon={<Boxes className="h-6 w-6" />} />
        <StatCard label="Flagged" value={report.flagged} icon={<ShieldAlert className="h-6 w-6" />} accent="text-orange-500" />
        <StatCard label="High Severity" value={r.by_severity?.High ?? 0} icon={<PackageX className="h-6 w-6" />} accent="text-red-500" />
        <div className="card flex items-center justify-between p-5">
          <div>
            <p className="card-title">Risk</p>
            <p className="mt-2 text-3xl font-bold" style={{ color: gradeColor(report.grade) }}>
              {report.risk_score}
              <span className="text-lg">/100</span>
            </p>
          </div>
          <span
            className="flex h-10 w-10 items-center justify-center rounded-lg text-lg font-bold text-white"
            style={{ backgroundColor: gradeColor(report.grade) }}
          >
            {report.grade}
          </span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader title="By ecosystem" />
          <ul className="space-y-2">
            {Object.entries(r.by_ecosystem).map(([eco, n]) => (
              <li key={eco} className="flex items-center justify-between text-sm">
                <span className="text-slate-600 dark:text-slate-300">{ECO_LABEL[eco] ?? eco}</span>
                <span className="font-semibold tabular-nums text-slate-800 dark:text-slate-100">{n}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <CardHeader title="By category" />
          <ul className="space-y-2">
            {Object.entries(r.by_category).map(([cat, n]) => (
              <li key={cat} className="flex items-center justify-between text-sm">
                <span className="capitalize text-slate-600 dark:text-slate-300">{cat.replace("-", " ")}</span>
                <span className="font-semibold tabular-nums text-slate-800 dark:text-slate-100">{n}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="flex flex-col justify-between">
          <div>
            <CardHeader title="CycloneDX SBOM" />
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {report.total_packages} components across {report.manifests.length} manifest(s):{" "}
              <span className="font-mono text-xs">{report.manifests.join(", ")}</span>
            </p>
          </div>
          <a href={api.sbomUrl(report.id)} className="btn-primary mt-4" download>
            <Download className="h-4 w-4" /> Download SBOM (CycloneDX 1.5)
          </a>
        </Card>
      </div>

      <Card className="!p-0">
        <div className="flex items-center justify-between px-5 py-3">
          <h3 className="card-title">Packages</h3>
          <label className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <input type="checkbox" checked={flaggedOnly} onChange={(e) => setFlaggedOnly(e.target.checked)} />
            Flagged only
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="border-y border-slate-200/70 text-xs uppercase tracking-wide text-slate-400 dark:border-white/10">
              <tr>
                <th className="px-5 py-3 font-semibold">Package</th>
                <th className="px-3 py-3 font-semibold">Version</th>
                <th className="px-3 py-3 font-semibold">Ecosystem</th>
                <th className="px-3 py-3 font-semibold">Advisory</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-white/5">
              {packages.map((p, i) => (
                <tr key={i} className="align-top">
                  <td className="px-5 py-3">
                    <p className="font-semibold text-slate-800 dark:text-slate-100">{p.name}</p>
                    <p className="font-mono text-[11px] text-slate-400">{p.purl}</p>
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">{p.version}</td>
                  <td className="px-3 py-3 text-slate-600 dark:text-slate-300">{ECO_LABEL[p.ecosystem] ?? p.ecosystem}</td>
                  <td className="px-3 py-3">
                    {p.advisory ? (
                      <div className="flex items-start gap-2">
                        <SeverityBadge severity={p.advisory.severity} />
                        <div className="max-w-md">
                          <p className="text-xs text-slate-600 dark:text-slate-300">{p.advisory.note}</p>
                          <p className="mt-0.5 text-xs font-medium text-green-600 dark:text-green-400">
                            → {p.advisory.recommendation}
                          </p>
                        </div>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
