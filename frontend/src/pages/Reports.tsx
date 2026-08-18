import { useEffect, useState } from "react";
import { FileCode2, FileJson, FileSpreadsheet, FileText, FileType2 } from "lucide-react";
import { api, type ScanSummary } from "../lib/api";
import { Card, CardHeader, EmptyState, Loading } from "../components/primitives";
import { Markdown } from "../components/Markdown";

const FORMATS = [
  { fmt: "pdf", label: "Executive PDF", desc: "Board-ready summary with risk KPIs and priority findings.", icon: FileType2, accent: "text-red-500" },
  { fmt: "sarif", label: "SARIF 2.1.0", desc: "For CI/SAST pipelines and code-scanning dashboards.", icon: FileCode2, accent: "text-violet-500" },
  { fmt: "csv", label: "CSV", desc: "Findings table for spreadsheets and BI tools.", icon: FileSpreadsheet, accent: "text-emerald-500" },
  { fmt: "json", label: "JSON", desc: "Full machine-readable assessment payload.", icon: FileJson, accent: "text-amber-500" },
  { fmt: "md", label: "Markdown", desc: "Human-readable report for docs and tickets.", icon: FileText, accent: "text-sky-500" },
];

export default function Reports() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [scanId, setScanId] = useState<number | null>(null);
  const [summary, setSummary] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.scans().then((s) => {
      setScans(s);
      setScanId(s[0]?.id ?? null);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    if (scanId == null) return;
    api.advisorSummarize(scanId).then((r) => setSummary(r.answer)).catch(() => setSummary(""));
  }, [scanId]);

  if (loading) return <Loading label="Loading reports…" />;
  if (!scans.length)
    return <EmptyState title="No scans to report on" body="Run a scan first, then export the assessment here." />;

  const scan = scans.find((s) => s.id === scanId);

  return (
    <div className="space-y-6">
      <Card className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-semibold text-slate-800 dark:text-slate-100">Assessment source</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {scan ? `Scan #${scan.id} · ${scan.total_findings} findings · risk ${scan.risk_score}/${scan.grade}` : "—"}
          </p>
        </div>
        <select className="input w-auto" value={scanId ?? ""} onChange={(e) => setScanId(Number(e.target.value))}>
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              Scan #{s.id} · {s.total_findings} findings
            </option>
          ))}
        </select>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {FORMATS.map((f) => (
          <Card key={f.fmt} className="card-hover flex flex-col">
            <div className={`${f.accent}`}>
              <f.icon className="h-7 w-7" />
            </div>
            <h3 className="mt-3 font-bold text-slate-800 dark:text-slate-100">{f.label}</h3>
            <p className="mt-1 flex-1 text-sm text-slate-500 dark:text-slate-400">{f.desc}</p>
            <a
              href={scanId ? api.reportUrl(scanId, f.fmt) : "#"}
              className="btn-ghost mt-4"
              download
            >
              Download {f.label}
            </a>
          </Card>
        ))}
      </div>

      {summary && (
        <Card>
          <CardHeader title="Executive summary preview" />
          <Markdown content={summary} />
        </Card>
      )}
    </div>
  );
}
