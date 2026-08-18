import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search, ShieldCheck } from "lucide-react";
import {
  api,
  type Finding,
  type PagedFindings,
  type Scan,
  type ScanSummary,
} from "../lib/api";
import {
  Card,
  ErrorState,
  Loading,
  SeverityBadge,
  ThreatBadge,
} from "../components/primitives";
import { difficultyBadge } from "../lib/ui";

const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const THREATS = [
  { v: "shor", label: "Shor-broken" },
  { v: "grover", label: "Grover-weakened" },
  { v: "classical", label: "Classically weak" },
];

export default function Findings() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [scanId, setScanId] = useState<number | null>(null);
  const [detail, setDetail] = useState<Scan | null>(null);

  const [data, setData] = useState<PagedFindings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const [severity, setSeverity] = useState("");
  const [threat, setThreat] = useState("");
  const [language, setLanguage] = useState("");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);
  const pageSize = 15;

  // Load scan list once.
  useEffect(() => {
    (async () => {
      try {
        const list = await api.scans();
        setScans(list);
        if (list.length) setScanId(list[0].id);
        else setLoading(false);
      } catch (e) {
        setError((e as Error).message);
        setLoading(false);
      }
    })();
  }, []);

  // Load scan detail (for filter options + header).
  useEffect(() => {
    if (scanId == null) return;
    api.scan(scanId).then(setDetail).catch(() => setDetail(null));
  }, [scanId]);

  // Load findings when query changes.
  useEffect(() => {
    if (scanId == null) return;
    setLoading(true);
    setError("");
    api
      .findings(scanId, {
        severity: severity || undefined,
        quantum_threat: threat || undefined,
        language: language || undefined,
        search: search || undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        page,
        page_size: pageSize,
      })
      .then(setData)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [scanId, severity, threat, language, search, sortBy, sortDir, page]);

  // reset to page 1 when filters change
  useEffect(() => setPage(1), [severity, threat, language, search, scanId]);

  const languages = useMemo(
    () => (detail ? Object.keys(detail.summary.by_language ?? {}) : []),
    [detail]
  );

  const toggleSort = (col: string) => {
    if (sortBy === col) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortBy(col);
      setSortDir("asc");
    }
  };

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  if (!scans.length && !loading)
    return (
      <Card className="text-center">
        <p className="py-8 text-slate-500 dark:text-slate-400">
          No scans available. Run a scan from the <b>New Scan</b> page first.
        </p>
      </Card>
    );

  return (
    <div className="space-y-5">
      {/* Filter bar */}
      <Card className="!p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              className="input pl-9"
              placeholder="Search file, algorithm, snippet…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select className="input w-auto" value={scanId ?? ""} onChange={(e) => setScanId(Number(e.target.value))}>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                Scan #{s.id} · {s.total_findings} findings
              </option>
            ))}
          </select>

          <select className="input w-auto" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <select className="input w-auto" value={threat} onChange={(e) => setThreat(e.target.value)}>
            <option value="">All threats</option>
            {THREATS.map((t) => (
              <option key={t.v} value={t.v}>
                {t.label}
              </option>
            ))}
          </select>

          <select className="input w-auto" value={language} onChange={(e) => setLanguage(e.target.value)}>
            <option value="">All languages</option>
            {languages.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {error && <ErrorState message={error} />}

      <Card className="!p-0">
        {loading ? (
          <Loading label="Loading findings…" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-sm">
              <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-400 dark:border-slate-800">
                <tr>
                  <th className="w-8 px-3 py-3"></th>
                  <Th label="Location" col="file" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
                  <Th label="Language" col="language" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
                  <Th label="Algorithm" col="algorithm" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
                  <Th label="Severity" col="severity" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
                  <th className="px-3 py-3 font-semibold">Quantum</th>
                  <th className="px-3 py-3 font-semibold">Migrate to</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data?.items.map((f) => (
                  <FindingRow
                    key={f.id}
                    f={f}
                    open={expanded === f.id}
                    onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                  />
                ))}
                {data && data.items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-12 text-center text-slate-400">
                      No findings match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data && data.total > 0 && (
          <div className="flex items-center justify-between border-t border-slate-200 px-4 py-3 text-sm dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400">
              {(data.page - 1) * data.page_size + 1}–
              {Math.min(data.page * data.page_size, data.total)} of {data.total}
            </span>
            <div className="flex items-center gap-2">
              <button
                className="btn-ghost !py-1.5"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Prev
              </button>
              <span className="tabular-nums text-slate-500">
                {page} / {totalPages}
              </span>
              <button
                className="btn-ghost !py-1.5"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function Th({
  label,
  col,
  sortBy,
  sortDir,
  onClick,
}: {
  label: string;
  col: string;
  sortBy: string;
  sortDir: string;
  onClick: (c: string) => void;
}) {
  const active = sortBy === col;
  return (
    <th className="px-3 py-3 font-semibold">
      <button
        className={`inline-flex items-center gap-1 hover:text-slate-600 dark:hover:text-slate-200 ${
          active ? "text-slate-700 dark:text-slate-200" : ""
        }`}
        onClick={() => onClick(col)}
      >
        {label}
        {active && <span className="text-[10px]">{sortDir === "asc" ? "▲" : "▼"}</span>}
      </button>
    </th>
  );
}

function FindingRow({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr
        className="cursor-pointer text-slate-700 transition hover:bg-slate-50 dark:text-slate-200 dark:hover:bg-slate-800/50"
        onClick={onToggle}
      >
        <td className="px-3 py-3 text-slate-400">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </td>
        <td className="px-3 py-3">
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {f.file}:{f.line}
          </span>
        </td>
        <td className="px-3 py-3 text-slate-500 dark:text-slate-400">{f.language}</td>
        <td className="px-3 py-3">
          <p className="font-semibold">{f.algorithm}</p>
          <p className="text-xs text-slate-400">{f.family}</p>
        </td>
        <td className="px-3 py-3">
          <SeverityBadge severity={f.severity} />
        </td>
        <td className="px-3 py-3">
          <ThreatBadge threat={f.quantum_threat} />
        </td>
        <td className="px-3 py-3">
          <div className="flex items-center gap-1.5 font-medium text-green-600 dark:text-green-400">
            <ShieldCheck className="h-4 w-4" />
            {f.pqc_primary}
          </div>
          <p className="text-xs text-slate-400">{f.pqc_standard}</p>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50/70 dark:bg-slate-800/30">
          <td></td>
          <td colSpan={6} className="px-3 pb-5 pt-1">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <DetailLabel>Detected code</DetailLabel>
                <pre className="mt-1 overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">
                  {f.snippet}
                </pre>
                <DetailLabel className="mt-3">Why it matters</DetailLabel>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{f.description}</p>
                {f.dataflow && (
                  <div className="mt-3 rounded-lg border border-violet-200 bg-violet-50 p-2.5 dark:border-violet-500/25 dark:bg-violet-500/10">
                    <p className="text-xs font-semibold uppercase tracking-wide text-violet-600 dark:text-violet-300">
                      Data-flow (AST taint)
                    </p>
                    <p className="mt-1 text-xs text-violet-800/90 dark:text-violet-200/80">{f.dataflow}</p>
                  </div>
                )}
                <p className="mt-2 text-xs text-slate-400">
                  {f.cwe} · confidence: {f.confidence} · analysis:{" "}
                  <span className={f.analysis === "ast" ? "font-semibold text-violet-500" : ""}>
                    {(f.analysis || "regex").toUpperCase()}
                  </span>
                </p>
              </div>
              <div>
                <DetailLabel>Remediation</DetailLabel>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{f.remediation}</p>
                <div className="mt-3 rounded-lg border border-green-200 bg-green-50 p-3 dark:border-green-500/25 dark:bg-green-500/10">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-green-700 dark:text-green-300">
                      Migrate to {f.pqc_primary}
                    </span>
                    {f.migration_difficulty && (
                      <span
                        className={`rounded px-2 py-0.5 text-xs font-semibold ${difficultyBadge(
                          f.migration_difficulty
                        )}`}
                      >
                        {f.migration_difficulty} effort
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-green-800/90 dark:text-green-200/80">
                    {f.pqc_guidance}
                  </p>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function DetailLabel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <p className={`text-xs font-semibold uppercase tracking-wide text-slate-400 ${className}`}>
      {children}
    </p>
  );
}
