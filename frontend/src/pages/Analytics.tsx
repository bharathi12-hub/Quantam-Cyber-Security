import { useEffect, useMemo, useState } from "react";
import { api, type Finding, type QuantumThreat, type Severity } from "../lib/api";
import { Card, CardHeader, EmptyState, ErrorState, Loading } from "../components/primitives";
import { THREAT_LABEL } from "../lib/ui";

const SEVS: Severity[] = ["Critical", "High", "Medium", "Low"];
const THREATS: QuantumThreat[] = ["shor", "grover", "classical"];

export default function Analytics() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const scans = await api.scans();
        if (!scans.length) return setLoading(false);
        const r = await api.findings(scans[0].id, { page_size: 200 });
        setFindings(r.items);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const matrix = useMemo(() => {
    const m: Record<string, Record<string, number>> = {};
    let max = 0;
    for (const s of SEVS) {
      m[s] = {};
      for (const t of THREATS) m[s][t] = 0;
    }
    for (const f of findings) {
      if (m[f.severity] && m[f.severity][f.quantum_threat] !== undefined) {
        m[f.severity][f.quantum_threat] += 1;
        max = Math.max(max, m[f.severity][f.quantum_threat]);
      }
    }
    return { m, max };
  }, [findings]);

  const graph = useMemo(() => buildGraph(findings), [findings]);

  if (loading) return <Loading label="Building analytics…" />;
  if (error) return <ErrorState message={error} />;
  if (!findings.length) return <EmptyState title="No data to analyze" body="Run a scan first." />;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Cryptographic Risk Matrix" />
        <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
          Findings by severity (rows) and quantum-threat class (columns). Shor-broken issues are the
          most urgent — public-key crypto broken outright by a quantum computer.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[420px] border-separate border-spacing-1 text-center text-sm">
            <thead>
              <tr>
                <th></th>
                {THREATS.map((t) => (
                  <th key={t} className="px-2 pb-1 text-xs font-semibold text-slate-500 dark:text-slate-400">
                    {THREAT_LABEL[t]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SEVS.map((s) => (
                <tr key={s}>
                  <td className="pr-2 text-right text-xs font-semibold text-slate-500 dark:text-slate-400">{s}</td>
                  {THREATS.map((t) => {
                    const v = matrix.m[s][t];
                    const intensity = matrix.max ? v / matrix.max : 0;
                    return (
                      <td key={t}>
                        <div
                          className="flex h-14 items-center justify-center rounded-lg text-lg font-bold"
                          style={{
                            backgroundColor: v ? `rgba(220,38,38,${0.12 + intensity * 0.68})` : "rgba(148,163,184,0.10)",
                            color: v ? (intensity > 0.4 ? "#fff" : "#b91c1c") : "#94a3b8",
                          }}
                        >
                          {v}
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card>
        <CardHeader title="Cryptographic Dependency Graph" />
        <p className="mb-2 text-sm text-slate-500 dark:text-slate-400">
          How detected algorithms map to their recommended quantum-safe targets. Edge thickness ∝ number of findings.
        </p>
        <DependencyGraph graph={graph} />
      </Card>
    </div>
  );
}

interface Graph {
  algos: { name: string; count: number }[];
  targets: { name: string; count: number }[];
  edges: { a: number; t: number; count: number }[];
}

function buildGraph(findings: Finding[]): Graph {
  const algoCount: Record<string, number> = {};
  const targetCount: Record<string, number> = {};
  const edgeMap: Record<string, number> = {};
  for (const f of findings) {
    const a = f.algorithm;
    const t = f.pqc_primary || "—";
    algoCount[a] = (algoCount[a] || 0) + 1;
    targetCount[t] = (targetCount[t] || 0) + 1;
    edgeMap[`${a}|||${t}`] = (edgeMap[`${a}|||${t}`] || 0) + 1;
  }
  const algos = Object.entries(algoCount).sort((x, y) => y[1] - x[1]).slice(0, 9).map(([name, count]) => ({ name, count }));
  const algoNames = new Set(algos.map((a) => a.name));
  const targetSet: Record<string, number> = {};
  const edges: { a: number; t: number; count: number }[] = [];
  Object.entries(edgeMap).forEach(([k, count]) => {
    const [a, t] = k.split("|||");
    if (!algoNames.has(a)) return;
    targetSet[t] = (targetSet[t] || 0) + count;
  });
  const targets = Object.entries(targetSet).sort((x, y) => y[1] - x[1]).map(([name, count]) => ({ name, count }));
  const targetIdx: Record<string, number> = Object.fromEntries(targets.map((t, i) => [t.name, i]));
  const algoIdx: Record<string, number> = Object.fromEntries(algos.map((a, i) => [a.name, i]));
  Object.entries(edgeMap).forEach(([k, count]) => {
    const [a, t] = k.split("|||");
    if (algoIdx[a] === undefined || targetIdx[t] === undefined) return;
    edges.push({ a: algoIdx[a], t: targetIdx[t], count });
  });
  return { algos, targets, edges };
}

function DependencyGraph({ graph }: { graph: Graph }) {
  const W = 720;
  const rowH = 46;
  const H = Math.max(graph.algos.length, graph.targets.length) * rowH + 20;
  const leftX = 150;
  const rightX = W - 150;
  const ay = (i: number) => 30 + i * rowH;
  const ty = (i: number) => 30 + i * rowH;
  const maxEdge = Math.max(1, ...graph.edges.map((e) => e.count));

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 560 }}>
        {graph.edges.map((e, i) => {
          const y1 = ay(e.a);
          const y2 = ty(e.t);
          const mx = (leftX + rightX) / 2;
          return (
            <path
              key={i}
              d={`M ${leftX} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${rightX} ${y2}`}
              fill="none"
              stroke="#6366f1"
              strokeOpacity={0.25 + 0.5 * (e.count / maxEdge)}
              strokeWidth={1 + 4 * (e.count / maxEdge)}
            />
          );
        })}
        {graph.algos.map((a, i) => (
          <g key={a.name}>
            <circle cx={leftX} cy={ay(i)} r={6} fill="#dc2626" />
            <text x={leftX - 14} y={ay(i) + 4} textAnchor="end" className="fill-slate-600 dark:fill-slate-300" style={{ fontSize: 12, fontWeight: 600 }}>
              {a.name}
            </text>
            <text x={leftX - 14} y={ay(i) + 17} textAnchor="end" className="fill-slate-400" style={{ fontSize: 10 }}>
              ×{a.count}
            </text>
          </g>
        ))}
        {graph.targets.map((t, i) => (
          <g key={t.name}>
            <circle cx={rightX} cy={ty(i)} r={6} fill="#16a34a" />
            <text x={rightX + 14} y={ty(i) + 4} className="fill-slate-600 dark:fill-slate-300" style={{ fontSize: 12, fontWeight: 600 }}>
              {t.name}
            </text>
          </g>
        ))}
        <text x={leftX} y={16} textAnchor="middle" className="fill-slate-400" style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>DETECTED</text>
        <text x={rightX} y={16} textAnchor="middle" className="fill-slate-400" style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>QUANTUM-SAFE</text>
      </svg>
    </div>
  );
}
