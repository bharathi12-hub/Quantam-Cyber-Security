import { useEffect, useState } from "react";
import {
  Atom,
  CalendarClock,
  ChevronDown,
  ChevronRight,
  Fingerprint,
  ScanLine,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { api, type Certificate } from "../lib/api";
import { Card, CardHeader, EmptyState, ErrorState, Loading, SeverityBadge, StatCard } from "../components/primitives";
import { gradeColor } from "../lib/ui";

export default function Certificates() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [pem, setPem] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      setCerts(await api.certificates());
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
      await api.seedCerts();
      await load();
    } finally {
      setBusy(false);
    }
  };

  const analyze = async () => {
    if (!pem.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api.analyzeCert(pem.trim());
      setPem("");
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <Loading label="Loading certificate inventory…" />;

  const total = certs.length;
  const expired = certs.filter((c) => c.is_expired).length;
  const soon = certs.filter((c) => c.expiring_soon).length;
  const quantum = certs.filter((c) => c.quantum_vulnerable).length;

  return (
    <div className="space-y-6">
      {error && <ErrorState message={error} />}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Certificates" value={total} icon={<ShieldCheck className="h-6 w-6" />} />
        <StatCard label="Expired" value={expired} icon={<ShieldX className="h-6 w-6" />} accent="text-red-500" />
        <StatCard label="Expiring ≤30d" value={soon} icon={<CalendarClock className="h-6 w-6" />} accent="text-amber-500" />
        <StatCard label="Quantum-Vulnerable" value={quantum} icon={<Atom className="h-6 w-6" />} accent="text-red-500" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader title="Analyze a certificate" />
          <textarea
            className="input h-40 resize-none font-mono text-[11px] leading-relaxed"
            placeholder="-----BEGIN CERTIFICATE-----&#10;…paste PEM here…"
            value={pem}
            onChange={(e) => setPem(e.target.value)}
          />
          <div className="mt-3 flex gap-2">
            <button className="btn-primary flex-1" onClick={analyze} disabled={busy}>
              <ScanLine className="h-4 w-4" /> Analyze
            </button>
            {total === 0 && (
              <button className="btn-ghost" onClick={seed} disabled={busy}>
                Load demo
              </button>
            )}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Parses PEM/DER X.509 and evaluates expiry, key strength, signature hash, and
            post-quantum readiness.
          </p>
        </Card>

        <div className="lg:col-span-2">
          {total === 0 ? (
            <EmptyState
              title="No certificates yet"
              body="Paste a PEM certificate to analyze it, or load the demo certificate set."
            />
          ) : (
            <Card className="!p-0">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="border-b border-slate-200/70 text-xs uppercase tracking-wide text-slate-400 dark:border-white/10">
                    <tr>
                      <th className="w-8 px-3 py-3"></th>
                      <th className="px-3 py-3 font-semibold">Subject</th>
                      <th className="px-3 py-3 font-semibold">Key</th>
                      <th className="px-3 py-3 font-semibold">Expiry</th>
                      <th className="px-3 py-3 font-semibold">Quantum</th>
                      <th className="px-3 py-3 font-semibold">Grade</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                    {certs.map((c) => (
                      <CertRow
                        key={c.id}
                        c={c}
                        open={expanded === c.id}
                        onToggle={() => setExpanded(expanded === c.id ? null : c.id)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function CertRow({ c, open, onToggle }: { c: Certificate; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="cursor-pointer transition hover:bg-slate-50 dark:hover:bg-white/5" onClick={onToggle}>
        <td className="px-3 py-3 text-slate-400">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </td>
        <td className="px-3 py-3">
          <p className="font-semibold text-slate-800 dark:text-slate-100">{c.subject}</p>
          <p className="text-xs text-slate-400">{c.is_self_signed ? "Self-signed" : c.issuer}</p>
        </td>
        <td className="px-3 py-3 text-slate-600 dark:text-slate-300">
          {c.public_key_algorithm}-{c.key_size}
          <span className="ml-1 text-xs text-slate-400">{c.hash_algorithm}</span>
        </td>
        <td className="px-3 py-3">
          {c.is_expired ? (
            <span className="chip bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300">
              Expired
            </span>
          ) : c.expiring_soon ? (
            <span className="chip bg-amber-100 text-amber-700 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300">
              {c.days_to_expiry}d
            </span>
          ) : (
            <span className="text-slate-500 dark:text-slate-400">{c.days_to_expiry}d</span>
          )}
        </td>
        <td className="px-3 py-3">
          {c.quantum_vulnerable ? (
            <span className="chip bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300">
              Vulnerable
            </span>
          ) : (
            <span className="chip bg-green-100 text-green-700 ring-green-600/20 dark:bg-green-500/15 dark:text-green-300">
              Safe
            </span>
          )}
        </td>
        <td className="px-3 py-3">
          <span
            className="flex h-6 w-6 items-center justify-center rounded text-xs font-bold text-white"
            style={{ backgroundColor: gradeColor(c.grade) }}
          >
            {c.grade}
          </span>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50/60 dark:bg-white/[0.02]">
          <td></td>
          <td colSpan={5} className="px-3 pb-5 pt-1">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1.5 text-sm">
                <Meta label="Signature" value={c.signature_algorithm} />
                <Meta label="Valid from" value={new Date(c.not_before).toLocaleDateString()} />
                <Meta label="Valid to" value={new Date(c.not_after).toLocaleDateString()} />
                {c.report.san?.length > 0 && <Meta label="SAN" value={c.report.san.join(", ")} />}
                <div className="flex items-start gap-2 pt-1 text-xs text-slate-400">
                  <Fingerprint className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span className="break-all font-mono">{c.fingerprint_sha256}</span>
                </div>
              </div>
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">Findings</p>
                <div className="space-y-2">
                  {c.report.flags?.map((f, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <SeverityBadge severity={f.severity} />
                      <div>
                        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{f.title}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">{f.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-3 rounded-lg border border-green-200 bg-green-50 p-2.5 text-xs dark:border-green-500/25 dark:bg-green-500/10">
                  <span className="font-semibold text-green-700 dark:text-green-300">PQC: </span>
                  <span className="text-green-800/90 dark:text-green-200/80">{c.pqc_recommendation}</span>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</span>
      <span className="text-slate-600 dark:text-slate-300">{value}</span>
    </div>
  );
}
