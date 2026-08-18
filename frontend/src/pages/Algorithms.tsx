import { useEffect, useState } from "react";
import { KeyRound, PenLine, Hash, Lock, Dice5, Vault, Network } from "lucide-react";
import { api, type PQCAlgorithm } from "../lib/api";
import { Card, ErrorState, Loading } from "../components/primitives";

const KIND_META: Record<string, { label: string; icon: any; color: string }> = {
  kem: { label: "Key Encapsulation", icon: KeyRound, color: "text-violet-500" },
  signature: { label: "Digital Signature", icon: PenLine, color: "text-blue-500" },
  hash: { label: "Hash Function", icon: Hash, color: "text-teal-500" },
  cipher: { label: "Symmetric Cipher", icon: Lock, color: "text-emerald-500" },
  rng: { label: "Random Generation", icon: Dice5, color: "text-amber-500" },
  process: { label: "Process / Config", icon: Network, color: "text-sky-500" },
};

function bytes(n: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export default function Algorithms() {
  const [algos, setAlgos] = useState<PQCAlgorithm[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .algorithms()
      .then((d) => setAlgos(d.algorithms))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Loading label="Loading PQC catalog…" />;
  if (error) return <ErrorState message={error} />;

  return (
    <div className="space-y-5">
      <Card className="bg-gradient-to-br from-brand-600 to-brand-800 !border-0 text-white">
        <h2 className="text-lg font-bold">NIST Post-Quantum & Hardened-Classical Targets</h2>
        <p className="mt-1 max-w-3xl text-sm text-brand-100">
          Every finding is mapped to one of these standardized migration targets. Lattice-based
          ML-KEM and ML-DSA are the primary post-quantum primitives (FIPS&nbsp;203/204); SLH-DSA
          (FIPS&nbsp;205) offers a conservative hash-based alternative for long-lived roots of trust.
        </p>
      </Card>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
        {algos.map((a) => {
          const meta = KIND_META[a.kind] ?? KIND_META.process;
          const Icon = meta.icon;
          return (
            <Card key={a.name} className="flex flex-col animate-fade-in">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2.5">
                  <div className={`${meta.color}`}>
                    <Icon className="h-6 w-6" />
                  </div>
                  <div>
                    <h3 className="font-bold text-slate-900 dark:text-white">{a.name}</h3>
                    <p className="text-xs text-slate-400">{meta.label}</p>
                  </div>
                </div>
                <span className="rounded-md bg-brand-50 px-2 py-1 text-xs font-semibold text-brand-700 dark:bg-brand-500/15 dark:text-brand-300">
                  {a.standard}
                </span>
              </div>

              <p className="mt-3 flex-1 text-sm text-slate-600 dark:text-slate-300">{a.summary}</p>

              {(a.public_key_bytes || a.ciphertext_or_sig_bytes) && (
                <div className="mt-4 grid grid-cols-3 gap-2 rounded-lg bg-slate-50 p-3 text-center dark:bg-slate-800/60">
                  <Metric label="Public key" value={bytes(a.public_key_bytes)} />
                  <Metric label="Secret key" value={bytes(a.private_key_bytes)} />
                  <Metric
                    label={a.kind === "signature" ? "Signature" : "Ciphertext"}
                    value={bytes(a.ciphertext_or_sig_bytes)}
                  />
                </div>
              )}

              <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
                <span className="rounded bg-slate-100 px-1.5 py-0.5 font-medium dark:bg-slate-800">
                  NIST Level {a.nist_security_category}
                </span>
              </div>
              {a.notes && (
                <p className="mt-2 text-xs leading-relaxed text-slate-500 dark:text-slate-400">{a.notes}</p>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-sm font-bold text-slate-800 dark:text-slate-100">{value}</p>
      <p className="text-[10px] uppercase tracking-wide text-slate-400">{label}</p>
    </div>
  );
}
