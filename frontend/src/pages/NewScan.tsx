import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FlaskConical, GitBranch, Github, Play, ScanLine } from "lucide-react";
import { api, type Scan } from "../lib/api";
import { Card, CardHeader, ErrorState, SeverityBadge } from "../components/primitives";
import { riskColor } from "../lib/ui";

const EXAMPLE = `import hashlib, random
from Crypto.PublicKey import RSA

API_KEY = "sk_live_hardcoded_secret_value_123"

def keypair():
    return RSA.generate(2048)          # RSA - broken by Shor

def digest(x):
    return hashlib.md5(x).hexdigest()  # MD5 - broken

def token():
    return random.randint(0, 1_000_000)  # weak RNG
`;

export default function NewScan() {
  const nav = useNavigate();
  const [filename, setFilename] = useState("snippet.py");
  const [content, setContent] = useState(EXAMPLE);
  const [projectName, setProjectName] = useState("Ad-hoc Snippet");
  const [result, setResult] = useState<Scan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [repoBranch, setRepoBranch] = useState("");

  const scanRepo = async () => {
    if (!repoUrl.trim()) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const scan = await api.runRepo({ url: repoUrl.trim(), branch: repoBranch.trim() || undefined });
      setResult(scan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const scanInline = async () => {
    if (!content.trim()) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const scan = await api.runInline({ filename, content, project_name: projectName });
      setResult(scan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const scanDemo = async () => {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const scan = await api.runDemo();
      setResult(scan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card>
          <CardHeader
            title="Scan Source Code"
            action={
              <button
                className="text-xs font-semibold text-brand-600 hover:underline dark:text-brand-400"
                onClick={() => setContent(EXAMPLE)}
              >
                Load example
              </button>
            }
          />
          <div className="mb-3 grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-500">Filename</label>
              <input className="input" value={filename} onChange={(e) => setFilename(e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-500">Project name</label>
              <input className="input" value={projectName} onChange={(e) => setProjectName(e.target.value)} />
            </div>
          </div>
          <textarea
            className="input h-80 resize-none font-mono text-xs leading-relaxed"
            value={content}
            spellCheck={false}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Paste source code here…"
          />
          <div className="mt-4 flex items-center gap-3">
            <button className="btn-primary" onClick={scanInline} disabled={busy}>
              <ScanLine className="h-4 w-4" />
              {busy ? "Scanning…" : "Scan code"}
            </button>
            <button className="btn-ghost" onClick={scanDemo} disabled={busy}>
              <FlaskConical className="h-4 w-4" />
              Run demo scan
            </button>
          </div>
        </Card>
      </div>

      <div className="space-y-5">
        <Card>
          <CardHeader title="Scan a Git repository" />
          <div className="relative">
            <Github className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              className="input pl-9"
              placeholder="https://github.com/org/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
            />
          </div>
          <div className="mt-2 flex gap-2">
            <div className="relative flex-1">
              <GitBranch className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <input
                className="input pl-9"
                placeholder="branch (optional)"
                value={repoBranch}
                onChange={(e) => setRepoBranch(e.target.value)}
              />
            </div>
            <button className="btn-primary" onClick={scanRepo} disabled={busy || !repoUrl.trim()}>
              {busy ? "Cloning…" : "Scan repo"}
            </button>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Shallow-clones a public repo and scans it. Internal/private hosts are blocked.
          </p>
        </Card>

        <Card>
          <CardHeader title="Filename → language" />
          <p className="text-sm text-slate-500 dark:text-slate-400">
            The scanner infers language from the filename extension. Try{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.py</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.java</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.go</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.js</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.c</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.cs</code>,{" "}
            <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">.php</code>.
          </p>
        </Card>

        {error && <ErrorState message={error} />}

        {result && (
          <Card className="animate-fade-in">
            <CardHeader title="Scan Result" />
            <div className="flex items-center gap-4">
              <div
                className="flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-xl text-white"
                style={{ backgroundColor: riskColor(result.risk_score) }}
              >
                <span className="text-2xl font-bold leading-none">{result.risk_score}</span>
                <span className="text-[10px] font-semibold tracking-wide">RISK</span>
              </div>
              <div className="text-sm">
                <p className="font-semibold text-slate-800 dark:text-slate-100">
                  {result.total_findings} findings · grade {result.grade}
                </p>
                <p className="text-slate-500 dark:text-slate-400">
                  {result.files_scanned} file(s), {result.lines_scanned} lines scanned
                </p>
                <p className="mt-0.5 text-red-500">
                  {result.summary.quantum_vulnerable} quantum-vulnerable
                </p>
              </div>
            </div>

            <div className="mt-4 space-y-1.5">
              {result.summary.by_severity &&
                (["Critical", "High", "Medium", "Low"] as const).map((s) =>
                  result.summary.by_severity[s] ? (
                    <div key={s} className="flex items-center justify-between text-sm">
                      <SeverityBadge severity={s} />
                      <span className="tabular-nums text-slate-500 dark:text-slate-400">
                        {result.summary.by_severity[s]}
                      </span>
                    </div>
                  ) : null
                )}
            </div>

            <button className="btn-primary mt-4 w-full" onClick={() => nav("/findings")}>
              <Play className="h-4 w-4" /> View findings
            </button>
          </Card>
        )}
      </div>
    </div>
  );
}
