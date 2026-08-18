import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Boxes,
  ClipboardCheck,
  FileText,
  FlaskConical,
  LayoutDashboard,
  Moon,
  Network,
  Route,
  ScanLine,
  Search,
  ShieldCheck,
  Sparkles,
  Table2,
  Terminal,
} from "lucide-react";
import { api, type Finding } from "../lib/api";
import { PALETTE_EVENT } from "../hooks/useHotkeys";
import { useTheme } from "../hooks/useTheme";

interface Cmd {
  id: string;
  label: string;
  hint?: string;
  icon: any;
  run: () => void;
}

export function CommandPalette() {
  const nav = useNavigate();
  const { toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanId, setScanId] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: Cmd[] = useMemo(
    () => [
      { id: "dash", label: "Go to Dashboard", hint: "g d", icon: LayoutDashboard, run: () => nav("/") },
      { id: "find", label: "Go to Findings", hint: "g f", icon: Table2, run: () => nav("/findings") },
      { id: "cert", label: "Go to Certificates", hint: "g c", icon: ShieldCheck, run: () => nav("/certificates") },
      { id: "dep", label: "Go to Dependencies & SBOM", hint: "g p", icon: Boxes, run: () => nav("/dependencies") },
      { id: "ana", label: "Go to Analytics", hint: "g n", icon: Network, run: () => nav("/analytics") },
      { id: "adv", label: "Go to AI Advisor", hint: "g a", icon: Sparkles, run: () => nav("/advisor") },
      { id: "mig", label: "Go to Migration Roadmap", hint: "g m", icon: Route, run: () => nav("/migration") },
      { id: "cmp", label: "Go to Compliance", hint: "g o", icon: ClipboardCheck, run: () => nav("/compliance") },
      { id: "rep", label: "Go to Reports", hint: "g r", icon: FileText, run: () => nav("/reports") },
      { id: "scan", label: "New Scan", hint: "g s", icon: ScanLine, run: () => nav("/scan") },
      { id: "cat", label: "PQC Catalog", hint: "g k", icon: Boxes, run: () => nav("/algorithms") },
      { id: "theme", label: "Toggle light / dark theme", icon: Moon, run: () => toggle() },
      {
        id: "demo",
        label: "Run demo scan",
        icon: FlaskConical,
        run: async () => {
          await api.runDemo();
          nav("/");
        },
      },
    ],
    [nav, toggle]
  );

  // Toggle via Ctrl+K event / topbar
  useEffect(() => {
    const onToggle = () => setOpen((o) => !o);
    window.addEventListener(PALETTE_EVENT, onToggle);
    return () => window.removeEventListener(PALETTE_EVENT, onToggle);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      setTimeout(() => inputRef.current?.focus(), 30);
      api.scans().then((s) => setScanId(s[0]?.id ?? null)).catch(() => {});
    }
  }, [open]);

  // Live finding search (debounced)
  useEffect(() => {
    if (!open || scanId == null || query.trim().length < 2) {
      setFindings([]);
      return;
    }
    const t = setTimeout(() => {
      api
        .findings(scanId, { search: query, page_size: 6 })
        .then((r) => setFindings(r.items))
        .catch(() => setFindings([]));
    }, 180);
    return () => clearTimeout(t);
  }, [query, open, scanId]);

  const filteredCmds = commands.filter((c) => c.label.toLowerCase().includes(query.toLowerCase()));
  const total = filteredCmds.length + findings.length;

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
      else if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive((a) => Math.min(a + 1, Math.max(0, total - 1)));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive((a) => Math.max(a - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (active < filteredCmds.length) {
          filteredCmds[active]?.run();
          setOpen(false);
        } else {
          nav("/findings");
          setOpen(false);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, active, total, filteredCmds, nav]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/50 p-4 pt-[12vh] backdrop-blur-sm"
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-2xl border border-white/10 bg-white shadow-2xl dark:bg-ink-800"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-slate-200 px-4 dark:border-white/10">
          <Search className="h-4 w-4 text-slate-400" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            placeholder="Search commands and findings…"
            className="w-full bg-transparent py-3.5 text-sm text-slate-800 outline-none placeholder:text-slate-400 dark:text-slate-100"
          />
          <kbd className="hidden rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500 dark:bg-white/10 sm:block">
            ESC
          </kbd>
        </div>

        <div className="max-h-[52vh] overflow-y-auto p-2">
          <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
            Commands
          </p>
          {filteredCmds.map((c, i) => (
            <Row
              key={c.id}
              active={i === active}
              icon={c.icon}
              label={c.label}
              hint={c.hint}
              onMouseEnter={() => setActive(i)}
              onClick={() => {
                c.run();
                setOpen(false);
              }}
            />
          ))}

          {findings.length > 0 && (
            <>
              <p className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Findings
              </p>
              {findings.map((f, i) => (
                <Row
                  key={f.id}
                  active={filteredCmds.length + i === active}
                  icon={Terminal}
                  label={`${f.algorithm} — ${f.file}:${f.line}`}
                  hint={f.severity}
                  onMouseEnter={() => setActive(filteredCmds.length + i)}
                  onClick={() => {
                    nav("/findings");
                    setOpen(false);
                  }}
                />
              ))}
            </>
          )}

          {total === 0 && (
            <p className="px-3 py-6 text-center text-sm text-slate-400">No matches.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function Row({
  active,
  icon: Icon,
  label,
  hint,
  onClick,
  onMouseEnter,
}: {
  active: boolean;
  icon: any;
  label: string;
  hint?: string;
  onClick: () => void;
  onMouseEnter: () => void;
}) {
  return (
    <button
      onClick={onClick}
      onMouseEnter={onMouseEnter}
      className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm ${
        active
          ? "bg-brand-600 text-white"
          : "text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-white/5"
      }`}
    >
      <Icon className="h-4 w-4 shrink-0 opacity-80" />
      <span className="flex-1 truncate">{label}</span>
      {hint && (
        <span className={`text-[10px] font-semibold ${active ? "text-white/80" : "text-slate-400"}`}>
          {hint}
        </span>
      )}
    </button>
  );
}
