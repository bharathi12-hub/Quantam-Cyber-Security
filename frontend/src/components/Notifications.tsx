import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, Bell, CalendarClock, ShieldX, Atom } from "lucide-react";
import { api } from "../lib/api";

interface Note {
  id: string;
  icon: any;
  color: string;
  title: string;
  body: string;
  to: string;
}

export function Notifications() {
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const [notes, setNotes] = useState<Note[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .dashboard()
      .then((d) => {
        const p = d.posture;
        const c = d.certificates || ({} as any);
        const out: Note[] = [];
        if (p.by_severity?.Critical > 0)
          out.push({
            id: "crit",
            icon: AlertTriangle,
            color: "text-red-400",
            title: `${p.by_severity.Critical} critical findings`,
            body: "Quantum-vulnerable public-key crypto detected.",
            to: "/findings",
          });
        if (p.quantum_vulnerable > 0)
          out.push({
            id: "qv",
            icon: Atom,
            color: "text-red-400",
            title: `${p.quantum_vulnerable} quantum-vulnerable assets`,
            body: "Broken by Shor's algorithm — plan PQC migration.",
            to: "/advisor",
          });
        if (c.expired > 0)
          out.push({
            id: "exp",
            icon: ShieldX,
            color: "text-orange-400",
            title: `${c.expired} certificate(s) expired`,
            body: "Renew or rotate immediately.",
            to: "/certificates",
          });
        if (c.expiring_soon > 0)
          out.push({
            id: "soon",
            icon: CalendarClock,
            color: "text-amber-400",
            title: `${c.expiring_soon} certificate(s) expiring soon`,
            body: "Within 30 days of expiry.",
            to: "/certificates",
          });
        setNotes(out);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="btn-ghost relative h-9 w-9 !px-0"
        aria-label="Notifications"
      >
        <Bell className="h-4 w-4" />
        {notes.length > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
            {notes.length}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl dark:border-white/10 dark:bg-ink-800">
          <div className="border-b border-slate-100 px-4 py-2.5 text-sm font-semibold text-slate-700 dark:border-white/10 dark:text-slate-200">
            Notifications
          </div>
          {notes.length === 0 ? (
            <p className="px-4 py-8 text-center text-sm text-slate-400">You're all caught up.</p>
          ) : (
            <ul className="max-h-96 overflow-y-auto">
              {notes.map((n) => (
                <li key={n.id}>
                  <button
                    onClick={() => {
                      nav(n.to);
                      setOpen(false);
                    }}
                    className="flex w-full items-start gap-3 px-4 py-3 text-left transition hover:bg-slate-50 dark:hover:bg-white/5"
                  >
                    <n.icon className={`mt-0.5 h-4 w-4 shrink-0 ${n.color}`} />
                    <div>
                      <p className="text-sm font-medium text-slate-800 dark:text-slate-100">{n.title}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{n.body}</p>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
