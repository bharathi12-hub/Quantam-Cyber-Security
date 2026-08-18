import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, Compass, LayoutDashboard, SearchX } from "lucide-react";

const SUGGESTIONS = [
  { to: "/", label: "Executive Dashboard" },
  { to: "/findings", label: "Cryptographic Findings" },
  { to: "/scan", label: "New Scan" },
  { to: "/reports", label: "Reports" },
];

export default function NotFound() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  return (
    <div className="card flex flex-col items-center justify-center gap-4 p-12 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-600/10 text-brand-500 dark:bg-brand-500/15">
        <SearchX className="h-7 w-7" />
      </div>

      <div className="space-y-1">
        <p className="text-3xl font-bold tracking-tight text-slate-800 dark:text-slate-100">404</p>
        <p className="text-lg font-semibold text-slate-700 dark:text-slate-200">Page not found</p>
        <p className="max-w-md text-sm text-slate-500 dark:text-slate-400">
          Nothing is routed to{" "}
          <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700 dark:bg-white/10 dark:text-slate-300">
            {pathname}
          </code>
          . It may have moved, or the link that brought you here may be out of date.
        </p>
      </div>

      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        <button type="button" onClick={() => navigate(-1)} className="btn-ghost">
          <ArrowLeft className="h-4 w-4" />
          Go back
        </button>
        <Link to="/" className="btn-primary">
          <LayoutDashboard className="h-4 w-4" />
          Open dashboard
        </Link>
      </div>

      <div className="mt-4 w-full max-w-md border-t border-slate-200/80 pt-4 dark:border-white/10">
        <p className="mb-2 flex items-center justify-center gap-1.5 card-title">
          <Compass className="h-3.5 w-3.5" />
          Jump to
        </p>
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1">
          {SUGGESTIONS.map((s) => (
            <Link
              key={s.to}
              to={s.to}
              className="text-xs font-semibold text-brand-500 hover:underline"
            >
              {s.label} →
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
