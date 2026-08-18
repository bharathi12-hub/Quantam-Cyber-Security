import { ReactNode } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import type { QuantumThreat, Severity } from "../lib/api";
import { SEVERITY_BADGE, THREAT_BADGE, THREAT_LABEL } from "../lib/ui";

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`card p-5 ${className}`}>{children}</div>;
}

export function CardHeader({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between">
      <h3 className="card-title">{title}</h3>
      {action}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${SEVERITY_BADGE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function ThreatBadge({ threat }: { threat: QuantumThreat }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${THREAT_BADGE[threat]}`}
    >
      {THREAT_LABEL[threat]}
    </span>
  );
}

export function StatCard({
  label,
  value,
  sub,
  icon,
  accent = "text-brand-600 dark:text-brand-400",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="card animate-fade-in p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="card-title">{label}</p>
          <p className="mt-2 text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
            {value}
          </p>
          {sub && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{sub}</p>}
        </div>
        {icon && <div className={accent}>{icon}</div>}
      </div>
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-slate-400">
      <Loader2 className="h-5 w-5 animate-spin" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300">
      <AlertTriangle className="h-5 w-5 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

export function EmptyState({ title, body }: { title: string; body: ReactNode }) {
  return (
    <div className="card flex flex-col items-center justify-center gap-2 p-12 text-center">
      <p className="text-lg font-semibold text-slate-700 dark:text-slate-200">{title}</p>
      <p className="max-w-md text-sm text-slate-500 dark:text-slate-400">{body}</p>
    </div>
  );
}
