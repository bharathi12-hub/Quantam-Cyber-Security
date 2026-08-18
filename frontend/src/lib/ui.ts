// Shared UI helpers: color maps, labels, formatting.
import type { QuantumThreat, Severity } from "./api";

// Chart-friendly hex palette (consistent across the app).
export const SEVERITY_HEX: Record<Severity, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#d97706",
  Low: "#64748b",
};

export const THREAT_HEX: Record<QuantumThreat, string> = {
  shor: "#dc2626",
  grover: "#d97706",
  classical: "#0ea5e9",
};

export const THREAT_LABEL: Record<QuantumThreat, string> = {
  shor: "Shor-broken",
  grover: "Grover-weakened",
  classical: "Classically weak",
};

export const THREAT_DESC: Record<QuantumThreat, string> = {
  shor: "Public-key crypto broken outright by Shor's algorithm — migrate to PQC.",
  grover: "Symmetric strength halved by Grover — double the key/hash size.",
  classical: "Already weak or broken by classical cryptanalysis.",
};

// Tailwind badge classes per severity.
export const SEVERITY_BADGE: Record<Severity, string> = {
  Critical:
    "bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/20",
  High: "bg-orange-100 text-orange-700 ring-orange-600/20 dark:bg-orange-500/15 dark:text-orange-300 dark:ring-orange-400/20",
  Medium:
    "bg-amber-100 text-amber-700 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/20",
  Low: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/20",
};

export const THREAT_BADGE: Record<QuantumThreat, string> = {
  shor: "bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/20",
  grover:
    "bg-amber-100 text-amber-700 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/20",
  classical:
    "bg-sky-100 text-sky-700 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300 dark:ring-sky-400/20",
};

export function gradeColor(grade: string): string {
  switch (grade) {
    case "A":
      return "#16a34a";
    case "B":
      return "#65a30d";
    case "C":
      return "#d97706";
    case "D":
      return "#ea580c";
    default:
      return "#dc2626";
  }
}

export function riskColor(score: number): string {
  if (score < 20) return "#16a34a";
  if (score < 40) return "#65a30d";
  if (score < 60) return "#d97706";
  if (score < 80) return "#ea580c";
  return "#dc2626";
}

export function difficultyBadge(level: string): string {
  switch (level) {
    case "Low":
      return "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-300";
    case "Medium":
      return "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300";
    case "High":
      return "bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300";
    default:
      return "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300";
  }
}

export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.max(1, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function toEntries(obj: Record<string, number>): { name: string; value: number }[] {
  return Object.entries(obj).map(([name, value]) => ({ name, value }));
}
