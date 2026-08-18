import { ReactNode, useState } from "react";
import { NavLink } from "react-router-dom";
import {
  Boxes,
  ClipboardCheck,
  FileText,
  LayoutDashboard,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Route,
  ScanLine,
  Search,
  ShieldCheck,
  Sparkles,
  Sun,
  Table2,
} from "lucide-react";
import { useTheme } from "../hooks/useTheme";
import { openPalette } from "../hooks/useHotkeys";
import { CommandPalette } from "./CommandPalette";
import { Notifications } from "./Notifications";

const NAV: { section: string; items: { to: string; label: string; icon: any; end?: boolean }[] }[] = [
  {
    section: "Overview",
    items: [{ to: "/", label: "Dashboard", icon: LayoutDashboard, end: true }],
  },
  {
    section: "Analysis",
    items: [
      { to: "/findings", label: "Findings", icon: Table2 },
      { to: "/certificates", label: "Certificates", icon: ShieldCheck },
      { to: "/dependencies", label: "Dependencies", icon: Boxes },
      { to: "/analytics", label: "Analytics", icon: Network },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { to: "/advisor", label: "AI Advisor", icon: Sparkles },
      { to: "/migration", label: "Migration", icon: Route },
      { to: "/compliance", label: "Compliance", icon: ClipboardCheck },
      { to: "/algorithms", label: "PQC Catalog", icon: Boxes },
    ],
  },
  {
    section: "Actions",
    items: [
      { to: "/scan", label: "New Scan", icon: ScanLine },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
];

export function Layout({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  const { theme, toggle } = useTheme();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("qs-sidebar") === "collapsed"
  );

  const toggleSidebar = () => {
    setCollapsed((c) => {
      localStorage.setItem("qs-sidebar", !c ? "collapsed" : "expanded");
      return !c;
    });
  };

  return (
    <div className="flex min-h-screen">
      <CommandPalette />

      {/* Sidebar */}
      <aside
        className={`sticky top-0 hidden h-screen shrink-0 flex-col border-r border-white/5 bg-ink-900/70 backdrop-blur-xl transition-all duration-200 md:flex ${
          collapsed ? "w-[68px]" : "w-64"
        }`}
      >
        <div className="flex items-center gap-2.5 px-4 py-4">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-brand-400 to-brand-600 shadow-lg shadow-brand-600/40">
            <ShieldCheck className="h-5 w-5 text-white" />
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <p className="text-[15px] font-bold leading-tight text-white">QuantumShield</p>
              <p className="text-[10px] font-medium uppercase tracking-wider text-accent-400">
                Quantum-Safe SOC
              </p>
            </div>
          )}
        </div>

        <nav className="flex flex-1 flex-col gap-4 overflow-y-auto px-3 py-2">
          {NAV.map((group) => (
            <div key={group.section}>
              {!collapsed && (
                <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                  {group.section}
                </p>
              )}
              <div className="flex flex-col gap-0.5">
                {group.items.map(({ to, label, icon: Icon, end }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={end}
                    title={collapsed ? label : undefined}
                    className={({ isActive }) =>
                      `nav-link ${isActive ? "nav-link-active" : ""} ${collapsed ? "justify-center !px-0" : ""}`
                    }
                  >
                    <Icon className="h-[18px] w-[18px] shrink-0" />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {!collapsed && (
          <div className="m-3 rounded-xl border border-white/5 bg-white/[0.03] p-3 text-xs text-slate-400">
            <p className="font-semibold text-slate-300">NIST PQC ready</p>
            <p className="mt-1 leading-relaxed">ML-KEM · ML-DSA · SLH-DSA (FIPS 203/204/205)</p>
          </div>
        )}
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center gap-4 border-b border-white/5 bg-white/60 px-4 py-3 backdrop-blur-xl dark:bg-ink-900/60 sm:px-6">
          <button onClick={toggleSidebar} className="btn-ghost hidden h-9 w-9 !px-0 md:flex" aria-label="Toggle sidebar">
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          </button>

          <div className="min-w-0 flex-1">
            <h1 className="truncate text-lg font-bold text-slate-900 dark:text-white">{title}</h1>
            {subtitle && <p className="truncate text-xs text-slate-500 dark:text-slate-400">{subtitle}</p>}
          </div>

          <button
            onClick={openPalette}
            className="hidden items-center gap-2 rounded-lg border border-slate-300/70 bg-white/60 px-3 py-2 text-sm text-slate-500 transition hover:bg-white dark:border-white/10 dark:bg-white/5 dark:text-slate-400 dark:hover:bg-white/10 lg:flex"
          >
            <Search className="h-4 w-4" />
            <span>Search or jump to…</span>
            <kbd className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500 dark:bg-white/10">
              Ctrl K
            </kbd>
          </button>

          <button onClick={openPalette} className="btn-ghost h-9 w-9 !px-0 lg:hidden" aria-label="Search">
            <Search className="h-4 w-4" />
          </button>

          <Notifications />

          <button onClick={toggle} className="btn-ghost h-9 w-9 !px-0" aria-label="Toggle theme">
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </header>

        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6">{children}</main>
      </div>
    </div>
  );
}
