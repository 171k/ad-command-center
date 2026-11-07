import { ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  Crosshair, Shield, Terminal, Radar, FileSearch, Settings as Cog,
  LogOut, CircleDot,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { useLiveSync } from "../lib/sse";
import { useQuery } from "@tanstack/react-query";
import { get } from "../lib/api";

const SECTIONS = [
  { to: "/attack", label: "Attack", icon: Crosshair, desc: "Targets · Recon · Exploits" },
  { to: "/defense", label: "Defense", icon: Shield, desc: "Code analysis · Patches" },
  { to: "/automation", label: "Automation", icon: Terminal, desc: "Scripts · Utilities · Health" },
  { to: "/soc", label: "Network / SOC", icon: Radar, desc: "Offenses · Traffic · Evidence" },
];
const SECONDARY = [
  { to: "/findings", label: "Findings", icon: FileSearch },
  { to: "/settings", label: "Settings", icon: Cog },
];

export function Layout({ children }: { children: ReactNode }) {
  useLiveSync();
  const { label, logout } = useAuth();
  const nav = useNavigate();
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: () => get("/system/stats") });

  return (
    <div className="h-full flex">
      {/* Sidebar */}
      <aside className="w-14 lg:w-60 shrink-0 bg-bg-raised border-r border-line flex flex-col transition-[width]">
        <div className="h-14 flex items-center gap-2.5 px-3 lg:px-4 border-b border-line">
          <div className="h-7 w-7 shrink-0 rounded bg-accent/15 border border-accent/30 grid place-items-center">
            <CircleDot className="h-4 w-4 text-accent" />
          </div>
          <div className="leading-tight hidden lg:block">
            <div className="text-sm font-semibold tracking-tight">A&amp;D Command</div>
            <div className="text-2xs text-ink-faint">Operations Center</div>
          </div>
        </div>

        <nav className="flex-1 overflow-auto py-3 px-2 space-y-1">
          <div className="px-2 text-2xs font-semibold uppercase tracking-wider text-ink-faint mb-1 hidden lg:block">
            Workspaces
          </div>
          {SECTIONS.map((s) => (
            <NavLink
              key={s.to}
              to={s.to}
              className={({ isActive }) =>
                `flex items-start gap-2.5 rounded px-2 py-2 transition-colors ${
                  isActive ? "bg-accent/10 text-ink" : "text-ink-dim hover:bg-bg-hover hover:text-ink"
                }`
              }
              title={s.label}
            >
              {({ isActive }) => (
                <>
                  <s.icon className={`h-4 w-4 mt-0.5 shrink-0 ${isActive ? "text-accent" : ""}`} />
                  <div className="min-w-0 hidden lg:block">
                    <div className="text-sm font-medium leading-tight">{s.label}</div>
                    <div className="text-2xs text-ink-faint truncate">{s.desc}</div>
                  </div>
                </>
              )}
            </NavLink>
          ))}

          <div className="px-2 pt-4 text-2xs font-semibold uppercase tracking-wider text-ink-faint mb-1 hidden lg:block">
            Shared
          </div>
          {SECONDARY.map((s) => (
            <NavLink
              key={s.to}
              to={s.to}
              title={s.label}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded px-2 py-1.5 text-sm transition-colors ${
                  isActive ? "bg-accent/10 text-ink" : "text-ink-dim hover:bg-bg-hover hover:text-ink"
                }`
              }
            >
              <s.icon className="h-4 w-4 shrink-0" />
              <span className="hidden lg:inline">{s.label}</span>
              {s.to === "/findings" && stats?.findings_open > 0 && (
                <span className="ml-auto tag border-line-strong text-ink-dim hidden lg:inline-flex">{stats.findings_open}</span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line p-2">
          <div className="flex items-center gap-2 px-1 lg:px-2 py-1.5 text-sm">
            <div className="h-6 w-6 shrink-0 rounded-full bg-accent/15 border border-accent/30 grid place-items-center text-2xs font-semibold text-accent">
              {(label ?? "T").slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1 hidden lg:block">
              <div className="text-xs font-medium truncate">{label ?? "Team"}</div>
              <div className="text-2xs text-ink-faint">shared account</div>
            </div>
            <button className="btn btn-ghost btn-sm" title="Log out" onClick={() => logout().then(() => nav("/"))}>
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 min-w-0 flex flex-col">{children}</main>
    </div>
  );
}
