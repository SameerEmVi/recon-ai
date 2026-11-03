import { NavLink, Outlet } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  Crosshair,
  Activity,
  Server,
  ShieldAlert,
  ScrollText,
  Settings as SettingsIcon,
  LogOut,
} from "lucide-react";
import { getHealth } from "@/lib/api";
import { clearToken } from "@/lib/auth";
import { cn } from "@/lib/cn";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: Crosshair },
  { to: "/monitor", label: "Live Monitor", icon: Activity },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/diagnostics", label: "Diagnostics", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

function HealthDot() {
  const { data, isError } = useQuery({
    queryKey: ["health"],
    queryFn: getHealth,
    refetchInterval: 10_000,
    retry: false,
  });
  const ok = !isError && data?.status === "ok";
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <span
        className={cn("h-2 w-2 rounded-full", ok ? "bg-success" : "bg-critical")}
        aria-label={ok ? "backend connected" : "backend unreachable"}
      />
      {ok ? `connected · ${data?.active_scans ?? 0} active` : "disconnected"}
    </div>
  );
}

export function Layout() {
  return (
    <div className="flex h-full">
      <aside className="flex w-56 flex-col border-r border-border bg-panel">
        <div className="flex h-14 items-center gap-2 border-b border-border px-4">
          <Crosshair className="h-5 w-5 text-primary" />
          <span className="font-mono text-sm font-semibold tracking-widest text-foreground">
            RECON<span className="text-primary">-AI</span>
          </span>
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent text-foreground"
                    : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-border p-3 text-[11px] text-muted-foreground">
          Authorized targets only.
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b border-border bg-panel px-5">
          <HealthDot />
          <button
            onClick={() => {
              clearToken();
              location.reload();
            }}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <LogOut className="h-3.5 w-3.5" />
            Lock
          </button>
        </header>
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
