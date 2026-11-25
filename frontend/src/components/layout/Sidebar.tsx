import { NavLink } from "react-router-dom";
import { Crosshair, PanelLeftClose, PanelLeft } from "lucide-react";
import { NAV_GROUPS } from "./navigation";
import { cn } from "@/lib/cn";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  /** Mobile drawer: when true the sidebar is shown as an overlay. */
  mobileOpen?: boolean;
  onNavigate?: () => void;
}

export function Sidebar({ collapsed, onToggle, onNavigate }: SidebarProps) {
  return (
    <aside
      className={cn(
        "flex h-full flex-col border-r border-border bg-panel transition-[width] duration-200 ease-out",
        collapsed ? "w-[64px]" : "w-60"
      )}
    >
      {/* Brand + collapse toggle */}
      <div className="flex h-14 items-center gap-2 border-b border-border px-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
          <Crosshair className="h-5 w-5" />
        </div>
        {!collapsed && (
          <span className="flex-1 truncate font-mono text-sm font-semibold tracking-widest text-foreground">
            RECON<span className="text-primary">-AI</span>
          </span>
        )}
        <button
          onClick={onToggle}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={cn(
            "flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
            collapsed && "mx-auto"
          )}
        >
          {collapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </button>
      </div>

      {/* Grouped navigation */}
      <nav className="flex-1 space-y-4 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="space-y-0.5">
            {collapsed ? (
              <div className="mx-auto my-1 h-px w-6 bg-border/70" />
            ) : (
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/60">
                {group.label}
              </div>
            )}
            {group.items.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                onClick={onNavigate}
                title={collapsed ? label : undefined}
                className={({ isActive }) =>
                  cn(
                    "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-all duration-150",
                    collapsed && "justify-center px-0",
                    isActive
                      ? "bg-accent text-foreground"
                      : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span
                      className={cn(
                        "absolute left-0 top-1/2 h-0 w-0.5 -translate-y-1/2 rounded-full bg-primary transition-all duration-200",
                        isActive && "h-5"
                      )}
                    />
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0 transition-transform duration-150 group-hover:scale-110",
                        isActive && "text-primary"
                      )}
                    />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {!collapsed && (
        <div className="border-t border-border p-3 text-[11px] text-muted-foreground">
          Authorized targets only.
        </div>
      )}
    </aside>
  );
}
