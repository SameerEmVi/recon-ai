import { useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search, LogOut, Menu, ChevronRight } from "lucide-react";
import { getHealth } from "@/lib/api";
import { clearToken } from "@/lib/auth";
import { navItemForPath } from "./navigation";
import { cn } from "@/lib/cn";

interface TopbarProps {
  onOpenCommand: () => void;
  onToggleMobile: () => void;
}

export function Topbar({ onOpenCommand, onToggleMobile }: TopbarProps) {
  const { pathname } = useLocation();
  const current = navItemForPath(pathname);
  const { data, isError } = useQuery({
    queryKey: ["health"], queryFn: getHealth, refetchInterval: 10_000, retry: false,
  });
  const ok = !isError && data?.status === "ok";
  const active = data?.active_scans ?? 0;
  const live = ok && active > 0;

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-panel px-4">
      {/* Mobile nav toggle */}
      <button
        onClick={onToggleMobile}
        className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground lg:hidden"
        aria-label="Open navigation"
      >
        <Menu className="h-4 w-4" />
      </button>

      {/* Breadcrumbs */}
      <nav className="flex min-w-0 items-center gap-1.5 text-sm" aria-label="Breadcrumb">
        <span className="hidden text-muted-foreground sm:inline">Recon-AI</span>
        <ChevronRight className="hidden h-3.5 w-3.5 shrink-0 text-muted-foreground/50 sm:inline" />
        <span className="truncate font-medium text-foreground">{current?.label ?? "—"}</span>
      </nav>

      <div className="ml-auto flex items-center gap-2">
        {/* Command palette trigger */}
        <button
          onClick={onOpenCommand}
          className="flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
          aria-label="Open command palette"
        >
          <Search className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Search</span>
          <kbd className="hidden rounded border border-border px-1 font-mono text-[10px] md:inline">⌘K</kbd>
        </button>

        {/* Connection + active scans */}
        <div className="flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-xs">
          <span
            className={cn("h-2 w-2 rounded-full", ok ? "bg-success text-success" : "bg-critical", live && "pulse-ring")}
            aria-label={ok ? "backend connected" : "backend unreachable"}
          />
          <span className="hidden text-muted-foreground sm:inline">{ok ? "Connected" : "Offline"}</span>
          {ok && (
            <>
              <span className="text-border">·</span>
              <span className={cn("tabular-nums", live ? "text-success" : "text-muted-foreground")}>
                {active} active
              </span>
            </>
          )}
        </div>

        {/* Session lock */}
        <button
          onClick={() => { clearToken(); location.reload(); }}
          className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          title="Lock session (clear token)"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Lock</span>
        </button>
      </div>
    </header>
  );
}
