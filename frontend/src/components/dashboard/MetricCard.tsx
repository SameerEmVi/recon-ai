import { useNavigate } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";
import { useCountUp } from "@/lib/useCountUp";
import { cn } from "@/lib/cn";

export type MetricTone = "default" | "primary" | "success" | "warning" | "critical";

const TONE: Record<MetricTone, { icon: string; value: string }> = {
  default: { icon: "text-muted-foreground bg-muted/40", value: "text-foreground" },
  primary: { icon: "text-primary bg-primary/12", value: "text-foreground" },
  success: { icon: "text-success bg-success/12", value: "text-foreground" },
  warning: { icon: "text-warning bg-warning/12", value: "text-warning" },
  critical: { icon: "text-critical bg-critical/12", value: "text-critical" },
};

/**
 * A command-centre KPI card. Clickable (navigates to `to`) when a destination is
 * given — so every metric drills into the page that explains it. The value
 * animates up; counters use tabular mono numerals.
 */
export function MetricCard({
  label, value, icon: Icon, tone = "default", to, hint,
}: {
  label: string;
  value: number;
  icon?: React.ComponentType<{ className?: string }>;
  tone?: MetricTone;
  to?: string;
  hint?: string;
}) {
  const navigate = useNavigate();
  const shown = useCountUp(value);
  const t = TONE[tone];
  const clickable = !!to;

  return (
    <div
      onClick={clickable ? () => navigate(to!) : undefined}
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={clickable ? (e) => { if (e.key === "Enter") navigate(to!); } : undefined}
      className={cn(
        "group relative rounded-xl border border-border bg-card p-4",
        clickable && "hover-lift cursor-pointer"
      )}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        {Icon && (
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", t.icon)}>
            <Icon className="h-4 w-4" />
          </span>
        )}
      </div>
      <div className={cn("mt-2 font-mono text-2xl font-semibold tabular-nums", t.value)}>
        {shown.toLocaleString()}
      </div>
      <div className="mt-0.5 flex items-center gap-1 text-[11px] text-muted-foreground">
        {hint && <span className="truncate">{hint}</span>}
        {clickable && (
          <ArrowUpRight className="ml-auto h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
        )}
      </div>
    </div>
  );
}
