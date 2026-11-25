import { cn } from "@/lib/cn";

export type StatusTone = "success" | "warning" | "critical" | "info" | "muted" | "running";

const TONE: Record<StatusTone, string> = {
  success: "bg-success text-success",
  warning: "bg-warning text-warning",
  critical: "bg-critical text-critical",
  info: "bg-primary text-primary",
  running: "bg-success text-success",
  muted: "bg-muted-foreground/50 text-muted-foreground",
};

/** A small status dot + optional label. `pulse` animates it (e.g. "running"). */
export function StatusIndicator({
  tone = "muted", label, pulse, className,
}: { tone?: StatusTone; label?: string; pulse?: boolean; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs", className)}>
      <span className={cn("h-2 w-2 shrink-0 rounded-full", TONE[tone], pulse && "pulse-ring")} />
      {label && <span className="text-muted-foreground">{label}</span>}
    </span>
  );
}

const SEV_TONE: Record<string, StatusTone> = {
  critical: "critical", high: "critical", medium: "warning", low: "success", info: "muted",
};

/** Severity → consistent tone across the app. */
export function severityTone(sev: string | null | undefined): StatusTone {
  return SEV_TONE[(sev || "").toLowerCase()] ?? "muted";
}
