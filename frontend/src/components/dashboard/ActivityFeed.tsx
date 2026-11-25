import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/common/states";
import { Radio } from "lucide-react";

interface FeedEvent {
  type: string;
  label: string;
  source: string;
  at?: string | null;
}

// Event type → accent for the little leading rail.
const TYPE_RAIL: Record<string, string> = {
  SUBDOMAIN: "bg-primary", DNS_RECORD: "bg-primary/70", IP: "bg-secondary",
  OPEN_PORT: "bg-warning", HTTP_SERVICE: "bg-success", TECHNOLOGY: "bg-secondary",
  URL: "bg-primary/60", ENDPOINT: "bg-primary/60", PARAMETER: "bg-muted-foreground",
  FINDING_CANDIDATE: "bg-critical", ANOMALY: "bg-warning", EMAIL: "bg-secondary",
};

function rel(at?: string | null): string {
  if (!at) return "";
  const d = Date.now() - new Date(at).getTime();
  if (d < 60_000) return `${Math.max(1, Math.floor(d / 1000))}s`;
  if (d < 3_600_000) return `${Math.floor(d / 60_000)}m`;
  if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h`;
  return `${Math.floor(d / 86_400_000)}d`;
}

/** Recent reconnaissance events — the live-ish discovery feed on the dashboard. */
export function ActivityFeed({ events }: { events: FeedEvent[] }) {
  if (events.length === 0)
    return <EmptyState icon={Radio} title="No events yet" description="Reconnaissance events show here as a scan runs." />;

  return (
    <div className="max-h-80 space-y-0.5 overflow-auto pr-1">
      {events.map((e, i) => (
        <div key={i} className="flex items-center gap-2.5 rounded-md px-1.5 py-1.5 text-xs transition-colors hover:bg-accent/40">
          <span className={`h-5 w-0.5 shrink-0 rounded-full ${TYPE_RAIL[e.type] ?? "bg-muted-foreground"}`} />
          <Badge variant="outline" className="shrink-0 font-mono text-[10px]">{e.type}</Badge>
          <span className="truncate text-muted-foreground" title={e.label}>{e.label}</span>
          <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground/70">{e.source}</span>
          {e.at && <span className="shrink-0 tabular-nums text-[10px] text-muted-foreground/50">{rel(e.at)}</span>}
        </div>
      ))}
    </div>
  );
}
