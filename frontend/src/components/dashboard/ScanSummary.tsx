import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/common/states";
import { StatusIndicator, type StatusTone } from "@/components/common/StatusIndicator";
import { Crosshair } from "lucide-react";

interface RecentScan {
  scan_id: string;
  domain: string;
  status: string;
  mode: string;
  created_at?: string | null;
}

const STATUS_TONE: Record<string, StatusTone> = {
  running: "running", complete: "success", failed: "critical", cancelled: "warning",
};

/** Recent scans + aggregate job state. Clicking a scan opens Live Operations. */
export function ScanSummary({ scans, jobs }: { scans: RecentScan[]; jobs: Record<string, number> }) {
  const navigate = useNavigate();
  const jobEntries = Object.entries(jobs).filter(([, n]) => n > 0);

  if (scans.length === 0)
    return <EmptyState icon={Crosshair} title="No scans this session"
      description="Launch one from Scan Management." />;

  return (
    <div className="space-y-1">
      {scans.slice(0, 8).map((s) => (
        <button
          key={s.scan_id}
          onClick={() => navigate("/monitor")}
          className="flex w-full items-center gap-2.5 rounded-md px-1.5 py-1.5 text-left text-xs transition-colors hover:bg-accent/40"
        >
          <StatusIndicator tone={STATUS_TONE[s.status] ?? "muted"} pulse={s.status === "running"} />
          <span className="truncate font-medium text-foreground">{s.domain}</span>
          <Badge variant="outline" className="ml-auto shrink-0 text-[10px]">{s.mode}</Badge>
          <span className="shrink-0 text-[10px] capitalize text-muted-foreground">{s.status}</span>
        </button>
      ))}
      {jobEntries.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5 border-t border-border pt-2">
          {jobEntries.map(([state, n]) => (
            <Badge key={state} variant="outline" className="font-mono text-[10px]">
              {state.toLowerCase()}: <span className="tabular-nums">{n}</span>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
