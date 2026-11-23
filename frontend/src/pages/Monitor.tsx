import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listScans } from "@/lib/api";
import { useLiveSocket } from "@/lib/live";
import { StatTile } from "@/components/StatTile";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

export default function Monitor() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  // Default to a running scan, else the most recent.
  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { state, connected } = useLiveSocket(scanId || undefined);
  const lim = state.stats?.limiter;
  const pool = state.stats?.pool;
  const terminal = pool?.terminal ?? {};

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Live Monitor</h1>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span
              className={cn(
                "h-2 w-2 rounded-full transition-colors",
                connected ? "bg-success text-success pulse-ring" : "bg-critical"
              )}
            />
            {connected ? "streaming" : "disconnected"}
          </div>
          <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-64">
            <option value="">Select a scan…</option>
            {(scans ?? []).map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.domain} · {s.status}
              </option>
            ))}
          </Select>
        </div>
      </div>

      {!scanId ? (
        <p className="animate-fade-in text-sm text-muted-foreground">Select a scan to monitor.</p>
      ) : (
        <>
          <div className="stagger grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <StatTile label="Requests" value={lim?.requests ?? "—"} />
            <StatTile label="Backoff ×" value={lim?.penalty ?? "—"}
              accent={lim && lim.penalty > 1 ? "warning" : undefined} />
            <StatTile label="Workers" value={pool ? `${pool.running}/${pool.max_workers}` : "—"} />
            <StatTile label="Queued" value={pool?.queued ?? "—"} />
            <StatTile label="Completed" value={terminal["COMPLETED"] ?? 0} accent="success" />
            <StatTile label="Failed" value={(terminal["FAILED"] ?? 0) + (terminal["CANCELLED"] ?? 0)}
              accent={(terminal["FAILED"] ?? 0) ? "critical" : undefined} />
          </div>

          <div className="stagger grid gap-4 lg:grid-cols-3">
            {/* WAF / rate-limit */}
            <Card className="hover-lift">
              <CardHeader><CardTitle>WAF / rate-limit</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-xs">
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-muted-foreground">vendors:</span>
                  {lim?.waf_vendors?.length
                    ? lim.waf_vendors.map((v) => <Badge key={v} variant="warning">{v}</Badge>)
                    : <span className="text-muted-foreground">none</span>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-muted-foreground">backed off:</span>
                  {lim?.targets_backed_off?.length
                    ? lim.targets_backed_off.map((t) => <Badge key={t} variant="warning">{t}</Badge>)
                    : <span className="text-muted-foreground">none</span>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <span className="text-muted-foreground">cooldown:</span>
                  {lim?.targets_in_cooldown?.length
                    ? lim.targets_in_cooldown.map((t) => <Badge key={t} variant="critical">{t}</Badge>)
                    : <span className="text-muted-foreground">none</span>}
                </div>
              </CardContent>
            </Card>

            {/* Live event stream */}
            <Card className="hover-lift lg:col-span-2">
              <CardHeader className="flex-row items-center justify-between">
                <CardTitle>Live event stream</CardTitle>
                {state.events.length > 0 && (
                  <span className="text-[10px] tabular-nums text-muted-foreground/70">
                    {state.events.length} buffered
                  </span>
                )}
              </CardHeader>
              <CardContent className="max-h-80 space-y-1 overflow-auto">
                {state.events.length === 0 ? (
                  <p className="animate-fade-in text-sm text-muted-foreground">
                    Waiting for events… (if the scan has finished, there may be none to stream)
                  </p>
                ) : (
                  state.events.map((e) => (
                    <div
                      key={e.seq}
                      className="flex animate-slide-in-right items-center gap-2 rounded px-1 py-0.5 text-xs transition-colors hover:bg-accent/40"
                    >
                      {e.kind === "lifecycle" ? (
                        <Badge variant="outline" className="shrink-0">lifecycle</Badge>
                      ) : (
                        <Badge variant="outline" className="shrink-0 font-mono">{e.type}</Badge>
                      )}
                      <span className="truncate text-muted-foreground">
                        {e.kind === "lifecycle" ? `${e.event} ${e.domain ?? ""}` : e.label}
                      </span>
                      <span className="ml-auto shrink-0 text-[10px] text-muted-foreground/70">
                        {e.source}
                      </span>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
