import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Pause, Play, Search, Cpu, Gauge, ShieldAlert } from "lucide-react";
import { listScans } from "@/lib/api";
import { useLiveSocket, type LiveFrame } from "@/lib/live";
import { Select, Input } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { StatusIndicator } from "@/components/common/StatusIndicator";
import { EmptyState } from "@/components/common/states";
import { cn } from "@/lib/cn";

// Event-type → accent rail (shared vocabulary with the dashboard feed).
const TYPE_RAIL: Record<string, string> = {
  SUBDOMAIN: "bg-primary", DNS_RECORD: "bg-primary/70", IP: "bg-secondary",
  OPEN_PORT: "bg-warning", HTTP_SERVICE: "bg-success", TECHNOLOGY: "bg-secondary",
  URL: "bg-primary/60", ENDPOINT: "bg-primary/60", PARAMETER: "bg-muted-foreground",
  FINDING_CANDIDATE: "bg-critical", ANOMALY: "bg-warning", EMAIL: "bg-secondary",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border last:border-0">
      <div className="px-3 pb-1.5 pt-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">{title}</div>
      <div className="px-3 pb-3">{children}</div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return (
    <div className="flex items-center justify-between py-0.5 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn("font-mono tabular-nums", tone ?? "text-foreground")}>{value}</span>
    </div>
  );
}

export default function Monitor() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");
  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { state, connected } = useLiveSocket(scanId || undefined);
  const lim = state.stats?.limiter;
  const pool = state.stats?.pool;
  const terminal = pool?.terminal ?? {};

  const [paused, setPaused] = useState(false);
  const [typeFilter, setTypeFilter] = useState("");
  const [q, setQ] = useState("");
  const frozen = useRef<LiveFrame[]>([]);

  // Freeze the stream snapshot when paused (display only — the scan keeps running).
  useEffect(() => { if (paused) frozen.current = state.events; }, [paused, state.events]);
  const source = paused ? frozen.current : state.events;

  const types = useMemo(() => {
    const s = new Set<string>();
    for (const e of state.events) if (e.kind === "event" && e.type) s.add(e.type);
    return [...s].sort();
  }, [state.events]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return source.filter((e) => {
      if (typeFilter && !(e.kind === "event" && e.type === typeFilter)) return false;
      if (needle) {
        const hay = `${e.type ?? ""} ${e.label ?? ""} ${e.event ?? ""} ${e.domain ?? ""} ${e.source ?? ""}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [source, typeFilter, q]);

  // Plan/module lifecycle frames (hybrid scheduler) for the left stages panel.
  const stages = useMemo(() => state.events.filter((e) => e.kind === "plan").slice(0, 14), [state.events]);
  const lastTs = state.events[0]?.ts;

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Live Operations</h1>
          <p className="text-xs text-muted-foreground">Reconnaissance operations cockpit</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusIndicator tone={connected ? "success" : "critical"} pulse={connected} label={connected ? "streaming" : "disconnected"} />
          <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-56">
            <option value="">Select a scan…</option>
            {(scans ?? []).map((s) => <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>)}
          </Select>
        </div>
      </div>

      {!scanId ? (
        <EmptyState icon={Gauge} title="Select a scan to monitor" />
      ) : (
        <div className="flex min-h-0 flex-1 gap-3">
          {/* Left — lifecycle / pool / stages */}
          <aside className="hidden w-60 shrink-0 flex-col overflow-y-auto rounded-lg border border-border bg-card lg:flex">
            <Section title="Worker pool">
              {pool ? (
                <>
                  <div className="mb-1.5 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${pool.max_workers ? Math.min(100, (pool.running / pool.max_workers) * 100) : 0}%` }} />
                  </div>
                  <Stat label="Workers" value={`${pool.running}/${pool.max_workers}`} />
                  <Stat label="Queued" value={pool.queued} tone={pool.queued ? "text-warning" : undefined} />
                  <Stat label="Accepted" value={pool.accepted} />
                  <Stat label="Deduped" value={pool.deduped} />
                </>
              ) : <p className="text-xs text-muted-foreground">No pool telemetry (non-hybrid scan).</p>}
            </Section>
            <Section title="Operations">
              <Stat label="Completed" value={terminal["COMPLETED"] ?? 0} tone="text-success" />
              <Stat label="Partial" value={terminal["PARTIAL"] ?? 0} tone={terminal["PARTIAL"] ? "text-warning" : undefined} />
              <Stat label="Failed" value={terminal["FAILED"] ?? 0} tone={terminal["FAILED"] ? "text-critical" : undefined} />
              <Stat label="Cancelled" value={terminal["CANCELLED"] ?? 0} />
            </Section>
            <Section title="Module activity">
              {stages.length === 0 ? (
                <p className="text-xs text-muted-foreground">No module lifecycle events.</p>
              ) : (
                <div className="space-y-1">
                  {stages.map((s, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-[11px]">
                      <StatusIndicator tone={s.status === "ok" || s.status === "completed" ? "success" : s.status === "failed" ? "critical" : "info"} />
                      <span className="truncate font-mono text-foreground">{s.module ?? s.event}</span>
                      <span className="ml-auto shrink-0 truncate text-muted-foreground">{s.target}</span>
                    </div>
                  ))}
                </div>
              )}
            </Section>
          </aside>

          {/* Centre — live event stream */}
          <div className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-lg border border-border bg-card">
            <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
              <button onClick={() => setPaused((p) => !p)}
                className={cn("flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition-colors",
                  paused ? "border-warning/40 bg-warning/10 text-warning" : "border-border text-muted-foreground hover:text-foreground")}>
                {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
                {paused ? "Resume" : "Pause"}
              </button>
              <Select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="h-8 w-40 text-xs">
                <option value="">All event types</option>
                {types.map((t) => <option key={t} value={t}>{t}</option>)}
              </Select>
              <div className="relative min-w-[8rem] flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search stream…" className="h-8 pl-8 text-xs" />
              </div>
              <span className="ml-auto shrink-0 text-[10px] tabular-nums text-muted-foreground/70">
                {shown.length}{paused && " (frozen)"} · {state.events.length} buffered
              </span>
            </div>
            <div className="flex-1 space-y-0.5 overflow-auto p-2">
              {shown.length === 0 ? (
                <EmptyState icon={Cpu} title={paused ? "Stream paused" : "Waiting for events…"}
                  description={paused ? "Display frozen — the scan keeps running." : "Events appear as the scan discovers assets."} />
              ) : (
                shown.map((e) => (
                  <div key={e.seq} className="flex animate-slide-in-right items-center gap-2.5 rounded-md px-1.5 py-1.5 text-xs transition-colors hover:bg-accent/40">
                    {e.kind === "lifecycle" ? (
                      <>
                        <span className="h-5 w-0.5 shrink-0 rounded-full bg-secondary" />
                        <Badge variant="secondary" className="shrink-0">lifecycle</Badge>
                        <span className="truncate text-foreground">{e.event} {e.domain ?? ""}</span>
                      </>
                    ) : e.kind === "plan" ? (
                      <>
                        <span className="h-5 w-0.5 shrink-0 rounded-full bg-muted-foreground" />
                        <Badge variant="outline" className="shrink-0 font-mono text-[10px]">plan</Badge>
                        <span className="truncate text-muted-foreground">{e.module ?? e.event} · {e.target} · {e.status}</span>
                      </>
                    ) : (
                      <>
                        <span className={cn("h-5 w-0.5 shrink-0 rounded-full", TYPE_RAIL[e.type ?? ""] ?? "bg-muted-foreground")} />
                        <Badge variant="outline" className="shrink-0 font-mono text-[10px]">{e.type}</Badge>
                        <span className="truncate text-muted-foreground" title={e.label}>{e.label}</span>
                        <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground/70">{e.source}</span>
                      </>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Right — telemetry */}
          <aside className="hidden w-60 shrink-0 flex-col overflow-y-auto rounded-lg border border-border bg-card xl:flex">
            <Section title="Connection">
              <div className="flex items-center justify-between text-xs">
                <StatusIndicator tone={connected ? "success" : "critical"} pulse={connected} label={connected ? "Streaming" : "Offline"} />
              </div>
              {lastTs && <Stat label="Last event" value={new Date(lastTs).toLocaleTimeString()} />}
            </Section>
            <Section title="Rate limiter">
              <Stat label="Requests" value={lim?.requests ?? "—"} />
              <Stat label="Backoff ×" value={lim?.penalty ?? "—"} tone={lim && lim.penalty > 1 ? "text-warning" : undefined} />
            </Section>
            <Section title="WAF detection">
              <div className="space-y-1.5 text-xs">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-muted-foreground">vendors</span>
                  {lim?.waf_vendors?.length ? lim.waf_vendors.map((v) => <Badge key={v} variant="warning">{v}</Badge>)
                    : <span className="text-muted-foreground/60">none</span>}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-muted-foreground">backed off</span>
                  {lim?.targets_backed_off?.length ? lim.targets_backed_off.map((t) => <Badge key={t} variant="warning" className="font-mono text-[10px]">{t}</Badge>)
                    : <span className="text-muted-foreground/60">none</span>}
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-muted-foreground">cooldown</span>
                  {lim?.targets_in_cooldown?.length ? lim.targets_in_cooldown.map((t) => <Badge key={t} variant="critical" className="font-mono text-[10px]">{t}</Badge>)
                    : <span className="text-muted-foreground/60">none</span>}
                </div>
              </div>
            </Section>
            {!lim && !pool && (
              <div className="p-3"><EmptyState icon={ShieldAlert} title="No telemetry yet" description="Rate-limiter stats stream once the scan is active." /></div>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
