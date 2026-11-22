import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listScans, getPlan } from "@/lib/api";
import { useLiveSocket } from "@/lib/live";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/cn";

// Job state → chip style, using the theme's semantic colors.
const STATE_STYLE: Record<string, string> = {
  RUNNING: "border-primary/40 bg-primary/10 text-primary",
  VALIDATING: "border-primary/30 bg-primary/5 text-primary/90",
  QUEUED: "border-border bg-accent/40 text-muted-foreground",
  PAUSED: "border-warning/40 bg-warning/10 text-warning",
  COMPLETED: "border-success/40 bg-success/10 text-success",
  PARTIAL: "border-warning/40 bg-warning/10 text-warning",
  FAILED: "border-critical/40 bg-critical/10 text-critical",
  CANCELLED: "border-border bg-transparent text-muted-foreground/70",
  OUT_OF_SCOPE: "border-border bg-transparent text-muted-foreground/60",
};
const STATE_ORDER = [
  "RUNNING", "VALIDATING", "QUEUED", "PAUSED", "COMPLETED", "PARTIAL",
  "FAILED", "CANCELLED", "OUT_OF_SCOPE",
];
const rank = (s: string | null) => {
  const i = STATE_ORDER.indexOf(s ?? "QUEUED");
  return i === -1 ? STATE_ORDER.length : i;
};

// Scheduler event name → the state it implies, when a frame omits `status`.
const EVENT_STATE: Record<string, string> = {
  target_discovered: "QUEUED",
  subdomain_job_queued: "QUEUED",
  target_started: "RUNNING",
  module_started: "RUNNING",
  module_completed: "COMPLETED",
  target_completed: "COMPLETED",
  module_failed: "FAILED",
  target_paused: "PAUSED",
  target_out_of_scope: "OUT_OF_SCOPE",
};

interface TState {
  state: string | null;
  modules: Map<string, { state: string; error: string | null }>;
}

function StateChip({ state, label }: { state: string | null; label?: string }) {
  const s = state ?? "QUEUED";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px]",
        STATE_STYLE[s] ?? "border-border text-muted-foreground"
      )}
    >
      {s === "RUNNING" && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />}
      {label ?? s}
    </span>
  );
}

export default function Plan() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data: plan } = useQuery({
    queryKey: ["plan", scanId],
    queryFn: () => getPlan(scanId || undefined),
    enabled: !!scanId,
    refetchInterval: 10_000, // backstop; live frames do the fast updates
  });

  const { state, connected } = useLiveSocket(scanId || undefined);

  const targetsRef = useRef<Map<string, TState>>(new Map());
  const processedSeq = useRef(0);
  const [, setTick] = useState(0);
  const [sawPlan, setSawPlan] = useState(false);

  // Rebuild from the REST snapshot when the scan changes / it refetches.
  useEffect(() => {
    const m = new Map<string, TState>();
    for (const t of plan?.targets ?? []) {
      const mods = new Map<string, { state: string; error: string | null }>();
      for (const mod of t.modules) mods.set(mod.module, { state: mod.state, error: mod.error });
      m.set(t.target, { state: t.state, modules: mods });
    }
    targetsRef.current = m;
    processedSeq.current = 0;
    setTick((n) => n + 1);
  }, [plan, scanId]);

  // Fold live scheduler frames in.
  useEffect(() => {
    const fresh = state.events.filter(
      (f) => f.kind === "plan" && f.seq > processedSeq.current && f.target
    );
    if (fresh.length === 0) return;
    processedSeq.current = Math.max(processedSeq.current, ...state.events.map((f) => f.seq));
    const m = targetsRef.current;
    for (const f of fresh) {
      const target = f.target!;
      const st = f.status ?? EVENT_STATE[f.event ?? ""] ?? "QUEUED";
      let t = m.get(target);
      if (!t) {
        t = { state: null, modules: new Map() };
        m.set(target, t);
      }
      if (f.module) t.modules.set(f.module, { state: st, error: null });
      else t.state = st;
    }
    setSawPlan(true);
    setTick((n) => n + 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.lastSeq]);

  const targets = useMemo(() => {
    const rows = Array.from(targetsRef.current.entries()).map(([target, t]) => ({
      target,
      state: t.state,
      modules: Array.from(t.modules.entries())
        .map(([module, m]) => ({ module, ...m }))
        .sort((a, b) => rank(a.state) - rank(b.state) || a.module.localeCompare(b.module)),
    }));
    rows.sort(
      (a, b) => rank(a.state) - rank(b.state) || b.modules.length - a.modules.length ||
        a.target.localeCompare(b.target)
    );
    return rows;
    // recompute on every tick
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetsRef.current.size, state.lastSeq, plan]);

  const summary = useMemo(() => {
    const by: Record<string, number> = {};
    for (const t of targets) {
      for (const m of t.modules) by[m.state] = (by[m.state] ?? 0) + 1;
    }
    return by;
  }, [targets]);

  const isHybrid = (plan?.is_hybrid ?? false) || sawPlan;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Plan &amp; Progress</h1>
          <p className="text-xs text-muted-foreground">
            Recon plan as it executes — {targets.length} target(s)
            {plan?.scan ? ` · ${plan.scan.domain}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span className={cn("h-2 w-2 rounded-full", connected ? "bg-success" : "bg-critical")} />
            {connected ? "streaming" : "disconnected"}
          </div>
          <select
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="h-9 w-64 rounded-md border border-border bg-background px-2 text-sm"
          >
            <option value="">Select a scan…</option>
            {(scans ?? []).map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.domain} · {s.status}
              </option>
            ))}
          </select>
        </div>
      </div>

      {Object.keys(summary).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {STATE_ORDER.filter((s) => summary[s]).map((s) => (
            <div key={s} className="flex items-center gap-1.5">
              <StateChip state={s} />
              <span className="text-xs tabular-nums text-foreground">{summary[s]}</span>
            </div>
          ))}
        </div>
      )}

      {!scanId ? (
        <p className="text-sm text-muted-foreground">Select a scan to view its plan.</p>
      ) : !isHybrid && targets.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No per-module execution plan recorded for this scan.
            <br />
            Per-target / per-module job state is tracked for <span className="font-mono">--hybrid</span>{" "}
            scans; run with the hybrid engine to populate this board.
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {targets.map((t) => (
            <Card key={t.target}>
              <CardHeader className="flex-row items-center justify-between gap-2 space-y-0 pb-2">
                <CardTitle className="truncate font-mono text-sm" title={t.target}>
                  {t.target}
                </CardTitle>
                <StateChip state={t.state} />
              </CardHeader>
              <CardContent className="pt-0">
                {t.modules.length === 0 ? (
                  <span className="text-xs text-muted-foreground">no modules yet</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {t.modules.map((m) => (
                      <span
                        key={m.module}
                        title={m.error ? `${m.module}: ${m.error}` : m.module}
                        className={cn(
                          "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px]",
                          STATE_STYLE[m.state] ?? "border-border text-muted-foreground"
                        )}
                      >
                        {m.state === "RUNNING" && (
                          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
                        )}
                        {m.module}
                      </span>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
