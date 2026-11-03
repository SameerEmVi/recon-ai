import { useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { getDiagnostics, checkProxy, type DiagRecord } from "@/lib/api";
import { StatTile } from "@/components/StatTile";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

const STREAMS = ["events", "errors", "http"] as const;

function levelVariant(l?: string): "critical" | "warning" | "default" {
  if (l === "ERROR" || l === "CRITICAL") return "critical";
  if (l === "WARNING") return "warning";
  return "default";
}
function statusVariant(s?: number | null): "success" | "warning" | "critical" | "default" {
  if (s == null) return "default";
  if (s >= 500) return "critical";
  if (s >= 400) return "warning";
  if (s >= 200 && s < 400) return "success";
  return "default";
}

export default function Diagnostics() {
  const [runId, setRunId] = useState<string>("");
  const [stream, setStream] = useState<string>("events");
  const [module, setModule] = useState<string>("");
  const [q, setQ] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["diagnostics", runId, stream, module],
    queryFn: () => getDiagnostics({ run_id: runId || undefined, stream, module: module || undefined }),
    refetchInterval: 10_000,
  });

  const [proxyUrl, setProxyUrl] = useState("http://127.0.0.1:8080");
  const proxyMut = useMutation({ mutationFn: () => checkProxy(proxyUrl) });

  const run = data?.run;
  const runs = data?.available_runs ?? [];

  const needle = q.trim().toLowerCase();
  const records = useMemo(() => {
    let rows: DiagRecord[] = data?.records ?? [];
    if (needle)
      rows = rows.filter((r) =>
        JSON.stringify(r).toLowerCase().includes(needle)
      );
    return rows;
  }, [data, needle]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Diagnostics</h1>
        <Select value={runId} onChange={(e) => setRunId(e.target.value)} className="w-72">
          <option value="">Most recent run</option>
          {runs.map((r) => (
            <option key={r.run_id} value={r.run_id}>
              {r.domain} · run-{r.run_id.slice(0, 8)} · {r.total_errors} err
            </option>
          ))}
        </Select>
      </div>

      {/* Proxy connectivity probe */}
      <Card>
        <CardHeader><CardTitle>Proxy connectivity check</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Input value={proxyUrl} onChange={(e) => setProxyUrl(e.target.value)}
            className="w-64 font-mono text-xs" placeholder="http://127.0.0.1:8080" />
          <Button variant="outline" onClick={() => proxyMut.mutate()} disabled={proxyMut.isPending}>
            {proxyMut.isPending ? "Checking…" : "Test"}
          </Button>
          {proxyMut.data && (
            <div className="flex items-center gap-2 text-xs">
              <span className={cn("h-2 w-2 rounded-full", proxyMut.data.ok ? "bg-success" : "bg-critical")} />
              <span className="font-mono text-muted-foreground">{proxyMut.data.target}</span>
              <span className={proxyMut.data.ok ? "text-success" : "text-critical"}>{proxyMut.data.message}</span>
            </div>
          )}
          {proxyMut.isError && <span className="text-xs text-critical">probe failed</span>}
        </CardContent>
      </Card>

      {!run ? (
        <p className="text-sm text-muted-foreground">
          No diagnostics found. Run a scan with <span className="font-mono">--debug</span> or a proxy, or set{" "}
          <span className="font-mono">RECON_AI_RESULTS_DIR</span>.
        </p>
      ) : (
        <>
          {/* Error summary */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile label="Total errors" value={run.total_errors}
              accent={run.total_errors ? "critical" : "success"} />
            <StatTile label="Events" value={run.streams?.events ?? 0} />
            <StatTile label="HTTP" value={run.streams?.http ?? 0} />
            <StatTile label="Error records" value={run.streams?.errors ?? 0}
              accent={(run.streams?.errors ?? 0) ? "warning" : undefined} />
          </div>

          {(Object.keys(run.errors_by_category).length > 0 ||
            Object.keys(run.errors_by_module).length > 0) && (
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader><CardTitle>Errors by category</CardTitle></CardHeader>
                <CardContent className="flex flex-wrap gap-1.5">
                  {Object.entries(run.errors_by_category).map(([c, n]) => (
                    <Badge key={c} variant="warning">{c}: {n}</Badge>
                  ))}
                  {Object.keys(run.errors_by_category).length === 0 && (
                    <span className="text-xs text-muted-foreground">none</span>)}
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>Errors by module</CardTitle></CardHeader>
                <CardContent className="flex flex-wrap gap-1.5">
                  {Object.entries(run.errors_by_module).map(([m, n]) => (
                    <Badge key={m} variant="critical">{m}: {n}</Badge>
                  ))}
                  {Object.keys(run.errors_by_module).length === 0 && (
                    <span className="text-xs text-muted-foreground">none</span>)}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Stream viewer */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex gap-1 rounded-md border border-border bg-card p-1">
              {STREAMS.map((s) => (
                <button key={s} onClick={() => setStream(s)}
                  className={cn("rounded px-3 py-1 text-xs font-medium transition-colors",
                    stream === s ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
                  {s}
                </button>
              ))}
            </div>
            <Input placeholder="module (exact)" value={module} onChange={(e) => setModule(e.target.value)}
              className="w-40" />
            <Input placeholder="Search records…" value={q} onChange={(e) => setQ(e.target.value)}
              className="w-56" />
            <span className="text-xs text-muted-foreground">{records.length} shown</span>
          </div>

          <Card>
            <CardHeader><CardTitle className="font-mono">{stream}.jsonl</CardTitle></CardHeader>
            <CardContent className="max-h-[32rem] overflow-auto">
              {isLoading ? (
                <p className="text-sm text-muted-foreground">Loading…</p>
              ) : records.length === 0 ? (
                <p className="text-sm text-muted-foreground">No records.</p>
              ) : (
                <div className="space-y-1">
                  {records.map((r, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px]">
                      <span className="shrink-0 font-mono text-muted-foreground/60">
                        {(r.timestamp ?? "").slice(11, 19)}
                      </span>
                      {r.level && <Badge variant={levelVariant(r.level)} className="shrink-0">{r.level}</Badge>}
                      {r.method && <Badge variant="outline" className="shrink-0 font-mono">{r.method}</Badge>}
                      {r.status != null && (
                        <Badge variant={statusVariant(r.status)} className="shrink-0 font-mono">{r.status}</Badge>
                      )}
                      <span className="shrink-0 font-mono text-foreground">{r.event}</span>
                      {r.target && <span className="truncate font-mono text-muted-foreground">{r.target}</span>}
                      {r.error_type && <span className="shrink-0 text-critical">{r.error_type}</span>}
                      <span className="ml-auto shrink-0 text-muted-foreground/60">
                        {r.module || ""}{r.duration_ms != null ? ` · ${r.duration_ms}ms` : ""}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
