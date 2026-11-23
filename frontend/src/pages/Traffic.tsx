import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getTraffic, listScans, type TrafficFlow } from "@/lib/api";
import { Input, Select } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

const PAGE_SIZES = [25, 50, 100, 200];
const STATUS_CLASSES = [
  { value: "", label: "All statuses" },
  { value: "2xx", label: "2xx · success" },
  { value: "3xx", label: "3xx · redirect" },
  { value: "4xx", label: "4xx · client" },
  { value: "5xx", label: "5xx · server" },
  { value: "error", label: "no response (error)" },
];

function statusVariant(s: number | null, ok: boolean): "success" | "warning" | "critical" | "default" {
  if (s == null) return ok ? "default" : "critical";
  if (s >= 500) return "critical";
  if (s >= 400) return "warning";
  if (s >= 200 && s < 400) return "success";
  return "default";
}
function fmtSize(n: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function fmtDur(n: number | null): string {
  if (n == null) return "—";
  if (n < 1000) return `${Math.round(n)} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

/** Debounce a rapidly-changing value so typing doesn't refetch per keystroke. */
function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export default function Traffic() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  // Filters
  const [host, setHost] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [moduleF, setModuleF] = useState("");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [sizeMin, setSizeMin] = useState("");
  const [sizeMax, setSizeMax] = useState("");
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState(1);

  const hostD = useDebounced(host);
  const qD = useDebounced(q);
  const sizeMinD = useDebounced(sizeMin);
  const sizeMaxD = useDebounced(sizeMax);

  // Default to the running scan, else the most recent.
  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  // Reset to page 1 whenever a filter changes.
  useEffect(() => {
    setPage(1);
  }, [scanId, hostD, method, status, qD, moduleF, errorsOnly, sizeMinD, sizeMaxD, pageSize]);

  const params = {
    scan_id: scanId || undefined,
    host: hostD || undefined,
    method: method || undefined,
    status: status || undefined,
    q: qD || undefined,
    module: moduleF || undefined,
    errors_only: errorsOnly || undefined,
    size_min: sizeMinD ? Number(sizeMinD) : undefined,
    size_max: sizeMaxD ? Number(sizeMaxD) : undefined,
    page,
    page_size: pageSize,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["traffic", params],
    queryFn: () => getTraffic(params),
    enabled: !!scanId,
    refetchInterval: 8_000,
    placeholderData: (prev) => prev,
  });

  const flows = data?.flows ?? [];
  const total = data?.total ?? 0;
  const pages = data?.pages ?? 0;
  const facets = data?.facets ?? { methods: [], statuses: [], modules: [] };

  const rangeStart = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const rangeEnd = Math.min(page * pageSize, total);

  const activeFilters = useMemo(
    () => [hostD, method, status, qD, moduleF, sizeMinD, sizeMaxD].some(Boolean) || errorsOnly,
    [hostD, method, status, qD, moduleF, sizeMinD, sizeMaxD, errorsOnly]
  );
  const clearAll = () => {
    setHost(""); setMethod(""); setStatus(""); setQ(""); setModuleF("");
    setErrorsOnly(false); setSizeMin(""); setSizeMax("");
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Traffic</h1>
          <p className="text-xs text-muted-foreground">
            Every HTTP exchange the scan made · metadata only (bodies are never recorded)
            {data?.run ? ` · ${data.run.domain}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground tabular-nums">{total} records</span>
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

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-panel p-3">
        <Input placeholder="host…" value={host} onChange={(e) => setHost(e.target.value)} className="w-44" />
        <Input placeholder="Search URL / path…" value={q} onChange={(e) => setQ(e.target.value)} className="w-64" />
        <Select value={method} onChange={(e) => setMethod(e.target.value)} className="w-32">
          <option value="">All methods</option>
          {facets.methods.map((m) => <option key={m} value={m}>{m}</option>)}
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-40">
          {STATUS_CLASSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </Select>
        <Select value={moduleF} onChange={(e) => setModuleF(e.target.value)} className="w-40">
          <option value="">All modules</option>
          {facets.modules.map((m) => <option key={m} value={m}>{m}</option>)}
        </Select>
        <Input placeholder="Min size (B)" value={sizeMin} onChange={(e) => setSizeMin(e.target.value.replace(/\D/g, ""))} className="w-28" inputMode="numeric" />
        <Input placeholder="Max size (B)" value={sizeMax} onChange={(e) => setSizeMax(e.target.value.replace(/\D/g, ""))} className="w-28" inputMode="numeric" />
        <button
          onClick={() => setErrorsOnly((v) => !v)}
          className={cn("rounded-md border px-3 py-1.5 text-xs transition-colors",
            errorsOnly ? "border-critical/50 bg-critical/15 text-critical" : "border-border text-muted-foreground hover:text-foreground")}
        >
          Errors only
        </button>
        {activeFilters && (
          <Button variant="outline" onClick={clearAll} className="h-8 text-xs">Clear</Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Select value={String(pageSize)} onChange={(e) => setPageSize(Number(e.target.value))} className="w-24">
            {PAGE_SIZES.map((n) => <option key={n} value={n}>{n} / page</option>)}
          </Select>
          <span className="text-xs text-muted-foreground tabular-nums">{rangeStart}–{rangeEnd} / {total}</span>
          <Button variant="outline" className="h-8 px-2" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>‹</Button>
          <span className="text-xs text-muted-foreground tabular-nums">{page} / {Math.max(1, pages)}</span>
          <Button variant="outline" className="h-8 px-2" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>›</Button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-left text-xs">
          <thead className="bg-card text-muted-foreground">
            <tr className="border-b border-border">
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Host</th>
              <th className="px-3 py-2 font-medium">Method</th>
              <th className="px-3 py-2 font-medium">URL / Path</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Module</th>
              <th className="px-3 py-2 text-right font-medium">Size</th>
              <th className="px-3 py-2 text-right font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {!scanId ? (
              <Empty>Select a scan to view its traffic.</Empty>
            ) : isLoading && flows.length === 0 ? (
              <SkeletonRows />
            ) : flows.length === 0 ? (
              <Empty>No matching traffic.</Empty>
            ) : (
              flows.map((f, i) => <Flow key={i} f={f} />)
            )}
          </tbody>
        </table>
      </div>

      {!isLoading && total === 0 && scanId && !activeFilters && (
        <p className="text-xs text-muted-foreground">
          No HTTP traffic was recorded for this scan. The engine writes the traffic stream when a
          scan runs with <span className="font-mono">--debug</span>, a proxy, or results enabled.
        </p>
      )}
    </div>
  );
}

function Flow({ f }: { f: TrafficFlow }) {
  return (
    <tr className="border-b border-border/50 last:border-0 hover:bg-accent/40">
      <td className="whitespace-nowrap px-3 py-1.5 font-mono text-muted-foreground/70">
        {(f.time ?? "").slice(11, 19) || "—"}
      </td>
      <td className="max-w-[12rem] truncate px-3 py-1.5 font-mono text-foreground" title={f.host}>{f.host || "—"}</td>
      <td className="px-3 py-1.5">
        <Badge variant="outline" className="font-mono">{f.method || "—"}</Badge>
      </td>
      <td className="max-w-[26rem] truncate px-3 py-1.5 font-mono text-muted-foreground" title={f.url}>{f.path || f.url}</td>
      <td className="px-3 py-1.5">
        {f.status != null ? (
          <Badge variant={statusVariant(f.status, f.ok)} className="font-mono">{f.status}</Badge>
        ) : f.error_type ? (
          <span className="text-critical" title={f.error_message ?? ""}>{f.error_type}</span>
        ) : (
          <span className="text-muted-foreground/60">—</span>
        )}
      </td>
      <td className="whitespace-nowrap px-3 py-1.5 text-muted-foreground/80">{f.module || "—"}</td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono text-muted-foreground tabular-nums">{fmtSize(f.size)}</td>
      <td className="whitespace-nowrap px-3 py-1.5 text-right font-mono text-muted-foreground tabular-nums">{fmtDur(f.duration_ms)}</td>
    </tr>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <tr>
      <td colSpan={8} className="animate-fade-in px-3 py-16 text-center text-sm text-muted-foreground">{children}</td>
    </tr>
  );
}

function SkeletonRows({ rows = 10 }: { rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="border-b border-border/50 last:border-0">
          {Array.from({ length: 8 }).map((__, j) => (
            <td key={j} className="px-3 py-2">
              <div className="skeleton h-3" style={{ width: `${[55, 70, 40, 90, 45, 60, 50, 50][j]}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
