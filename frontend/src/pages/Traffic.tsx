import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Copy, Check, ShieldCheck, ShieldAlert, Radio } from "lucide-react";
import { getTraffic, listScans } from "@/lib/api";
import { Input, Select } from "@/components/ui/field";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/common/states";
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
function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}
      className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground transition-colors hover:text-foreground"
    >
      {done ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />} {label}
    </button>
  );
}

export default function Traffic() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");
  const [host, setHost] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [moduleF, setModuleF] = useState("");
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState(0);

  const hostD = useDebounced(host);
  const qD = useDebounced(q);

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);
  useEffect(() => { setPage(1); setSel(0); }, [scanId, hostD, method, status, qD, moduleF, errorsOnly, pageSize]);

  const params = {
    scan_id: scanId || undefined, host: hostD || undefined, method: method || undefined,
    status: status || undefined, q: qD || undefined, module: moduleF || undefined,
    errors_only: errorsOnly || undefined, page, page_size: pageSize,
  };
  const { data, isLoading } = useQuery({
    queryKey: ["traffic", params], queryFn: () => getTraffic(params),
    enabled: !!scanId, refetchInterval: 8_000, placeholderData: (p) => p,
  });

  const flows = data?.flows ?? [];
  const total = data?.total ?? 0;
  const pages = data?.pages ?? 0;
  const facets = data?.facets ?? { methods: [], statuses: [], modules: [] };
  const active = flows[sel];

  const activeFilters = useMemo(
    () => [hostD, method, status, qD, moduleF].some(Boolean) || errorsOnly,
    [hostD, method, status, qD, moduleF, errorsOnly]);
  const clearAll = () => { setHost(""); setMethod(""); setStatus(""); setQ(""); setModuleF(""); setErrorsOnly(false); };

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">HTTP Traffic</h1>
          <p className="text-xs text-muted-foreground">
            Every HTTP exchange · <span className="text-muted-foreground/70">metadata only — bodies & headers are never recorded</span>
            {data?.run ? ` · ${data.run.domain}` : ""}
          </p>
        </div>
        <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-56">
          <option value="">Select a scan…</option>
          {(scans ?? []).map((s) => <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>)}
        </Select>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-panel p-2">
        <Input placeholder="host…" value={host} onChange={(e) => setHost(e.target.value)} className="h-8 w-40 text-xs" />
        <Input placeholder="Search URL / path…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56 text-xs" />
        <Select value={method} onChange={(e) => setMethod(e.target.value)} className="h-8 w-28 text-xs">
          <option value="">Method</option>{facets.methods.map((m) => <option key={m} value={m}>{m}</option>)}
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} className="h-8 w-36 text-xs">
          {STATUS_CLASSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </Select>
        <Select value={moduleF} onChange={(e) => setModuleF(e.target.value)} className="h-8 w-36 text-xs">
          <option value="">Module</option>{facets.modules.map((m) => <option key={m} value={m}>{m}</option>)}
        </Select>
        <button onClick={() => setErrorsOnly((v) => !v)}
          className={cn("rounded-md border px-2.5 py-1.5 text-xs transition-colors",
            errorsOnly ? "border-critical/50 bg-critical/15 text-critical" : "border-border text-muted-foreground hover:text-foreground")}>
          Errors only
        </button>
        {activeFilters && <Button variant="outline" onClick={clearAll} className="h-8 text-xs">Clear</Button>}
        <div className="ml-auto flex items-center gap-2">
          <Select value={String(pageSize)} onChange={(e) => setPageSize(Number(e.target.value))} className="h-8 w-24 text-xs">
            {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}/page</option>)}
          </Select>
          <Button variant="outline" className="h-8 px-2" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>‹</Button>
          <span className="text-xs tabular-nums text-muted-foreground">{page}/{Math.max(1, pages)}</span>
          <Button variant="outline" className="h-8 px-2" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>›</Button>
        </div>
      </div>

      {/* 2-pane: request list + inspector */}
      <div className="flex min-h-0 flex-1 gap-3">
        <div className="flex min-w-0 flex-[3] flex-col overflow-hidden rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between border-b border-border px-3 py-1.5 text-[11px] text-muted-foreground">
            <span>Request history</span><span className="tabular-nums">{total} records</span>
          </div>
          <div className="flex-1 overflow-auto">
            {!scanId ? (
              <EmptyState icon={Radio} title="Select a scan to inspect its traffic" />
            ) : isLoading && flows.length === 0 ? (
              <div className="space-y-1 p-2">{Array.from({ length: 12 }).map((_, i) => <div key={i} className="skeleton h-6 w-full" />)}</div>
            ) : flows.length === 0 ? (
              <EmptyState icon={Radio} title="No matching traffic"
                description="The engine writes traffic when a scan runs with --debug, a proxy, or results enabled." />
            ) : (
              <table className="w-full text-left text-xs">
                <tbody>
                  {flows.map((f, i) => (
                    <tr key={i} onClick={() => setSel(i)}
                      className={cn("cursor-pointer border-b border-border/40 last:border-0 transition-colors",
                        i === sel ? "bg-primary/10" : "hover:bg-accent/40")}>
                      <td className="whitespace-nowrap px-2 py-1.5 font-mono text-muted-foreground/60">{(f.time ?? "").slice(11, 19) || "—"}</td>
                      <td className="px-2 py-1.5"><Badge variant="outline" className="font-mono text-[10px]">{f.method || "—"}</Badge></td>
                      <td className="max-w-0 truncate px-2 py-1.5 font-mono text-muted-foreground" title={f.url}>{f.path || f.url}</td>
                      <td className="px-2 py-1.5 text-right">
                        {f.status != null ? <Badge variant={statusVariant(f.status, f.ok)} className="font-mono">{f.status}</Badge>
                          : f.error_type ? <span className="text-critical" title={f.error_message ?? ""}>ERR</span>
                          : <span className="text-muted-foreground/50">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Inspector */}
        <aside className="hidden w-[22rem] shrink-0 flex-col overflow-hidden rounded-lg border border-border bg-card lg:flex">
          {!active ? (
            <EmptyState icon={Radio} title="No request selected" description="Pick a request from the list to inspect it." />
          ) : (
            <div className="flex-1 overflow-y-auto">
              {/* Request line */}
              <div className="border-b border-border p-3">
                <div className="mb-1.5 flex items-center gap-2">
                  <Badge variant="outline" className="font-mono">{active.method}</Badge>
                  {active.status != null
                    ? <Badge variant={statusVariant(active.status, active.ok)} className="font-mono">{active.status}</Badge>
                    : active.error_type && <Badge variant="critical" className="font-mono">{active.error_type}</Badge>}
                  <span className="ml-auto flex gap-1">
                    <CopyBtn text={active.url} label="URL" />
                    <CopyBtn text={`${active.method} ${active.url}`} label="line" />
                  </span>
                </div>
                <div className="break-all font-mono text-xs text-foreground">{active.url}</div>
              </div>
              {/* Request metadata */}
              <Section title="Request">
                <KV k="host" v={active.host} mono />
                <KV k="path" v={active.path} mono />
                {active.module && <KV k="module" v={active.module} />}
                {active.operation && <KV k="operation" v={active.operation} />}
                {active.time && <KV k="time" v={active.time.replace("T", " ").slice(0, 19)} />}
                <div className="flex items-center gap-1.5 py-0.5 text-xs">
                  <span className="w-20 shrink-0 text-muted-foreground/70">tls verify</span>
                  {active.tls_verify === false
                    ? <span className="inline-flex items-center gap-1 text-warning"><ShieldAlert className="h-3 w-3" /> disabled</span>
                    : <span className="inline-flex items-center gap-1 text-success"><ShieldCheck className="h-3 w-3" /> on</span>}
                </div>
              </Section>
              {/* Response metadata */}
              <Section title="Response">
                <KV k="status" v={active.status != null ? String(active.status) : (active.ok ? "no body" : "—")} mono />
                <KV k="size" v={fmtSize(active.size)} mono />
                <KV k="timing" v={fmtDur(active.duration_ms)} mono />
                {active.error_type && <KV k="error" v={active.error_type} tone="text-critical" />}
                {active.error_message && <KV k="detail" v={active.error_message} />}
              </Section>
              <div className="p-3 text-[10px] leading-relaxed text-muted-foreground/60">
                Response & request bodies and headers are intentionally not recorded (secrets/credentials are never stored).
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border last:border-0">
      <div className="px-3 pb-1 pt-2.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">{title}</div>
      <div className="px-3 pb-2.5">{children}</div>
    </div>
  );
}
function KV({ k, v, mono, tone }: { k: string; v: string; mono?: boolean; tone?: string }) {
  return (
    <div className="flex gap-2 py-0.5 text-xs">
      <span className="w-20 shrink-0 text-muted-foreground/70">{k}</span>
      <span className={cn("min-w-0 break-all", tone ?? "text-foreground", mono && "font-mono")}>{v}</span>
    </div>
  );
}
