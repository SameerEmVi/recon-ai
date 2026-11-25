import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { X, ShieldAlert } from "lucide-react";
import { getVulns, listScans, type VulnFinding } from "@/lib/api";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { Badge } from "@/components/ui/badge";
import { Input, Select } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/common/states";
import { cn } from "@/lib/cn";

const SEV_BORDER: Record<string, string> = {
  critical: "border-l-critical", high: "border-l-critical/80", medium: "border-l-warning",
  low: "border-l-success", info: "border-l-muted-foreground/40",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function sevVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "warning";
  if (s === "low") return "success";
  return "default";
}
function statusVariant(s: string | null): "success" | "warning" | "default" {
  if (s === "CONFIRMED") return "success";
  if (s === "POTENTIAL" || s === "OBSERVED") return "warning";
  return "default";
}
const metricTone = sevVariant;   // severity → MetricCard tone (critical/warning/success/default)

function FindingDrawer({ f, onClose }: { f: VulnFinding; onClose: () => void }) {
  const extraKeys = Object.keys(f.extra ?? {});
  return (
    <aside className="flex w-full flex-col overflow-hidden rounded-lg border border-border bg-card lg:w-[24rem]">
      <div className={cn("flex items-start justify-between gap-2 border-b border-l-2 border-border p-3", SEV_BORDER[f.severity] ?? SEV_BORDER.info)}>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant={sevVariant(f.severity)} className="uppercase">{f.severity}</Badge>
            {f.status && <Badge variant={statusVariant(f.status)}>{f.status}</Badge>}
          </div>
          <h2 className="mt-1.5 text-sm font-medium text-foreground">{f.title}</h2>
        </div>
        <button onClick={onClose} className="shrink-0 text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
      </div>
      <div className="flex-1 space-y-3 overflow-y-auto p-3 text-xs">
        <p className="leading-relaxed text-foreground/90">{f.description}</p>
        <dl className="space-y-1">
          <KV k="host" v={f.host} mono />
          {f.url && <KV k="url" v={f.url} mono />}
          <KV k="category" v={f.category} mono />
          {f.detection_method && <KV k="detection" v={f.detection_method} />}
          {f.tier && <KV k="tier" v={f.tier} />}
          {f.confidence_label && <KV k="confidence" v={`${f.confidence_label}${f.confidence != null ? ` ${(f.confidence * 100).toFixed(0)}%` : ""}`} />}
          {f.created_at && <KV k="found" v={f.created_at.slice(0, 19).replace("T", " ")} />}
        </dl>
        {f.remediation && (
          <div className="rounded-md border border-border/60 bg-background/40 p-2">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">Remediation</div>
            <p className="text-foreground/90">{f.remediation}</p>
          </div>
        )}
        {f.references && (
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">References</div>
            <div className="flex flex-wrap gap-1">
              {f.references.split(/[\s,]+/).filter(Boolean).map((r, i) => (
                <span key={i} className="rounded border border-border/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{r}</span>
              ))}
            </div>
          </div>
        )}
        {extraKeys.length > 0 && (
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">Evidence</div>
            <dl className="space-y-1">
              {extraKeys.map((k) => <KV key={k} k={k.replace(/^ev_/, "")} v={String(f.extra[k])} mono />)}
            </dl>
          </div>
        )}
      </div>
    </aside>
  );
}

export default function Vulnerabilities() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 8_000 });
  const [scanId, setScanId] = useState<string>("");
  const [sev, setSev] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [q, setQ] = useState("");
  const [selId, setSelId] = useState<string | null>(null);

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data, isLoading } = useQuery({
    queryKey: ["vulns", scanId], queryFn: () => getVulns(scanId || undefined), refetchInterval: 8_000,
  });

  const needle = q.trim().toLowerCase();
  const findings = useMemo(() => {
    let rows: VulnFinding[] = data?.findings ?? [];
    if (sev) rows = rows.filter((f) => f.severity === sev);
    if (status) rows = rows.filter((f) => f.status === status);
    if (needle) rows = rows.filter((f) =>
      [f.title, f.host, f.category, f.url ?? ""].some((x) => x.toLowerCase().includes(needle)));
    return rows;
  }, [data, sev, status, needle]);

  const sum = data?.summary;
  const statuses = Object.keys(sum?.by_status ?? {});
  const selected = findings.find((f) => f.id === selId) ?? null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Vulnerability Intelligence</h1>
        <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-56">
          <option value="">Select a scan…</option>
          {(scans ?? []).map((s) => <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>)}
        </Select>
      </div>

      {/* Severity summary */}
      <div className="stagger grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <MetricCard label="Findings" value={sum?.total ?? 0} icon={ShieldAlert} />
        {SEV_ORDER.map((s) => (
          <MetricCard key={s} label={s[0].toUpperCase() + s.slice(1)} value={sum?.by_severity?.[s] ?? 0}
            tone={(sum?.by_severity?.[s] ?? 0) ? metricTone(s) : "default"} />
        ))}
      </div>

      {statuses.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {statuses.map((st) => <Badge key={st} variant={statusVariant(st)}>{st}: {sum!.by_status[st]}</Badge>)}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Select value={sev} onChange={(e) => setSev(e.target.value)} className="w-36">
          <option value="">All severities</option>{SEV_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-40">
          <option value="">All statuses</option>{statuses.map((st) => <option key={st} value={st}>{st}</option>)}
        </Select>
        <Input placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} className="w-56" />
        <span className="text-xs text-muted-foreground">{findings.length} shown</span>
      </div>

      {/* List + drawer */}
      <div className="flex gap-4">
        <div className="min-w-0 flex-1">
          {!scanId ? (
            <EmptyState icon={ShieldAlert} title="Select a scan to view its findings" />
          ) : isLoading ? (
            <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-14 w-full rounded-md" />)}</div>
          ) : findings.length === 0 ? (
            <EmptyState icon={ShieldAlert} title={sum?.total ? "No findings match the filters" : "No findings for this scan"} />
          ) : (
            <div className="stagger space-y-1.5">
              {findings.map((f) => (
                <button key={f.id} onClick={() => setSelId(f.id)}
                  className={cn("flex w-full items-center gap-2.5 rounded-md border border-l-2 border-border/60 p-2.5 text-left transition-colors hover:border-primary/40 hover:bg-accent/30",
                    SEV_BORDER[f.severity] ?? SEV_BORDER.info, selId === f.id && "bg-accent/40 border-primary/40")}>
                  <Badge variant={sevVariant(f.severity)} className="shrink-0 uppercase">{f.severity}</Badge>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-foreground">{f.title}</div>
                    <div className="truncate font-mono text-[11px] text-muted-foreground">{f.host}</div>
                  </div>
                  {f.status && <Badge variant={statusVariant(f.status)} className="shrink-0 text-[10px]">{f.status}</Badge>}
                  <Badge variant="outline" className="hidden shrink-0 font-mono text-[10px] sm:inline-flex">{f.category}</Badge>
                </button>
              ))}
            </div>
          )}
        </div>
        {selected && (
          <div className="sticky top-0 hidden shrink-0 self-start lg:block">
            <FindingDrawer f={selected} onClose={() => setSelId(null)} />
          </div>
        )}
      </div>
    </div>
  );
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <dt className="w-20 shrink-0 text-muted-foreground/70">{k}</dt>
      <dd className={cn("min-w-0 break-all text-foreground", mono && "font-mono")}>{v}</dd>
    </div>
  );
}
