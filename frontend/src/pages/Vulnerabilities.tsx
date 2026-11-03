import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getVulns, listScans, type VulnFinding } from "@/lib/api";
import { StatTile } from "@/components/StatTile";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input, Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function sevVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "warning";
  if (s === "low") return "success";
  return "default";
}
function sevAccent(s: string): "critical" | "warning" | "success" | undefined {
  const v = sevVariant(s);
  return v === "default" ? undefined : v;
}
function statusVariant(s: string | null): "success" | "warning" | "default" {
  if (s === "CONFIRMED") return "success";
  if (s === "POTENTIAL" || s === "OBSERVED") return "warning";
  return "default";
}

function FindingRow({ f }: { f: VulnFinding }) {
  const [open, setOpen] = useState(false);
  const extraKeys = Object.keys(f.extra ?? {});
  return (
    <div className="rounded-md border border-border/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={sevVariant(f.severity)} className="shrink-0 uppercase">{f.severity}</Badge>
        {f.status && <Badge variant={statusVariant(f.status)} className="shrink-0">{f.status}</Badge>}
        {f.confidence_label && (
          <Badge variant="outline" className="shrink-0">
            {f.confidence_label}{f.confidence != null ? ` ${(f.confidence * 100).toFixed(0)}%` : ""}
          </Badge>
        )}
        <span className="truncate text-sm text-foreground">{f.title}</span>
        <Badge variant="outline" className="ml-auto shrink-0 font-mono text-[10px]">{f.category}</Badge>
      </div>

      <p className="mt-1.5 text-xs text-muted-foreground">{f.description}</p>

      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground/80">
        <span>host: <span className="font-mono text-muted-foreground">{f.host}</span></span>
        {f.url && <span className="truncate">url: <span className="font-mono text-muted-foreground">{f.url}</span></span>}
        {f.detection_method && <span>via: {f.detection_method}</span>}
        {f.tier && <span>tier: {f.tier}</span>}
      </div>

      {(f.references || f.remediation || extraKeys.length > 0) && (
        <button onClick={() => setOpen((v) => !v)}
          className="mt-2 text-[11px] text-primary hover:underline">
          {open ? "hide" : "show"} evidence & remediation
        </button>
      )}
      {open && (
        <div className="mt-1.5 space-y-1.5 border-t border-border/50 pt-2 text-[11px]">
          {f.remediation && (
            <div><span className="text-muted-foreground/70">remediation:</span>{" "}
              <span className="text-muted-foreground">{f.remediation}</span></div>
          )}
          {f.references && (
            <div><span className="text-muted-foreground/70">references:</span>{" "}
              <span className="font-mono text-muted-foreground">{f.references}</span></div>
          )}
          {extraKeys.map((k) => (
            <div key={k}>
              <span className="text-muted-foreground/70">{k.replace(/^ev_/, "")}:</span>{" "}
              <span className="font-mono text-muted-foreground break-all">{String(f.extra[k])}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Vulnerabilities() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 8_000 });
  const [scanId, setScanId] = useState<string>("");
  const [sev, setSev] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [q, setQ] = useState("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data, isLoading } = useQuery({
    queryKey: ["vulns", scanId],
    queryFn: () => getVulns(scanId || undefined),
    refetchInterval: 8_000,
  });

  const needle = q.trim().toLowerCase();
  const findings = useMemo(() => {
    let rows: VulnFinding[] = data?.findings ?? [];
    if (sev) rows = rows.filter((f) => f.severity === sev);
    if (status) rows = rows.filter((f) => f.status === status);
    if (needle)
      rows = rows.filter(
        (f) =>
          f.title.toLowerCase().includes(needle) ||
          f.host.toLowerCase().includes(needle) ||
          f.category.toLowerCase().includes(needle) ||
          (f.url ?? "").toLowerCase().includes(needle)
      );
    return rows;
  }, [data, sev, status, needle]);

  const sum = data?.summary;
  const statuses = Object.keys(sum?.by_status ?? {});

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold tracking-tight">Vulnerability Intelligence</h1>
        <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-64">
          <option value="">Select a scan…</option>
          {(scans ?? []).map((s) => (
            <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>
          ))}
        </Select>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Findings" value={sum?.total ?? "—"} />
        {SEV_ORDER.map((s) => (
          <StatTile key={s} label={s[0].toUpperCase() + s.slice(1)}
            value={sum?.by_severity?.[s] ?? 0}
            accent={(sum?.by_severity?.[s] ?? 0) ? sevAccent(s) : undefined} />
        ))}
      </div>

      {/* Verification-status chips */}
      {statuses.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {statuses.map((st) => (
            <Badge key={st} variant={statusVariant(st)}>{st}: {sum!.by_status[st]}</Badge>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={sev} onChange={(e) => setSev(e.target.value)} className="w-40">
          <option value="">All severities</option>
          {SEV_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-44">
          <option value="">All statuses</option>
          {statuses.map((st) => <option key={st} value={st}>{st}</option>)}
        </Select>
        <Input placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} className="w-56" />
        <span className="text-xs text-muted-foreground">{findings.length} shown</span>
      </div>

      {!scanId ? (
        <p className="text-sm text-muted-foreground">Select a scan to view its findings.</p>
      ) : isLoading ? (
        <p className="text-sm text-muted-foreground">Loading findings…</p>
      ) : findings.length === 0 ? (
        <Card><CardContent className={cn("py-8 text-center text-sm text-muted-foreground")}>
          {sum?.total ? "No findings match the current filters." : "No findings for this scan."}
        </CardContent></Card>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => <FindingRow key={f.id} f={f} />)}
        </div>
      )}
    </div>
  );
}
