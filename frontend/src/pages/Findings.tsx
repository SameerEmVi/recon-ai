import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, Bug } from "lucide-react";
import {
  getFindings, patchTriage, exportFindings,
  type Finding, type FindingsParams,
} from "@/lib/api";
import { StatTile } from "@/components/StatTile";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STAGES = ["pending", "triaged", "submitted", "accepted", "rejected", "duplicate", "informative"];
const SORTS = [
  { value: "severity", label: "By severity" },
  { value: "time", label: "Newest first" },
  { value: "stage", label: "By report stage" },
];
const VIEWS = [
  { value: "all", label: "All findings" },
  { value: "task", label: "By task" },
  { value: "asset", label: "By asset" },
];

function sevVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "warning";
  if (s === "low") return "success";
  return "default";
}
function stageVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "accepted") return "success";
  if (s === "submitted" || s === "triaged") return "warning";
  if (s === "rejected" || s === "duplicate") return "critical";
  return "default";
}
function statusVariant(s: string | null): "success" | "warning" | "default" {
  const u = (s || "").toUpperCase();
  if (u === "CONFIRMED") return "success";
  if (u === "POTENTIAL" || u === "OBSERVED") return "warning";
  return "default";
}

export default function Findings() {
  const qc = useQueryClient();
  const toast = useToast();
  const [view, setView] = useState("all");
  const [severity, setSeverity] = useState("");
  const [reportStage, setReportStage] = useState("");
  const [status, setStatus] = useState("");
  const [category, setCategory] = useState("");
  const [task, setTask] = useState("");
  const [sort, setSort] = useState("severity");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 20;

  useEffect(() => { setPage(1); }, [severity, reportStage, status, category, task, sort, q]);

  const params: FindingsParams = {
    severity: severity || undefined,
    report_stage: reportStage || undefined,
    status: status || undefined,
    category: category || undefined,
    scan_id: task || undefined,
    q: q || undefined,
    sort,
    page,
    page_size: pageSize,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["findings", params],
    queryFn: () => getFindings(params),
    refetchInterval: 10_000,
    placeholderData: (p) => p,
  });

  const triageMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { report_stage?: string } }) =>
      patchTriage(id, body),
    onSuccess: (_r, v) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      if (v.body.report_stage) toast.success("Finding updated", `stage → ${v.body.report_stage}`);
    },
    onError: () => toast.error("Could not update finding"),
  });

  const findings = data?.findings ?? [];
  const summary = data?.summary ?? { total: 0, by_severity: {}, by_stage: {}, by_status: {} };
  const facets = data?.facets ?? { categories: [], statuses: [], stages: STAGES, tasks: [] };
  const total = data?.total ?? 0;
  const pages = data?.pages ?? 0;

  const tile = (k: string) => summary.by_stage[k] ?? 0;
  const sev = (k: string) => summary.by_severity[k] ?? 0;

  // Client-side grouping for the By task / By asset views.
  const groups = useMemo(() => {
    if (view === "all") return null;
    const key = (f: Finding) => (view === "task" ? f.task.domain || f.task.scan_id : f.host);
    const m = new Map<string, Finding[]>();
    for (const f of findings) {
      const g = key(f) || "—";
      (m.get(g) ?? m.set(g, []).get(g)!).push(f);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [view, findings]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Findings</h1>
          <p className="text-xs text-muted-foreground">Cross-task vulnerability overview</p>
        </div>
        <div className="flex gap-1 rounded-md border border-border bg-card p-1">
          {VIEWS.map((v) => (
            <button key={v.value} onClick={() => setView(v.value)}
              className={cn("rounded px-3 py-1 text-xs font-medium transition-colors",
                view === v.value ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
              {v.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tiles */}
      <div className="stagger grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
        <StatTile label="Total" value={summary.total} icon={<Bug className="h-4 w-4" />} />
        <StatTile label="Pending" value={tile("pending")} accent={tile("pending") ? "warning" : undefined} />
        <StatTile label="Submitted" value={tile("submitted")} />
        <StatTile label="Accepted" value={tile("accepted")} accent={tile("accepted") ? "success" : undefined} />
        <StatTile label="Critical" value={sev("critical")} accent={sev("critical") ? "critical" : undefined} />
        <StatTile label="High" value={sev("high")} accent={sev("high") ? "critical" : undefined} />
        <StatTile label="Medium" value={sev("medium")} accent={sev("medium") ? "warning" : undefined} />
        <StatTile label="Low" value={sev("low")} accent={sev("low") ? "success" : undefined} />
      </div>

      {/* Filters row 1 */}
      <div className="flex flex-wrap items-center gap-2">
        <Input placeholder="Search findings…" value={q} onChange={(e) => setQ(e.target.value)} className="w-60" />
        <div className="flex gap-1 rounded-md border border-border bg-card p-1">
          <SevChip label="All" active={!severity} onClick={() => setSeverity("")} />
          {SEVERITIES.map((s) => (
            <SevChip key={s} label={s[0].toUpperCase() + s.slice(1)} active={severity === s} onClick={() => setSeverity(s)} />
          ))}
        </div>
        <Select value={status} onChange={(e) => setStatus(e.target.value)} className="w-44">
          <option value="">All verification states</option>
          {facets.statuses.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={reportStage} onChange={(e) => setReportStage(e.target.value)} className="w-40">
          <option value="">All report stages</option>
          {STAGES.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={category} onChange={(e) => setCategory(e.target.value)} className="w-44">
          <option value="">All types</option>
          {facets.categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </Select>
      </div>

      {/* Filters row 2 */}
      <div className="flex flex-wrap items-center gap-2">
        <Select value={task} onChange={(e) => setTask(e.target.value)} className="w-56">
          <option value="">All tasks</option>
          {facets.tasks.map((t) => <option key={t.scan_id} value={t.scan_id}>{t.domain || t.scan_id.slice(0, 8)}</option>)}
        </Select>
        <Select value={sort} onChange={(e) => setSort(e.target.value)} className="w-40">
          {SORTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </Select>
        <Button variant="outline" className="ml-auto h-9 gap-1.5 text-xs"
          onClick={() =>
            exportFindings(params)
              .then(() => toast.success("Export ready", "findings.csv downloaded"))
              .catch(() => toast.error("Export failed"))
          }>
          <Download className="h-3.5 w-3.5" /> Export
        </Button>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-left text-xs">
          <thead className="bg-card text-muted-foreground">
            <tr className="border-b border-border">
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Vulnerability</th>
              <th className="px-3 py-2 font-medium">Asset</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Report</th>
              <th className="px-3 py-2 font-medium">Task</th>
              <th className="px-3 py-2 font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && findings.length === 0 ? (
              <SkeletonRows />
            ) : findings.length === 0 ? (
              <Empty>No matching findings.</Empty>
            ) : view === "all" ? (
              findings.map((f) => (
                <Row key={f.id} f={f} onStage={(s) => triageMut.mutate({ id: f.id, body: { report_stage: s } })} />
              ))
            ) : (
              groups!.map(([g, rows]) => (
                <GroupRows key={g} group={g} rows={rows}
                  onStage={(id, s) => triageMut.mutate({ id, body: { report_stage: s } })} />
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex items-center gap-3 border-t border-border bg-card/40 px-3 py-2 text-xs text-muted-foreground">
          <span className="tabular-nums">{total} total</span>
          {view === "all" && pages > 1 && (
            <div className="ml-auto flex items-center gap-2">
              <Button variant="outline" className="h-7 px-2" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹</Button>
              <span className="tabular-nums">{page} / {pages}</span>
              <Button variant="outline" className="h-7 px-2" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>›</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function SevChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={cn("rounded px-2.5 py-1 text-xs font-medium transition-colors",
        active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
      {label}
    </button>
  );
}

function StageSelect({ value, onChange }: { value: string; onChange: (s: string) => void }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      onClick={(e) => e.stopPropagation()}
      className={cn("rounded-md border px-1.5 py-0.5 text-[11px] font-medium bg-transparent outline-none cursor-pointer",
        "border-border/60 focus:border-primary")}>
      {STAGES.map((s) => <option key={s} value={s} className="bg-background text-foreground">{s}</option>)}
    </select>
  );
}

function Row({ f, onStage }: { f: Finding; onStage: (s: string) => void }) {
  return (
    <tr className="border-b border-border/50 last:border-0 align-top hover:bg-accent/40">
      <td className="px-3 py-2"><Badge variant={sevVariant(f.severity)} className="uppercase">{f.severity}</Badge></td>
      <td className="max-w-[22rem] px-3 py-2">
        <div className="truncate font-medium text-foreground" title={f.title}>{f.title}</div>
        <div className="truncate text-[11px] text-muted-foreground">{f.category}</div>
      </td>
      <td className="max-w-[12rem] truncate px-3 py-2 font-mono text-muted-foreground" title={f.url || f.host}>{f.host}</td>
      <td className="px-3 py-2">
        {f.status ? <Badge variant={statusVariant(f.status)} className="font-mono">{f.status}</Badge>
          : <span className="text-muted-foreground/50">—</span>}
      </td>
      <td className="px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className={cn("h-1.5 w-1.5 rounded-full",
            stageVariant(f.report_stage) === "success" ? "bg-success" :
            stageVariant(f.report_stage) === "warning" ? "bg-warning" :
            stageVariant(f.report_stage) === "critical" ? "bg-critical" : "bg-muted-foreground/40")} />
          <StageSelect value={f.report_stage} onChange={onStage} />
        </div>
      </td>
      <td className="max-w-[10rem] truncate px-3 py-2 text-muted-foreground" title={f.task.domain}>{f.task.domain || "—"}</td>
      <td className="whitespace-nowrap px-3 py-2 font-mono text-muted-foreground/70">{(f.created_at || "").slice(0, 10) || "—"}</td>
    </tr>
  );
}

function GroupRows({ group, rows, onStage }: {
  group: string; rows: Finding[]; onStage: (id: string, s: string) => void;
}) {
  return (
    <>
      <tr className="bg-card/60">
        <td colSpan={7} className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {group} <span className="ml-1 font-normal normal-case text-muted-foreground/60">· {rows.length}</span>
        </td>
      </tr>
      {rows.map((f) => <Row key={f.id} f={f} onStage={(s) => onStage(f.id, s)} />)}
    </>
  );
}

function SkeletonRows({ rows = 8 }: { rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="border-b border-border/50 last:border-0">
          {Array.from({ length: 7 }).map((__, j) => (
            <td key={j} className="px-3 py-2.5">
              <div className="skeleton h-3" style={{ width: `${[45, 85, 60, 50, 55, 40, 45][j]}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <tr><td colSpan={7} className="animate-fade-in px-3 py-16 text-center text-sm text-muted-foreground">{children}</td></tr>;
}
