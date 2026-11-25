import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, Bug, ChevronRight, Server, ExternalLink } from "lucide-react";
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
// Verification-status overrides an operator can apply ("" = inherit the engine's detection).
const VERIFY = ["", "OBSERVED", "POTENTIAL", "UNCONFIRMED", "CONFIRMED"];
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

type TriageBody = { report_stage?: string; verification_override?: string };

function sevVariant(s: string): "critical" | "warning" | "success" | "default" {
  if (s === "critical" || s === "high") return "critical";
  if (s === "medium") return "warning";
  if (s === "low") return "success";
  return "default";
}
function stageDot(s: string): string {
  if (s === "accepted") return "bg-success";
  if (s === "submitted" || s === "triaged") return "bg-warning";
  if (s === "rejected" || s === "duplicate") return "bg-critical";
  return "bg-muted-foreground/40";
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
  const [asset, setAsset] = useState("");       // selected host in the By-asset tree
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const pageSize = 20;

  useEffect(() => { setPage(1); }, [severity, reportStage, status, category, task, sort, q]);
  useEffect(() => { setAsset(""); }, [view]);

  // Grouped views fetch the full set (no pagination) so the tree/groups are complete.
  const effPageSize = view === "all" ? pageSize : 500;
  const params: FindingsParams = {
    severity: severity || undefined,
    report_stage: reportStage || undefined,
    status: status || undefined,
    category: category || undefined,
    scan_id: task || undefined,
    q: q || undefined,
    sort,
    page: view === "all" ? page : 1,
    page_size: effPageSize,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["findings", params],
    queryFn: () => getFindings(params),
    refetchInterval: 10_000,
    placeholderData: (p) => p,
  });

  const triageMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: TriageBody }) => patchTriage(id, body),
    onSuccess: (_r, v) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      if (v.body.report_stage) toast.success("Finding updated", `report → ${v.body.report_stage}`);
      else if (v.body.verification_override !== undefined)
        toast.success("Finding updated", `status → ${v.body.verification_override || "inherit"}`);
    },
    onError: () => toast.error("Could not update finding"),
  });
  const triage = (id: string, body: TriageBody) => triageMut.mutate({ id, body });

  const findings = data?.findings ?? [];
  const summary = data?.summary ?? { total: 0, by_severity: {}, by_stage: {}, by_status: {} };
  const facets = data?.facets ?? { categories: [], statuses: [], stages: STAGES, tasks: [] };
  const total = data?.total ?? 0;
  const pages = data?.pages ?? 0;

  const tile = (k: string) => summary.by_stage[k] ?? 0;
  const sev = (k: string) => summary.by_severity[k] ?? 0;

  const toggle = (id: string) =>
    setExpanded((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  // Asset tree (By asset) — host → count, strongest-count first.
  const assetTree = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.host || "—", (m.get(f.host || "—") ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [findings]);

  // Rows to render for the active view.
  const assetRows = asset ? findings.filter((f) => f.host === asset) : findings;
  const taskGroups = useMemo(() => {
    if (view !== "task") return null;
    const m = new Map<string, Finding[]>();
    for (const f of findings) {
      const g = f.task.domain || f.task.scan_id || "—";
      (m.get(g) ?? m.set(g, []).get(g)!).push(f);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [view, findings]);

  const COLS = 7;

  const table = (rows: React.ReactNode) => (
    <div className="flex-1 overflow-hidden rounded-lg border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-card text-muted-foreground">
          <tr className="border-b border-border">
            <th className="w-8 px-2 py-2" />
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Vulnerability</th>
            <th className="px-3 py-2 font-medium">Asset</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Report</th>
            <th className="px-3 py-2 font-medium">Task</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <div className="flex items-center gap-3 border-t border-border bg-card/40 px-3 py-2 text-xs text-muted-foreground">
        <span className="tabular-nums">{view === "asset" ? assetRows.length : total} shown</span>
        {view === "all" && pages > 1 && (
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" className="h-7 px-2" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>‹</Button>
            <span className="tabular-nums">{page} / {pages}</span>
            <Button variant="outline" className="h-7 px-2" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>›</Button>
          </div>
        )}
      </div>
    </div>
  );

  const rowFor = (f: Finding) => (
    <Row key={f.id} f={f} open={expanded.has(f.id)} cols={COLS}
      onToggle={() => toggle(f.id)} onTriage={(b) => triage(f.id, b)} />
  );

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

      {/* Body */}
      {isLoading && findings.length === 0 ? (
        table(<SkeletonRows cols={COLS} />)
      ) : findings.length === 0 ? (
        table(<Empty cols={COLS}>No matching findings.</Empty>)
      ) : view === "asset" ? (
        <div className="flex flex-col gap-4 lg:flex-row">
          <AssetTree tree={assetTree} total={findings.length} selected={asset} onSelect={setAsset} />
          {table(assetRows.map(rowFor))}
        </div>
      ) : view === "task" ? (
        table(taskGroups!.map(([g, rows]) => (
          <GroupRows key={g} group={g} count={rows.length} cols={COLS}>{rows.map(rowFor)}</GroupRows>
        )))
      ) : (
        table(findings.map(rowFor))
      )}
    </div>
  );
}

// ── asset tree (By asset view) ──────────────────────────────────────────────────
function AssetTree({ tree, total, selected, onSelect }: {
  tree: [string, number][]; total: number; selected: string; onSelect: (h: string) => void;
}) {
  return (
    <aside className="w-full shrink-0 self-start overflow-hidden rounded-lg border border-border lg:w-64">
      <div className="border-b border-border bg-card px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        Assets <span className="font-normal normal-case text-muted-foreground/60">· {tree.length}</span>
      </div>
      <button onClick={() => onSelect("")}
        className={cn("flex w-full items-center justify-between px-3 py-2 text-xs transition-colors",
          !selected ? "bg-primary/10 text-primary" : "text-foreground hover:bg-accent/40")}>
        <span className="font-medium">All assets</span>
        <span className="tabular-nums text-muted-foreground">{total}</span>
      </button>
      <div className="max-h-[60vh] overflow-y-auto">
        {tree.map(([host, n]) => (
          <button key={host} onClick={() => onSelect(host)}
            className={cn("flex w-full items-center justify-between gap-2 border-t border-border/50 px-3 py-2 text-xs transition-colors",
              selected === host ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent/40 hover:text-foreground")}>
            <span className="flex min-w-0 items-center gap-1.5">
              <Server className="h-3 w-3 shrink-0 opacity-60" />
              <span className="truncate font-mono" title={host}>{host}</span>
            </span>
            <span className="tabular-nums">{n}</span>
          </button>
        ))}
      </div>
    </aside>
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

// Inline triage dropdown (used for both Report stage and Verification status).
function TriageSelect({ value, options, onChange, blankLabel }: {
  value: string; options: string[]; onChange: (s: string) => void; blankLabel?: string;
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} onClick={(e) => e.stopPropagation()}
      className="cursor-pointer rounded-md border border-border/60 bg-transparent px-1.5 py-0.5 text-[11px] font-medium outline-none focus:border-primary">
      {options.map((s) => (
        <option key={s} value={s} className="bg-background text-foreground">
          {s === "" ? (blankLabel ?? "—") : s}
        </option>
      ))}
    </select>
  );
}

function Row({ f, open, cols, onToggle, onTriage }: {
  f: Finding; open: boolean; cols: number;
  onToggle: () => void; onTriage: (b: TriageBody) => void;
}) {
  return (
    <>
      <tr className="cursor-pointer border-b border-border/50 align-top transition-colors last:border-0 hover:bg-accent/40"
        onClick={onToggle}>
        <td className="px-2 py-2 text-muted-foreground">
          <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-90")} />
        </td>
        <td className="px-3 py-2"><Badge variant={sevVariant(f.severity)} className="uppercase">{f.severity}</Badge></td>
        <td className="max-w-[22rem] px-3 py-2">
          <div className="truncate font-medium text-foreground" title={f.title}>{f.title}</div>
          <div className="mt-0.5 flex items-center gap-1.5">
            <span className="truncate text-[11px] text-muted-foreground">{f.category}</span>
            <Badge variant={statusVariant(f.status)} className="font-mono text-[9px]">
              {f.status || "UNVERIFIED"}
            </Badge>
          </div>
        </td>
        <td className="max-w-[12rem] px-3 py-2">
          <div className="truncate font-mono text-muted-foreground" title={f.url || f.host}>{f.host}</div>
          {f.url && f.url !== f.host && (
            <div className="truncate text-[10px] text-muted-foreground/60" title={f.url}>{f.url}</div>
          )}
        </td>
        <td className="px-3 py-2">
          <TriageSelect value={f.verification_override || ""} options={VERIFY} blankLabel="inherit"
            onChange={(s) => onTriage({ verification_override: s })} />
        </td>
        <td className="px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className={cn("h-1.5 w-1.5 rounded-full", stageDot(f.report_stage))} />
            <TriageSelect value={f.report_stage} options={STAGES}
              onChange={(s) => onTriage({ report_stage: s })} />
          </div>
        </td>
        <td className="max-w-[10rem] truncate px-3 py-2 text-muted-foreground" title={f.task.domain}>{f.task.domain || "—"}</td>
      </tr>
      {open && (
        <tr className="border-b border-border/50 bg-card/30">
          <td colSpan={cols} className="animate-fade-in px-4 py-3">
            <Detail f={f} />
          </td>
        </tr>
      )}
    </>
  );
}

function Detail({ f }: { f: Finding }) {
  const refs = Array.isArray(f.references) ? (f.references as string[]) : [];
  return (
    <div className="space-y-2 text-xs">
      {f.description && <p className="leading-relaxed text-foreground/90">{f.description}</p>}
      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-3">
        {f.url && <KV k="url" v={f.url} mono link />}
        {f.detection_method && <KV k="detection" v={f.detection_method} />}
        {f.confidence != null && <KV k="confidence" v={f.confidence_label || String(f.confidence)} />}
        {f.tier && <KV k="tier" v={f.tier} />}
        {f.check_id && <KV k="check" v={f.check_id} mono />}
        {f.detected_status && <KV k="detected" v={f.detected_status} mono />}
        <KV k="task" v={f.task.domain || f.task.scan_id} />
        {f.created_at && <KV k="found" v={f.created_at.slice(0, 19).replace("T", " ")} />}
      </dl>
      {f.remediation && (
        <div><span className="text-muted-foreground/70">remediation: </span><span className="text-foreground/90">{f.remediation}</span></div>
      )}
      {refs.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {refs.map((r, i) => (
            <span key={i} className="rounded border border-border/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{r}</span>
          ))}
        </div>
      )}
      {f.note && <div className="rounded border border-border/60 bg-background/50 px-2 py-1 text-[11px] text-muted-foreground">note: {f.note}</div>}
    </div>
  );
}

function KV({ k, v, mono, link }: { k: string; v: string; mono?: boolean; link?: boolean }) {
  return (
    <div className="flex min-w-0 gap-2">
      <dt className="shrink-0 text-muted-foreground/70">{k}</dt>
      <dd className={cn("min-w-0 truncate text-foreground/90", mono && "font-mono")} title={v}>
        {link ? (
          <a href={v} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-primary" onClick={(e) => e.stopPropagation()}>
            {v}<ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        ) : v}
      </dd>
    </div>
  );
}

function GroupRows({ group, count, cols, children }: {
  group: string; count: number; cols: number; children: React.ReactNode;
}) {
  return (
    <>
      <tr className="bg-card/60">
        <td colSpan={cols} className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {group} <span className="ml-1 font-normal normal-case text-muted-foreground/60">· {count}</span>
        </td>
      </tr>
      {children}
    </>
  );
}

function SkeletonRows({ cols, rows = 8 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="border-b border-border/50 last:border-0">
          {Array.from({ length: cols }).map((__, j) => (
            <td key={j} className="px-3 py-2.5">
              <div className="skeleton h-3" style={{ width: `${[20, 45, 85, 60, 50, 55, 40][j]}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function Empty({ cols, children }: { cols: number; children: React.ReactNode }) {
  return <tr><td colSpan={cols} className="animate-fade-in px-3 py-16 text-center text-sm text-muted-foreground">{children}</td></tr>;
}
