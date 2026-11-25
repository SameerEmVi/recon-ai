import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition } from "cytoscape";
import {
  Pause, Play, Square, RefreshCw, Target, Compass, ChevronRight, Check, X, Ban, ArrowUp,
} from "lucide-react";
import {
  listExplorations, getEngineGraph, getEngGoals, getEngActivities, getEngNode,
  engPause, engResume, engStop, engReplan, engApproveIntent, engRejectIntent,
  engCancelIntent, engBlockGoal, engPrioritizeGoal,
  type EngGoal, type EngNode, type EngNodeKind,
} from "@/lib/api";
import { Select } from "@/components/ui/field";
import { StatusIndicator } from "@/components/common/StatusIndicator";
import { EmptyState } from "@/components/common/states";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";

// Node palette + status overrides.
const KIND_COLOR: Record<EngNodeKind, string> = {
  objective: "#a78bfa", goal: "#38bdf8", intent: "#818cf8", fact: "#94a3b8",
  hint: "#f59e0b", finding: "#ef4444", digest: "#64748b",
};
const GOAL_STATE: Record<string, string> = {
  satisfied: "#22c55e", partial: "#f59e0b", blocked: "#ef4444", failed: "#ef4444",
  active: "#38bdf8", open: "#64748b", cancelled: "#475569",
};
const INTENT_STATE: Record<string, string> = {
  completed: "#22c55e", running: "#38bdf8", failed: "#ef4444", rejected: "#ef4444",
  blocked: "#f59e0b", queued: "#818cf8", open: "#64748b", cancelled: "#475569",
};
function nodeColor(n: EngNode): string {
  if (n.kind === "goal") return GOAL_STATE[n.state ?? ""] ?? KIND_COLOR.goal;
  if (n.kind === "intent") return INTENT_STATE[n.state ?? ""] ?? KIND_COLOR.intent;
  return KIND_COLOR[n.kind] ?? "#64748b";
}

const cyStyle: cytoscape.Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": (el) => nodeColor(el.data() as EngNode),
      label: "data(label)", color: "#cbd5e1", "font-size": 8,
      "font-family": "\"JetBrains Mono\", ui-monospace, monospace",
      "text-valign": "center", "text-halign": "right", "text-margin-x": 5,
      "min-zoomed-font-size": 6, width: 14, height: 14,
    },
  },
  { selector: 'node[kind = "objective"]', style: { width: 30, height: 30, shape: "round-rectangle", "font-size": 12 } },
  { selector: 'node[kind = "goal"]', style: { width: 22, height: 22, shape: "round-rectangle", "font-size": 10 } },
  { selector: 'node[kind = "intent"]', style: { width: 16, height: 16, shape: "hexagon" } },
  { selector: 'node[kind = "fact"]', style: { shape: "diamond", width: 12, height: 12 } },
  { selector: 'node[kind = "finding"]', style: { shape: "triangle", width: 16, height: 16 } },
  { selector: 'node[kind = "digest"]', style: { shape: "round-rectangle", width: 18, height: 12, opacity: 0.6 } },
  {
    selector: "edge",
    style: {
      width: 1.2, "line-color": "#334155", "target-arrow-color": "#334155",
      "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier", opacity: 0.55,
    },
  },
  { selector: "node:selected", style: { "border-width": 3, "border-color": "#38bdf8" } },
  { selector: ".faded", style: { opacity: 0.1 } },
];

export default function Exploration() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data: explResp } = useQuery({ queryKey: ["explorations"], queryFn: listExplorations, refetchInterval: 6_000 });
  const explorations = explResp?.explorations ?? [];
  const [eid, setEid] = useState<string>("");
  useEffect(() => {
    if (eid || !explorations.length) return;
    const running = explorations.find((e) => e.status === "running");
    setEid((running ?? explorations[0]).id);
  }, [explorations, eid]);

  const { data: graph } = useQuery({
    queryKey: ["eng-graph", eid], queryFn: () => getEngineGraph(undefined, eid || undefined),
    enabled: !!eid, refetchInterval: 4_000,
  });
  const { data: goalsResp } = useQuery({
    queryKey: ["eng-goals", eid], queryFn: () => getEngGoals(undefined, eid || undefined),
    enabled: !!eid, refetchInterval: 5_000,
  });
  const { data: acts } = useQuery({
    queryKey: ["eng-activities", eid], queryFn: () => getEngActivities(undefined, eid || undefined),
    enabled: !!eid, refetchInterval: 4_000,
  });

  const run = graph?.run ?? goalsResp?.run ?? null;
  const goals = goalsResp?.goals ?? [];

  const [selId, setSelId] = useState<string | null>(null);
  const { data: nodeDetail } = useQuery({
    queryKey: ["eng-node", eid, selId],
    queryFn: () => getEngNode(selId!, undefined, eid || undefined),
    enabled: !!selId && !!eid && !selId.startsWith("digest:"),
  });

  const invalidate = () => {
    for (const k of ["eng-graph", "eng-goals", "eng-activities", "eng-node"]) qc.invalidateQueries({ queryKey: [k] });
  };

  // ── graph ─────────────────────────────────────────────────────────────────
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({ container: containerRef.current, style: cyStyle, minZoom: 0.1, maxZoom: 3, wheelSensitivity: 0.2 });
    cy.on("tap", "node", (ev) => {
      setSelId(ev.target.id());
      cy.elements().addClass("faded");
      ev.target.closedNeighborhood().removeClass("faded");
    });
    cy.on("tap", (ev) => { if (ev.target === cy) { setSelId(null); cy.elements().removeClass("faded"); } });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, []);
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    const els: ElementDefinition[] = [
      ...graph.nodes.map((n) => ({ group: "nodes" as const, data: { ...n } })),
      ...graph.edges.filter((e) => graph.nodes.some((n) => n.id === e.source) && graph.nodes.some((n) => n.id === e.target))
        .map((e) => ({ group: "edges" as const, data: { id: e.id, source: e.source, target: e.target } })),
    ];
    cy.batch(() => { cy.elements().remove(); cy.add(els); });
    cy.resize();
    const root = graph.nodes.find((n) => n.kind === "objective")?.id;
    try {
      cy.layout({ name: "breadthfirst", directed: true, ...(root ? { roots: [root] } : {}),
        spacingFactor: 1.1, animate: false, fit: true, padding: 28 } as cytoscape.LayoutOptions).run();
    } catch { /* ignore */ }
  }, [graph]);

  const zoomBy = (f: number) => { const cy = cyRef.current; if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); };

  // ── controls ───────────────────────────────────────────────────────────────
  const ctl = useMutation({
    mutationFn: async (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => { invalidate(); toast.success("Exploration updated"); },
    onError: () => toast.error("Action failed"),
  });
  const act = (label: string, fn: () => Promise<unknown>) => ctl.mutate(fn, { onSuccess: () => { invalidate(); toast.success(label); } });

  const streaming = run?.status === "running";
  const noEngine = explorations.length === 0 || (!!eid && graph && graph.nodes.length === 0 && goals.length === 0);

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            Exploration
            {streaming && <span className="pulse-ring inline-block h-2 w-2 rounded-full bg-success" />}
          </h1>
          <p className="truncate text-xs text-muted-foreground">
            {run ? <>Objective: <span className="text-foreground">{run.title}</span> · {run.target} · <span className="capitalize">{run.status}</span></>
              : "Goal-driven autonomous exploration"}
            {graph?.summary && <> · {graph.summary.goals} goals · {graph.summary.intents} intents · {graph.summary.facts} facts</>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {run && (
            <div className="flex items-center gap-1 rounded-md border border-border bg-card p-0.5">
              {run.status === "paused"
                ? <TBtn icon={Play} label="Resume" onClick={() => act("Resumed", () => engResume(run.id))} />
                : <TBtn icon={Pause} label="Pause" onClick={() => act("Paused", () => engPause(run.id))} />}
              <TBtn icon={RefreshCw} label="Replan" onClick={() => act("Replan requested", () => engReplan(run.id))} />
              <TBtn icon={Square} label="Stop" danger onClick={() => act("Stopped", () => engStop(run.id))} />
            </div>
          )}
          <Select value={eid} onChange={(e) => setEid(e.target.value)} className="w-64">
            <option value="">Select an exploration…</option>
            {explorations.map((e) => <option key={e.id} value={e.id}>{e.target} · {e.status}</option>)}
          </Select>
        </div>
      </div>

      {noEngine ? (
        <EmptyState icon={Target} title="No exploration for this scan yet"
          description="The autonomous engine creates an objective, decomposes goals, plans intents and records facts as it runs." />
      ) : (
        <div className="flex min-h-0 flex-1 gap-3">
          {/* Left — goal tree */}
          <aside className="hidden w-60 shrink-0 flex-col overflow-hidden rounded-lg border border-border bg-card lg:flex">
            <div className="border-b border-border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
              Goal tree
            </div>
            <div className="flex-1 overflow-y-auto p-1">
              <GoalTree goals={goals} selId={selId} onSelect={setSelId} />
              {goals.length === 0 && <p className="px-2 py-4 text-center text-xs text-muted-foreground">No goals yet.</p>}
            </div>
          </aside>

          {/* Centre — graph + timeline */}
          <div className="flex min-w-0 flex-1 flex-col gap-3">
            <div className="relative min-h-0 flex-1">
              <div ref={containerRef} className="h-full w-full rounded-lg border border-border bg-panel" />
              <div className="absolute bottom-3 left-3 flex flex-col gap-1 rounded-md border border-border bg-background/80 p-1 backdrop-blur">
                <button onClick={() => zoomBy(1.3)} className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground">+</button>
                <button onClick={() => zoomBy(0.75)} className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground">−</button>
                <button onClick={() => cyRef.current?.fit(undefined, 40)} title="Fit" className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"><Target className="h-3.5 w-3.5" /></button>
              </div>
              {/* Legend */}
              <div className="absolute left-3 top-3 flex animate-fade-in flex-wrap gap-x-3 gap-y-1 rounded-md border border-border bg-background/80 p-2 text-[10px] backdrop-blur">
                {(["objective", "goal", "intent", "fact", "finding"] as EngNodeKind[]).map((k) => (
                  <span key={k} className="flex items-center gap-1 text-muted-foreground">
                    <span className="h-2 w-2 rounded-full" style={{ background: KIND_COLOR[k] }} />{k}
                  </span>
                ))}
              </div>
            </div>
            {/* Activity timeline */}
            <div className="h-36 shrink-0 overflow-hidden rounded-lg border border-border bg-card">
              <div className="border-b border-border px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">Activity timeline</div>
              <div className="h-[calc(100%-1.75rem)] space-y-0.5 overflow-y-auto p-2">
                {(acts?.activities ?? []).length === 0 ? (
                  <p className="px-1 py-3 text-center text-xs text-muted-foreground">No activity yet.</p>
                ) : (acts!.activities.map((a) => (
                  <div key={a.id} className="flex items-center gap-2 rounded px-1.5 py-1 text-[11px] hover:bg-accent/40">
                    <span className="shrink-0 font-mono text-muted-foreground/60">{(a.timestamp ?? "").slice(11, 19)}</span>
                    <span className="shrink-0 rounded border border-border/60 px-1 font-mono text-[9px] text-muted-foreground">{a.activity_type}</span>
                    <span className="truncate text-muted-foreground">{a.summary}</span>
                    <span className="ml-auto shrink-0 text-muted-foreground/50">{a.worker}</span>
                  </div>
                )))}
              </div>
            </div>
          </div>

          {/* Right — inspector */}
          <aside className="hidden w-80 shrink-0 flex-col overflow-hidden rounded-lg border border-border bg-card xl:flex">
            {!selId ? (
              <EmptyState icon={Compass} title="No node selected" description="Click a node in the graph or a goal in the tree." />
            ) : (
              <Inspector detail={nodeDetail} run={run} onAction={act} />
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

function TBtn({ icon: Icon, label, onClick, danger }: { icon: typeof Target; label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick} title={label}
      className={cn("flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors hover:bg-accent",
        danger ? "text-critical hover:text-critical" : "text-muted-foreground hover:text-foreground")}>
      <Icon className="h-3.5 w-3.5" /> <span className="hidden sm:inline">{label}</span>
    </button>
  );
}

// ── goal tree (nested) ────────────────────────────────────────────────────────
function GoalTree({ goals, selId, onSelect }: { goals: EngGoal[]; selId: string | null; onSelect: (id: string) => void }) {
  const children = useMemo(() => {
    const m = new Map<string | null, EngGoal[]>();
    for (const g of goals) {
      const k = g.parent_goal_id;
      (m.get(k) ?? m.set(k, []).get(k)!).push(g);
    }
    return m;
  }, [goals]);

  const render = (parent: string | null, depth: number): React.ReactNode =>
    (children.get(parent) ?? []).map((g) => (
      <div key={g.id}>
        <button onClick={() => onSelect(g.id)}
          style={{ paddingLeft: 8 + depth * 14 }}
          className={cn("flex w-full items-center gap-1.5 rounded px-2 py-1.5 text-left text-xs transition-colors hover:bg-accent/50",
            selId === g.id && "bg-accent/60")}>
          {depth > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/40" />}
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: GOAL_STATE[g.state] ?? "#64748b" }} />
          <span className="truncate text-foreground">{g.title}</span>
          <span className="ml-auto shrink-0 font-mono text-[9px] text-muted-foreground/60">P{g.priority}</span>
        </button>
        {render(g.id, depth + 1)}
      </div>
    ));

  return <>{render(null, 0)}</>;
}

// ── inspector ─────────────────────────────────────────────────────────────────
function Inspector({ detail, run, onAction }: {
  detail: Record<string, unknown> | undefined; run: { id: string } | null;
  onAction: (label: string, fn: () => Promise<unknown>) => void;
}) {
  if (!detail) return <EmptyState icon={Compass} title="Loading…" />;
  const kind = detail.kind as string;
  const id = detail.id as string;
  const title = detail.title as string;
  const facts = (detail.facts as Array<Record<string, unknown>>) ?? [];
  const intents = (detail.intents as Array<Record<string, unknown>>) ?? [];

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="border-b border-border p-3">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground/60">{kind}</span>
        <h2 className="mt-0.5 text-sm font-medium text-foreground">{title}</h2>
        {detail.state != null && <StatusIndicator className="mt-1" tone="info" label={String(detail.state)} />}
      </div>

      <div className="space-y-3 p-3 text-xs">
        {kind === "goal" && (
          <>
            {detail.success_criteria != null && <KV k="criteria" v={JSON.stringify(detail.success_criteria)} />}
            {detail.completion_reason != null && <KV k="reason" v={String(detail.completion_reason)} />}
            {run && (
              <div className="flex flex-wrap gap-1.5">
                <ActBtn icon={ArrowUp} label="Raise priority" onClick={() => onAction("Priority raised", () => engPrioritizeGoal(run.id, id, 1))} />
                <ActBtn icon={Ban} label="Block" danger onClick={() => onAction("Goal blocked", () => engBlockGoal(run.id, id))} />
              </div>
            )}
            <RelList title={`Intents (${intents.length})`} items={intents.map((i) => `${i.tool_name} → ${i.target}  [${i.state}]`)} />
          </>
        )}
        {kind === "intent" && (
          <>
            <KV k="tool" v={String(detail.tool_name)} mono />
            <KV k="target" v={String(detail.target)} mono />
            {detail.rationale ? <KV k="rationale" v={String(detail.rationale)} /> : null}
            <KV k="approval" v={String(detail.approval_state)} />
            {detail.execution_summary ? <KV k="result" v={String(detail.execution_summary)} /> : null}
            {detail.error ? <KV k="error" v={String(detail.error)} /> : null}
            {run && (
              <div className="flex flex-wrap gap-1.5">
                {detail.approval_state === "pending" && (
                  <>
                    <ActBtn icon={Check} label="Approve" onClick={() => onAction("Intent approved", () => engApproveIntent(run.id, id))} />
                    <ActBtn icon={X} label="Reject" danger onClick={() => onAction("Intent rejected", () => engRejectIntent(run.id, id))} />
                  </>
                )}
                <ActBtn icon={Ban} label="Cancel" danger onClick={() => onAction("Intent cancelled", () => engCancelIntent(run.id, id))} />
              </div>
            )}
          </>
        )}
        {kind === "fact" && (
          <>
            <KV k="type" v={String(detail.fact_type)} mono />
            <KV k="asset" v={String(detail.asset)} mono />
            <KV k="source" v={String(detail.source)} />
            <KV k="confidence" v={String(detail.confidence)} />
            {detail.content != null && <KV k="content" v={JSON.stringify(detail.content)} />}
            {detail.evidence_reference != null && <KV k="evidence" v={String(detail.evidence_reference)} />}
          </>
        )}
        {facts.length > 0 && kind !== "fact" && (
          <RelList title={`Supporting facts (${facts.length})`} items={facts.map((f) => String(f.title))} />
        )}
      </div>
    </div>
  );
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 text-muted-foreground/70">{k}</span>
      <span className={cn("min-w-0 break-all text-foreground", mono && "font-mono")}>{v}</span>
    </div>
  );
}
function RelList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">{title}</div>
      <div className="space-y-0.5">
        {items.slice(0, 40).map((t, i) => (
          <div key={i} className="truncate rounded px-1.5 py-1 font-mono text-[11px] text-muted-foreground hover:bg-accent/40">{t}</div>
        ))}
      </div>
    </div>
  );
}
function ActBtn({ icon: Icon, label, onClick, danger }: { icon: typeof Target; label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button onClick={onClick}
      className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] transition-colors",
        danger ? "border-critical/40 text-critical hover:bg-critical/10" : "border-border text-foreground hover:bg-accent")}>
      <Icon className="h-3 w-3" /> {label}
    </button>
  );
}
