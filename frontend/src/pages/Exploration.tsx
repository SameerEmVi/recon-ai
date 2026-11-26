import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Bug,
  ChevronDown,
  ChevronRight,
  Compass,
  Copy,
  Flag,
  FlaskConical,
  Lock,
  ShieldCheck,
  Target,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { listScans, getExploration } from "@/lib/api";
import type { ExploreEdge, ExploreKind, ExploreNode, ExploreRel, ScanStatus } from "@/lib/api";
import { CARD_W, layoutExploration } from "@/lib/explorationLayout";
import { Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

// ── visual vocabulary ─────────────────────────────────────────────────────────

type KindMeta = { label: string; icon: LucideIcon; tile: string; hex: string };
const KIND: Record<ExploreKind, KindMeta> = {
  start: { label: "Start", icon: Flag, tile: "bg-slate-500", hex: "#64748b" },
  scope: { label: "Scope", icon: ShieldCheck, tile: "bg-violet-500", hex: "#8b5cf6" },
  goal: { label: "Goal", icon: Target, tile: "bg-emerald-500", hex: "#10b981" },
  intent: { label: "Intent", icon: Compass, tile: "bg-blue-500", hex: "#3b82f6" },
  fact: { label: "Fact", icon: FlaskConical, tile: "bg-amber-500", hex: "#f59e0b" },
  vulnerability: { label: "Vulnerability", icon: Bug, tile: "bg-rose-500", hex: "#f43f5e" },
};
const LEGEND_KINDS: ExploreKind[] = ["start", "scope", "goal", "intent", "fact", "vulnerability"];

const REL: Record<ExploreRel, { label: string; color: string; dashed?: boolean }> = {
  spawns: { label: "spawns", color: "#10b981" },
  next: { label: "then", color: "#6366f1" },
  constrains: { label: "scope", color: "#8b5cf6", dashed: true },
  yields: { label: "yields", color: "#f59e0b" },
  proves: { label: "proves", color: "#f43f5e" },
  "intent-chain": { label: "data flow", color: "#38bdf8", dashed: true },
};

type Tone = "slate" | "sky" | "indigo" | "emerald" | "amber" | "rose";
const TONE: Record<Tone, string> = {
  slate: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  sky: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  indigo: "bg-indigo-500/15 text-indigo-300 ring-indigo-500/30",
  emerald: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  amber: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  rose: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
};

const GOAL_STATE: Record<string, { label: string; tone: Tone; hint: string }> = {
  locked: { label: "Locked", tone: "slate", hint: "This tier is not allowed by the scan's mode" },
  pending: { label: "Pending", tone: "slate", hint: "No tool for this goal has started yet" },
  running: { label: "In progress", tone: "sky", hint: "Tools for this goal produced output in the last 90 s" },
  waiting: { label: "Quiet", tone: "indigo", hint: "Started; no new output in the last 90 s" },
  achieved: { label: "Achieved", tone: "emerald", hint: "Scan finished and this goal's tools ran" },
  incomplete: { label: "Incomplete", tone: "amber", hint: "Scan finished but some tools failed" },
  skipped: { label: "Skipped", tone: "slate", hint: "Scan finished without any tool for this goal running" },
};
const INTENT_STATE: Record<string, { label: string; tone: Tone; hint: string }> = {
  pending: { label: "Queued", tone: "slate", hint: "Loaded for this scan, waiting for its input events" },
  running: { label: "Running", tone: "sky", hint: "Produced output in the last 90 s" },
  waiting: { label: "Quiet", tone: "indigo", hint: "No new output in the last 90 s; may still be working" },
  done: { label: "Done", tone: "emerald", hint: "Scan finished" },
  failed: { label: "Failed", tone: "rose", hint: "At least one run of this tool failed" },
  skipped: { label: "Not triggered", tone: "slate", hint: "Its input never appeared" },
};
const VERIFY_TONE: Record<string, Tone> = {
  CONFIRMED: "rose",
  POTENTIAL: "amber",
  UNCONFIRMED: "slate",
  OBSERVED: "slate",
};
const SEV_TONE: Record<string, Tone> = {
  critical: "rose",
  high: "rose",
  medium: "amber",
  low: "sky",
  info: "slate",
};
const TIER_LABEL: Record<string, string> = { osint: "Recon (OSINT)", recon: "Enumeration", pentest: "Web app pentest" };

const prioTone = (p: number): Tone => (p >= 8 ? "rose" : p >= 5 ? "amber" : "slate");
const isLive = (n: ExploreNode) => n.state === "running";

function Pill({ tone, children, title, pulse }: { tone: Tone; children: ReactNode; title?: string; pulse?: boolean }) {
  return (
    <span
      title={title}
      className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset", TONE[tone])}
    >
      {pulse !== undefined && (
        <span className={cn("h-1.5 w-1.5 rounded-full bg-current", pulse && "animate-pulse")} />
      )}
      {children}
    </span>
  );
}

function statePill(n: ExploreNode) {
  if (n.kind === "goal" || n.kind === "intent") {
    const table = n.kind === "goal" ? GOAL_STATE : INTENT_STATE;
    const s = table[n.state ?? ""] ?? { label: n.state ?? "—", tone: "slate" as Tone, hint: "" };
    return (
      <Pill tone={s.tone} title={s.hint} pulse={isLive(n)}>
        {n.state === "locked" && <Lock className="h-2.5 w-2.5" />}
        {s.label}
      </Pill>
    );
  }
  if (n.kind === "vulnerability") {
    return n.verification ? (
      <Pill tone={VERIFY_TONE[n.verification] ?? "slate"} title="Verification status (set by deterministic checks)">
        {n.verification.toLowerCase()}
      </Pill>
    ) : (
      <Pill tone={SEV_TONE[n.severity ?? ""] ?? "slate"}>{n.severity ?? "finding"}</Pill>
    );
  }
  if (n.kind === "fact" && n.etype) {
    return <span className="font-mono text-[10px] text-muted-foreground">{n.etype.toLowerCase()}</span>;
  }
  return <span className="text-[10px] text-muted-foreground">{KIND[n.kind].label}</span>;
}

// ── node card ─────────────────────────────────────────────────────────────────

type CardData = {
  node: ExploreNode;
  displayId: string;
  hidden?: number;
  collapsed?: boolean;
  onToggle?: (goalId: string) => void;
};
type CardNode = Node<CardData, "card">;

const handleCls = "!h-2 !w-2 !min-h-0 !min-w-0 !border-0 !bg-transparent";

const ExploreCard = memo(function ExploreCard({ data, selected }: NodeProps<CardNode>) {
  const n = data.node;
  const meta = KIND[n.kind];
  const Icon = meta.icon;
  const locked = n.kind === "goal" && n.state === "locked";
  const live = isLive(n);
  const showPrio = (n.kind === "goal" || n.kind === "intent") && (n.priority ?? 0) > 0;

  let title = n.label;
  let body = n.summary ?? "";
  if (n.kind === "goal") {
    title = `${n.step}. ${n.label}`;
    body = locked
      ? n.reason ?? "Not allowed in this mode"
      : `${n.intents ?? 0} intent${n.intents === 1 ? "" : "s"} · ${n.events ?? 0} events`;
  } else if (n.kind === "start") {
    body = n.summary ?? "";
  }

  return (
    <div
      style={{ width: CARD_W }}
      className={cn(
        "group rounded-xl border-2 transition-colors",
        selected ? "border-sky-400" : live ? "border-sky-500/50" : "border-transparent",
      )}
    >
      <div
        className={cn(
          "relative rounded-[10px] border border-border bg-card shadow-md shadow-black/30 transition-shadow group-hover:shadow-lg group-hover:shadow-black/50",
          locked && "opacity-55",
        )}
      >
        <Handle id="in" type="target" position={Position.Left} className={handleCls} />
        <Handle id="out" type="source" position={Position.Right} className={handleCls} />
        {n.kind === "goal" && (
          <>
            <Handle id="next-in" type="target" position={Position.Top} className={handleCls} />
            <Handle id="next-out" type="source" position={Position.Bottom} className={handleCls} />
          </>
        )}

        <div className="flex items-center gap-2 px-3 pb-1 pt-2.5">
          <span className={cn("flex h-5 w-5 shrink-0 items-center justify-center rounded-md shadow-sm", meta.tile)}>
            <Icon className="h-3 w-3 text-white" />
          </span>
          <span className="grow truncate text-[12px] font-semibold text-foreground/90">{meta.label}</span>
          {live && (
            <span className="relative flex h-2 w-2 shrink-0" aria-label="live">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
            </span>
          )}
          {showPrio && (
            <span className={cn("shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums ring-1 ring-inset", TONE[prioTone(n.priority!)])}>
              P{n.priority}
            </span>
          )}
          {n.kind === "goal" && data.onToggle && !locked && (
            <button
              type="button"
              title={data.collapsed ? "Expand this goal" : "Collapse this goal"}
              onClick={(e) => {
                e.stopPropagation();
                data.onToggle?.(n.id);
              }}
              className="nodrag -mr-1 rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              {data.collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>
          )}
        </div>

        <div className="px-3 pb-2">
          <div className="truncate text-[13px] font-medium text-foreground" title={title}>
            {title}
          </div>
          {body && <div className="mt-0.5 line-clamp-2 break-words text-[11.5px] leading-snug text-muted-foreground">{body}</div>}
        </div>

        <div className="flex items-center justify-between gap-2 px-3 pb-2.5">
          <div className="flex min-w-0 items-center gap-1.5">
            {statePill(n)}
            {data.collapsed && (data.hidden ?? 0) > 0 && (
              <span className="text-[10px] text-muted-foreground">+{data.hidden} hidden</span>
            )}
          </div>
          <span className="shrink-0 font-mono text-[10px] text-muted-foreground/70">{data.displayId}</span>
        </div>
      </div>
    </div>
  );
});

const nodeTypes = { card: ExploreCard };

// ── edges ─────────────────────────────────────────────────────────────────────

function toEdge(e: ExploreEdge, liveTargets: Set<string>): Edge {
  const rel = REL[e.rel] ?? { label: e.rel, color: "#64748b" };
  const isNext = e.rel === "next";
  const animated = liveTargets.has(e.target) && (e.rel === "spawns" || e.rel === "intent-chain");
  return {
    id: e.id,
    source: e.source,
    target: e.target,
    sourceHandle: isNext ? "next-out" : "out",
    targetHandle: isNext ? "next-in" : "in",
    type: "default",
    animated,
    label: e.rel === "intent-chain" ? undefined : rel.label,
    labelShowBg: false,
    labelStyle: { fontSize: 10, fontWeight: 600, fill: rel.color },
    style: {
      stroke: rel.color,
      strokeWidth: isNext ? 2.5 : e.rel === "intent-chain" ? 1.2 : 1.8,
      strokeOpacity: animated ? 0.95 : e.rel === "intent-chain" ? 0.45 : 0.6,
      strokeDasharray: rel.dashed ? "5 4" : undefined,
    },
    markerEnd: { type: MarkerType.ArrowClosed, color: rel.color, width: 14, height: 14 },
    zIndex: isNext ? 1 : 0,
  };
}

// ── page ──────────────────────────────────────────────────────────────────────

export default function Exploration() {
  return (
    <ReactFlowProvider>
      <ExplorationView />
    </ReactFlowProvider>
  );
}

function ExplorationView() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  // Always enabled: with no scan picked the backend falls back to the most
  // recent scan in the DB, so CLI-launched and past scans are viewable too.
  const { data } = useQuery({
    queryKey: ["exploration", scanId],
    queryFn: () => getExploration(scanId || undefined),
    refetchInterval: 4_000, // live: the plan fills in as the scan runs
  });
  const shownScanId = scanId || data?.scan?.scan_id || "";

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [showFlow, setShowFlow] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<CardNode>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const { fitView, setViewport } = useReactFlow();
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const layoutSig = useRef("");
  const fittedFor = useRef("");

  const toggleGoal = useCallback((goalId: string) => {
    setCollapsed((cur) => {
      const next = new Set(cur);
      if (next.has(goalId)) next.delete(goalId);
      else next.add(goalId);
      return next;
    });
  }, []);

  useEffect(() => {
    setCollapsed(new Set());
    setSelectedId(null);
    layoutSig.current = "";
  }, [shownScanId]);

  const nodes = useMemo(() => data?.nodes ?? [], [data]);
  const edges = useMemo(() => data?.edges ?? [], [data]);
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const laid = useMemo(() => layoutExploration(nodes, edges, collapsed), [nodes, edges, collapsed]);

  // Re-lay out only when the structure changes; a pure data refresh keeps any
  // positions the operator dragged.
  useEffect(() => {
    const sig = [...laid.visible].sort().join("|");
    const relayout = sig !== layoutSig.current;
    layoutSig.current = sig;
    setRfNodes((prev) => {
      const prevPos = new Map(prev.map((p) => [p.id, p.position]));
      return nodes
        .filter((n) => laid.visible.has(n.id))
        .map((n) => ({
          id: n.id,
          type: "card" as const,
          position: (!relayout && prevPos.get(n.id)) || laid.positions.get(n.id) || { x: 0, y: 0 },
          data: {
            node: n,
            displayId: laid.displayId.get(n.id) ?? "",
            hidden: laid.hiddenCount.get(n.id),
            collapsed: collapsed.has(n.id),
            onToggle: toggleGoal,
          },
          selected: n.id === selectedId,
        }));
    });
    const live = new Set(nodes.filter(isLive).map((n) => n.id));
    setRfEdges(
      edges
        .filter((e) => laid.visible.has(e.source) && laid.visible.has(e.target))
        .filter((e) => showFlow || e.rel !== "intent-chain")
        .map((e) => toEdge(e, live)),
    );
  }, [nodes, edges, laid, collapsed, showFlow, selectedId, toggleGoal, setRfNodes, setRfEdges]);

  // Open each scan at the top-left of the plan at a readable zoom: fit the width
  // (capped at 100%) and let the operator scroll down, rather than shrinking a
  // tall plan until the cards are unreadable.
  const showTop = useCallback(
    (duration = 300) => {
      const el = canvasRef.current;
      if (!el || laid.positions.size === 0) return;
      let minX = Infinity, minY = Infinity, maxX = -Infinity;
      for (const id of laid.visible) {
        const p = laid.positions.get(id);
        if (!p) continue;
        minX = Math.min(minX, p.x);
        minY = Math.min(minY, p.y);
        maxX = Math.max(maxX, p.x + CARD_W);
      }
      const pad = 32;
      const zoom = Math.max(0.45, Math.min(1, (el.clientWidth - pad * 2) / (maxX - minX)));
      void setViewport({ x: pad - minX * zoom, y: pad + 96 - minY * zoom, zoom }, { duration });
    },
    [laid, setViewport],
  );
  useEffect(() => {
    if (!shownScanId || rfNodes.length < 3 || fittedFor.current === shownScanId) return;
    fittedFor.current = shownScanId;
    requestAnimationFrame(() => showTop(0));
  }, [shownScanId, rfNodes.length, showTop]);

  const goals = useMemo(
    () => nodes.filter((n) => n.kind === "goal").sort((a, b) => (a.step ?? 0) - (b.step ?? 0)),
    [nodes],
  );

  const focusGoal = (goalId: string) => {
    if (collapsed.has(goalId)) toggleGoal(goalId);
    const ids = new Set([goalId]);
    for (const e of edges) if (e.source === goalId && e.rel !== "next" && e.rel !== "constrains") ids.add(e.target);
    requestAnimationFrame(() =>
      fitView({ nodes: [...ids].map((id) => ({ id })), padding: 0.25, duration: 450, maxZoom: 1.1 }),
    );
    setSelectedId(goalId);
  };

  const summary = data?.summary;
  const streaming = (data?.scan?.status ?? "") === "running";
  const selected = selectedId ? byId.get(selectedId) ?? null : null;
  const empty = !data?.scan || nodes.length <= 2;
  // The selector lists console scans, plus the DB scan being shown if it isn't one.
  const scanOptions = [...(scans ?? [])];
  if (data?.scan && !scanOptions.some((s) => s.scan_id === data.scan!.scan_id)) {
    scanOptions.push({ ...data.scan, status: data.scan.status as ScanStatus["status"], event_count: 0 });
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            Exploration
            {streaming && <span className="pulse-ring inline-block h-2 w-2 rounded-full bg-success" aria-label="live" />}
          </h1>
          <p className="text-xs text-muted-foreground">
            The scan's plan, left to right: goals → intents → facts → vulnerabilities
            {summary
              ? ` · ${summary.goals_achieved}/${summary.goals} goals achieved · ${summary.intents} intents · ${summary.facts} facts · ${summary.vulnerabilities} vulns`
              : ""}
            {data?.scan ? ` · ${data.scan.domain} (${data.scan.mode})` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex cursor-pointer select-none items-center gap-1.5 text-xs text-muted-foreground">
            <input type="checkbox" checked={showFlow} onChange={(e) => setShowFlow(e.target.checked)} className="accent-sky-500" />
            Data flow
          </label>
          <button
            type="button"
            onClick={() => showTop()}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            Top
          </button>
          <button
            type="button"
            onClick={() => void fitView({ padding: 0.1, duration: 400 })}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            Whole plan
          </button>
          <button
            type="button"
            onClick={() => setCollapsed(collapsed.size ? new Set() : new Set(goals.map((g) => g.id)))}
            className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            {collapsed.size ? "Expand all" : "Collapse all"}
          </button>
          <Select value={shownScanId} onChange={(e) => setScanId(e.target.value)} className="w-64">
            <option value="">Latest scan</option>
            {scanOptions.map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.domain} · {s.status}
              </option>
            ))}
          </Select>
        </div>
      </div>

      {goals.length > 0 && <GoalStepper goals={goals} activeId={selectedId} onPick={focusGoal} />}

      <div ref={canvasRef} className="relative h-[72vh] w-full overflow-hidden rounded-xl border border-border">
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, node) => setSelectedId(node.id)}
          onPaneClick={() => setSelectedId(null)}
          nodeTypes={nodeTypes}
          nodesConnectable={false}
          panOnScroll
          zoomOnPinch
          colorMode="dark"
          minZoom={0.08}
          maxZoom={1.75}
          proOptions={{ hideAttribution: true }}
          onlyRenderVisibleElements
          className="!bg-background"
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="hsl(222 14% 22%)" />
          <Controls showInteractive={false} className="!overflow-hidden !rounded-lg !border !border-border !shadow-md" />
          <MiniMap
            pannable
            zoomable
            className="!rounded-lg !border !border-border !bg-card"
            maskColor="rgb(2 6 23 / 0.55)"
            nodeColor={(node) => KIND[(node.data as CardData | undefined)?.node.kind ?? "intent"].hex}
            nodeStrokeWidth={0}
            nodeBorderRadius={4}
          />
          <Panel position="top-left">
            <Legend />
          </Panel>
        </ReactFlow>

        {empty && (
          <div className="pointer-events-none absolute inset-0 flex animate-fade-in items-center justify-center">
            <p className="text-sm text-muted-foreground">
              {!data?.scan ? "No scans recorded yet. Run a scan to see its plan." : "No exploration recorded yet for this scan."}
            </p>
          </div>
        )}

        {selected && (
          <DetailPanel
            node={selected}
            displayId={laid.displayId.get(selected.id) ?? ""}
            byId={byId}
            onSelect={setSelectedId}
            onClose={() => setSelectedId(null)}
          />
        )}
      </div>
    </div>
  );
}

// ── goal stepper: the goals in processing order ───────────────────────────────

function GoalStepper({ goals, activeId, onPick }: { goals: ExploreNode[]; activeId: string | null; onPick: (id: string) => void }) {
  return (
    <ol className="flex flex-wrap items-stretch gap-2">
      {goals.map((g, i) => {
        const s = GOAL_STATE[g.state ?? ""] ?? GOAL_STATE.pending;
        const doneish = g.state === "achieved";
        return (
          <li key={g.id} className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onPick(g.id)}
              title={s.hint}
              className={cn(
                "flex items-center gap-2.5 rounded-lg border bg-card px-3 py-2 text-left transition-colors hover:bg-accent",
                activeId === g.id ? "border-sky-500/60" : "border-border",
                g.state === "locked" && "opacity-55",
              )}
            >
              <span
                className={cn(
                  "flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold",
                  doneish ? "bg-emerald-500 text-white" : g.state === "running" ? "bg-sky-500 text-white" : "bg-muted text-muted-foreground",
                )}
              >
                {g.state === "locked" ? <Lock className="h-3 w-3" /> : g.step}
              </span>
              <span className="min-w-0">
                <span className="block text-[12.5px] font-medium leading-tight text-foreground">{g.label}</span>
                <span className="mt-0.5 flex items-center gap-1.5">
                  <Pill tone={s.tone} pulse={g.state === "running"}>
                    {s.label}
                  </Pill>
                  <span className="text-[10.5px] text-muted-foreground">
                    {g.intents ?? 0} intents · {g.events ?? 0} events
                  </span>
                </span>
              </span>
            </button>
            {i < goals.length - 1 && <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/60" />}
          </li>
        );
      })}
    </ol>
  );
}

// ── legend ────────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div className="flex max-w-[380px] flex-col gap-2 rounded-lg border border-border bg-card/95 p-2.5 text-[11px] shadow-md backdrop-blur">
      <div className="flex flex-wrap gap-x-3 gap-y-1.5">
        {LEGEND_KINDS.map((k) => {
          const m = KIND[k];
          const Icon = m.icon;
          return (
            <span key={k} className="inline-flex items-center gap-1.5 text-foreground/90">
              <span className={cn("flex h-4 w-4 items-center justify-center rounded", m.tile)}>
                <Icon className="h-2.5 w-2.5 text-white" />
              </span>
              {m.label}
            </span>
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1.5 border-t border-border pt-2 text-muted-foreground">
        {(Object.keys(REL) as ExploreRel[]).map((k) => (
          <span key={k} className="inline-flex items-center gap-1.5">
            <svg width="16" height="4" aria-hidden>
              <line x1="0" y1="2" x2="16" y2="2" stroke={REL[k].color} strokeWidth="2" strokeDasharray={REL[k].dashed ? "4 3" : undefined} />
            </svg>
            {REL[k].label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── detail panel ──────────────────────────────────────────────────────────────

function ago(iso?: string) {
  if (!iso) return null;
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex items-start gap-3 py-1">
      <dt className="w-20 shrink-0 text-muted-foreground">{k}</dt>
      <dd className="min-w-0 flex-1 break-words text-foreground">{children}</dd>
    </div>
  );
}

function Chips({ items, onPick }: { items: string[]; onPick?: (s: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((t) => (
        <button
          key={t}
          type="button"
          disabled={!onPick}
          onClick={() => onPick?.(t)}
          className={cn("rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10.5px]", onPick && "hover:border-sky-500/60 hover:text-sky-300")}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

function DetailPanel({
  node,
  displayId,
  byId,
  onSelect,
  onClose,
}: {
  node: ExploreNode;
  displayId: string;
  byId: Map<string, ExploreNode>;
  onSelect: (id: string) => void;
  onClose: () => void;
}) {
  const meta = KIND[node.kind];
  const Icon = meta.icon;
  const [copied, setCopied] = useState(false);
  const raw = JSON.stringify(node, null, 2);
  const pickIntent = (tool: string) => byId.has(`intent:${tool}`) && onSelect(`intent:${tool}`);

  return (
    <aside className="absolute bottom-3 right-3 top-3 z-10 flex w-80 animate-slide-in-right flex-col overflow-hidden rounded-lg border border-border bg-card/95 text-xs shadow-xl backdrop-blur">
      <header className="flex items-center gap-2.5 border-b border-border p-3">
        <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-lg", meta.tile)}>
          <Icon className="h-4 w-4 text-white" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold text-foreground">{node.label}</div>
          <div className="font-mono text-[10.5px] text-muted-foreground">
            {meta.label} · {displayId}
          </div>
        </div>
        <button type="button" onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground" aria-label="Close">
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
        {node.summary && node.kind !== "intent" && <p className="leading-relaxed text-muted-foreground">{node.summary}</p>}
        <dl>
          {(node.kind === "goal" || node.kind === "intent" || node.kind === "vulnerability") && <Row k="Status">{statePill(node)}</Row>}
          {node.reason && <Row k="Why">{node.reason}</Row>}
          {node.priority != null && <Row k="Priority">P{node.priority}</Row>}
          {node.tier && node.kind === "intent" && <Row k="Goal">{TIER_LABEL[node.tier] ?? node.tier}</Row>}
          {node.kind === "intent" && node.summary && <Row k="Output">{node.summary}</Row>}
          {node.kind === "goal" && <Row k="Intents">{node.intents ?? 0}</Row>}
          {node.events != null && <Row k="Events">{node.events}</Row>}
          {node.count != null && node.kind !== "intent" && <Row k="Count">{node.count}</Row>}
          {node.hosts != null && node.hosts > 0 && <Row k="Hosts">{node.hosts}</Row>}
          {node.first_seen && <Row k="Started">{ago(node.first_seen)}</Row>}
          {node.last_seen && <Row k="Last output">{ago(node.last_seen)}</Row>}
          {node.failed_jobs != null && <Row k="Failed runs">{node.failed_jobs}</Row>}
          {node.more_facts != null && <Row k="More facts">{node.more_facts} more event types not shown</Row>}
          {node.severity && <Row k="Severity">{node.severity}</Row>}
          {node.category && <Row k="Category"><span className="font-mono">{node.category}</span></Row>}
          {node.host && <Row k="Host"><span className="font-mono">{node.host}</span></Row>}
          {node.confidence != null && <Row k="Confidence">{Math.round(node.confidence * 100)}%</Row>}
          {node.mode && <Row k="Mode">{node.mode}</Row>}
          {node.status && <Row k="Scan">{node.status}</Row>}
          {node.in_scope && <Row k="In scope"><Chips items={node.in_scope} /></Row>}
          {node.out_scope && <Row k="Out of scope"><Chips items={node.out_scope} /></Row>}
          {node.caps && <Row k="Capabilities"><Chips items={node.caps.map((c) => c.toLowerCase())} /></Row>}
          {node.fed_by && <Row k="Fed by"><Chips items={node.fed_by} onPick={pickIntent} /></Row>}
          {node.feeds && <Row k="Feeds"><Chips items={node.feeds} onPick={pickIntent} /></Row>}
        </dl>

        {node.samples && node.samples.length > 0 && (
          <section>
            <h4 className="mb-1 text-[11px] font-medium text-muted-foreground">Examples</h4>
            <ul className="space-y-0.5 font-mono text-[11px] text-foreground">
              {node.samples.map((s) => (
                <li key={s} className="break-all">{s}</li>
              ))}
            </ul>
          </section>
        )}

        <section className="border-t border-border pt-2">
          <div className="mb-1 flex items-center justify-between">
            <h4 className="text-[11px] font-medium text-muted-foreground">Raw</h4>
            <button
              type="button"
              onClick={() =>
                void navigator.clipboard?.writeText(raw).then(() => {
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1200);
                })
              }
              className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
            >
              <Copy className="h-3 w-3" />
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background/60 p-2 font-mono text-[10.5px] text-muted-foreground">
            {raw}
          </pre>
        </section>
      </div>
    </aside>
  );
}
