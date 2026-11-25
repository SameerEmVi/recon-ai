import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition } from "cytoscape";
import {
  Search, ZoomIn, ZoomOut, Maximize2, RotateCcw, X,
} from "lucide-react";
import { listScans, getGraph } from "@/lib/api";
import type { GraphKind, GraphNode, GraphEdge } from "@/lib/api";
import { useLiveSocket } from "@/lib/live";
import { Select, Input } from "@/components/ui/field";
import { StatusIndicator } from "@/components/common/StatusIndicator";
import { cn } from "@/lib/cn";

// Node palette aligned to the design-system accents.
const KIND_COLOR: Record<GraphKind, string> = {
  domain: "#818cf8", host: "#38bdf8", ip: "#22d3ee", service: "#22c55e",
  port: "#f59e0b", tech: "#fb923c", url: "#94a3b8", finding: "#ef4444",
  anomaly: "#f472b6", email: "#c084fc",
};
const KIND_ORDER: GraphKind[] = [
  "domain", "host", "ip", "service", "port", "tech", "url", "finding", "anomaly", "email",
];

const MAX_ELEMENTS = 6000;
const COSE_MAX_NODES = 500;

function nodeEl(n: GraphNode): ElementDefinition { return { group: "nodes", data: { ...n } }; }
function edgeEl(e: GraphEdge): ElementDefinition {
  return { group: "edges", data: { id: e.id, source: e.source, target: e.target, rel: e.rel } };
}

const cyStyle: cytoscape.Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": (el) => KIND_COLOR[(el.data("kind") as GraphKind)] ?? "#64748b",
      label: "data(label)", color: "#cbd5e1", "font-size": 7,
      "font-family": "\"JetBrains Mono\", ui-monospace, monospace",
      "text-valign": "bottom", "text-halign": "center", "text-margin-y": 2,
      "min-zoomed-font-size": 6, width: 12, height: 12, "border-width": 0,
    },
  },
  { selector: 'node[kind = "domain"]', style: { width: 26, height: 26, "font-size": 10 } },
  { selector: 'node[kind = "host"]', style: { width: 16, height: 16 } },
  { selector: 'node[kind = "finding"]', style: { shape: "diamond", width: 16, height: 16, "border-width": 2, "border-color": "#ef4444" } },
  { selector: 'node[kind = "anomaly"]', style: { shape: "triangle" } },
  { selector: "edge", style: { width: 1, "line-color": "#334155", "curve-style": "bezier", "target-arrow-shape": "none", opacity: 0.6 } },
  { selector: "node:selected", style: { "border-width": 3, "border-color": "#38bdf8" } },
  { selector: ".faded", style: { opacity: 0.12 } },
  { selector: ".search-hit", style: { "border-width": 3, "border-color": "#f59e0b" } },
  { selector: ".hidden-el", style: { display: "none" } },
];

export default function Map() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data: graph } = useQuery({
    queryKey: ["graph", scanId], queryFn: () => getGraph(scanId || undefined),
    enabled: !!scanId, refetchInterval: 15_000,
  });
  const { state, connected } = useLiveSocket(scanId || undefined);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const processedSeq = useRef(0);
  const layoutTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [related, setRelated] = useState<GraphNode[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [truncated, setTruncated] = useState(false);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({ container: containerRef.current, style: cyStyle, minZoom: 0.1, maxZoom: 3, wheelSensitivity: 0.2 });
    cy.on("tap", "node", (ev) => {
      const node = ev.target;
      setSelected(node.data() as GraphNode);
      setRelated(node.neighborhood("node").map((n: cytoscape.NodeSingular) => n.data() as GraphNode));
      cy.elements().addClass("faded");
      node.closedNeighborhood().removeClass("faded");
    });
    cy.on("tap", (ev) => {
      if (ev.target === cy) { setSelected(null); setRelated([]); cy.elements().removeClass("faded"); }
    });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, []);

  const scheduleLayout = (initial: boolean) => {
    if (layoutTimer.current) clearTimeout(layoutTimer.current);
    layoutTimer.current = setTimeout(() => {
      const cy = cyRef.current;
      if (!cy) return;
      cy.resize();
      const n = cy.nodes().length;
      const opts = n > COSE_MAX_NODES
        ? { name: "concentric", animate: false, fit: true, concentric: (node: cytoscape.NodeSingular) => node.degree(false), levelWidth: () => 6, minNodeSpacing: 8 }
        : { name: "cose", animate: initial, animationDuration: 400, nodeRepulsion: () => 8000, idealEdgeLength: () => 60, fit: initial, randomize: false };
      try { cy.layout(opts as unknown as cytoscape.LayoutOptions).run(); }
      catch { try { cy.layout({ name: "grid", fit: true } as cytoscape.LayoutOptions).run(); } catch { /* ignore */ } }
      recount();
    }, initial ? 0 : 350);
  };

  const recount = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const by: Record<string, number> = {};
    cy.nodes().forEach((n) => { const k = n.data("kind") as string; by[k] = (by[k] ?? 0) + 1; });
    setCounts(by);
  };

  const addElements = (nodes: GraphNode[], edges: GraphEdge[]): boolean => {
    const cy = cyRef.current;
    if (!cy) return false;
    let added = false, capped = false, count = cy.elements().length;
    cy.batch(() => {
      for (const n of nodes) {
        if (count >= MAX_ELEMENTS) { capped = true; break; }
        if (cy.getElementById(n.id).empty()) { cy.add(nodeEl(n)); count++; added = true; }
      }
      for (const e of edges) {
        if (count >= MAX_ELEMENTS) { capped = true; break; }
        if (!cy.getElementById(e.id).empty()) continue;
        if (cy.getElementById(e.source).empty() || cy.getElementById(e.target).empty()) continue;
        cy.add(edgeEl(e)); count++; added = true;
      }
    });
    if (capped) setTruncated(true);
    return added;
  };

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    cy.elements().remove();
    processedSeq.current = 0;
    setTruncated(graph.truncated);
    addElements(graph.nodes, graph.edges);
    recount();
    scheduleLayout(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, scanId]);

  useEffect(() => {
    if (!cyRef.current) return;
    const fresh = state.events.filter((f) => f.kind === "event" && f.seq > processedSeq.current && f.graph);
    if (fresh.length === 0) return;
    processedSeq.current = Math.max(processedSeq.current, ...state.events.map((f) => f.seq));
    let added = false;
    for (const f of fresh) {
      if (!f.graph) continue;
      if (addElements(f.graph.nodes as unknown as GraphNode[], f.graph.edges as unknown as GraphEdge[])) added = true;
    }
    if (added) { recount(); scheduleLayout(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.lastSeq]);

  // Node-type filter → show/hide whole kinds.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach((n) => {
        n.toggleClass("hidden-el", hidden.has(n.data("kind") as string));
      });
    });
  }, [hidden, counts]);

  // Graph search → ring matching nodes, fit to them.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass("search-hit");
    const q = search.trim().toLowerCase();
    if (!q) return;
    const hits = cy.nodes().filter((n) => String(n.data("label") ?? "").toLowerCase().includes(q));
    hits.addClass("search-hit");
    if (hits.length) cy.animate({ fit: { eles: hits, padding: 80 } }, { duration: 300 });
  }, [search]);

  const total = useMemo(() => Object.values(counts).reduce((a, b) => a + b, 0), [counts]);
  const zoomBy = (f: number) => { const cy = cyRef.current; if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); };
  const fit = () => cyRef.current?.fit(undefined, 40);
  const toggleKind = (k: string) => setHidden((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Attack Surface Graph</h1>
          <p className="text-xs text-muted-foreground">
            Live entity graph — <span className="tabular-nums">{total}</span> nodes{graph?.scan ? ` · ${graph.scan.domain}` : ""}
            {truncated && <span className="text-warning"> · capped</span>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusIndicator tone={connected ? "success" : "critical"} pulse={connected} label={connected ? "streaming" : "disconnected"} />
          <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-56">
            <option value="">Select a scan…</option>
            {(scans ?? []).map((s) => <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>)}
          </Select>
        </div>
      </div>

      {/* 3-panel workspace */}
      <div className="flex min-h-0 flex-1 gap-3">
        {/* Left — search + node-type filters */}
        <aside className="hidden w-56 shrink-0 flex-col overflow-hidden rounded-lg border border-border bg-card lg:flex">
          <div className="border-b border-border p-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search nodes…" className="h-8 pl-8 text-xs" />
            </div>
          </div>
          <div className="border-b border-border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">Node types</div>
          <div className="flex-1 overflow-y-auto p-1">
            {KIND_ORDER.filter((k) => counts[k]).map((k) => (
              <button key={k} onClick={() => toggleKind(k)}
                className={cn("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs transition-colors hover:bg-accent/50",
                  hidden.has(k) && "opacity-40")}>
                <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: KIND_COLOR[k] }} />
                <span className="capitalize text-foreground">{k}</span>
                <span className="ml-auto tabular-nums text-muted-foreground">{counts[k]}</span>
              </button>
            ))}
            {total === 0 && <p className="px-2 py-4 text-center text-xs text-muted-foreground">No assets yet.</p>}
          </div>
        </aside>

        {/* Centre — canvas + controls */}
        <div className="relative min-w-0 flex-1">
          <div ref={containerRef} className="h-full w-full rounded-lg border border-border bg-panel" />
          {/* Zoom controls */}
          <div className="absolute bottom-3 left-3 flex flex-col gap-1 rounded-md border border-border bg-background/80 p-1 backdrop-blur">
            {[
              { icon: ZoomIn, fn: () => zoomBy(1.3), label: "Zoom in" },
              { icon: ZoomOut, fn: () => zoomBy(0.75), label: "Zoom out" },
              { icon: Maximize2, fn: fit, label: "Fit to screen" },
              { icon: RotateCcw, fn: () => scheduleLayout(true), label: "Reset layout" },
            ].map(({ icon: Icon, fn, label }) => (
              <button key={label} onClick={fn} title={label} aria-label={label}
                className="flex h-7 w-7 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground">
                <Icon className="h-4 w-4" />
              </button>
            ))}
          </div>
          {/* Empty states */}
          {!scanId ? (
            <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
              <p className="text-sm text-muted-foreground">Select a scan to map.</p>
            </div>
          ) : total === 0 ? (
            <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
              <p className="text-sm text-muted-foreground">{graph ? "No mappable assets yet." : "Loading graph…"}</p>
            </div>
          ) : null}
        </div>

        {/* Right — selected asset */}
        {selected && (
          <aside className="hidden w-72 shrink-0 animate-slide-in-right flex-col overflow-hidden rounded-lg border border-border bg-card xl:flex">
            <div className="flex items-center justify-between border-b border-border px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[selected.kind] }} />
                <span className="font-mono text-xs capitalize text-foreground">{selected.kind}</span>
              </div>
              <button onClick={() => { setSelected(null); setRelated([]); cyRef.current?.elements().removeClass("faded"); }}
                className="text-muted-foreground hover:text-foreground"><X className="h-3.5 w-3.5" /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 text-xs">
              <div className="break-all font-mono text-sm text-foreground">{selected.label}</div>
              <dl className="mt-3 space-y-1 text-muted-foreground">
                {selected.url && <Row k="url" v={selected.url} />}
                {selected.status != null && <Row k="status" v={String(selected.status)} />}
                {selected.title && <Row k="title" v={selected.title} />}
                {selected.server && <Row k="server" v={selected.server} />}
                {selected.version && <Row k="version" v={selected.version} />}
                {selected.category && <Row k="category" v={selected.category} />}
                {selected.severity && <Row k="severity" v={selected.severity} />}
                {selected.method && <Row k="method" v={selected.method} />}
                {selected.description && <Row k="detail" v={selected.description} />}
              </dl>
              {related.length > 0 && (
                <div className="mt-4">
                  <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                    Related assets ({related.length})
                  </div>
                  <div className="space-y-0.5">
                    {related.slice(0, 40).map((r) => (
                      <button key={r.id}
                        onClick={() => {
                          const cy = cyRef.current; if (!cy) return;
                          const el = cy.getElementById(r.id);
                          if (el.nonempty()) { el.emit("tap"); cy.animate({ fit: { eles: el.closedNeighborhood(), padding: 80 } }, { duration: 300 }); }
                        }}
                        className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left transition-colors hover:bg-accent/50">
                        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: KIND_COLOR[r.kind] }} />
                        <span className="truncate font-mono text-[11px] text-foreground">{r.label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <dt className="w-16 shrink-0 text-muted-foreground/70">{k}</dt>
      <dd className="min-w-0 break-all text-foreground">{v}</dd>
    </div>
  );
}
