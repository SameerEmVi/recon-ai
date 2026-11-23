import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition } from "cytoscape";
import { listScans, getGraph } from "@/lib/api";
import type { GraphKind, GraphNode, GraphEdge } from "@/lib/api";
import { useLiveSocket } from "@/lib/live";
import { Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

// One palette, shared by the node styles and the legend.
const KIND_COLOR: Record<GraphKind, string> = {
  domain: "#a78bfa",
  host: "#38bdf8",
  ip: "#22d3ee",
  service: "#34d399",
  port: "#facc15",
  tech: "#fb923c",
  url: "#94a3b8",
  finding: "#f87171",
  anomaly: "#f472b6",
  email: "#c084fc",
};
const KIND_ORDER: GraphKind[] = [
  "domain", "host", "ip", "service", "port", "tech", "url", "finding", "anomaly", "email",
];

const MAX_ELEMENTS = 6000; // browser-side safety cap (fits the backend's 2500-node graph + edges)
const COSE_MAX_NODES = 500; // above this, cose is too slow — use a fast deterministic layout

function nodeEl(n: GraphNode): ElementDefinition {
  return { group: "nodes", data: { ...n } };
}
function edgeEl(e: GraphEdge): ElementDefinition {
  return { group: "edges", data: { id: e.id, source: e.source, target: e.target, rel: e.rel } };
}

const cyStyle: cytoscape.Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": (el) => KIND_COLOR[(el.data("kind") as GraphKind)] ?? "#64748b",
      label: "data(label)",
      color: "#cbd5e1",
      "font-size": 7,
      "font-family": "ui-monospace, monospace",
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 2,
      "min-zoomed-font-size": 6,
      width: 12,
      height: 12,
      "border-width": 0,
    },
  },
  { selector: 'node[kind = "domain"]', style: { width: 26, height: 26, "font-size": 10 } },
  { selector: 'node[kind = "host"]', style: { width: 16, height: 16 } },
  {
    selector: 'node[kind = "finding"]',
    style: { shape: "diamond", width: 16, height: 16, "border-width": 2, "border-color": "#ef4444" },
  },
  { selector: 'node[kind = "anomaly"]', style: { shape: "triangle" } },
  {
    selector: "edge",
    style: {
      width: 1,
      "line-color": "#334155",
      "curve-style": "bezier",
      "target-arrow-shape": "none",
      opacity: 0.6,
    },
  },
  {
    selector: "node:selected",
    style: { "border-width": 3, "border-color": "#f8fafc" },
  },
  {
    selector: ".faded",
    style: { opacity: 0.12 },
  },
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
    queryKey: ["graph", scanId],
    queryFn: () => getGraph(scanId || undefined),
    enabled: !!scanId,
    refetchInterval: 15_000, // backstop; live deltas do the fast updates
  });

  const { state, connected } = useLiveSocket(scanId || undefined);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const processedSeq = useRef(0);
  const layoutTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [truncated, setTruncated] = useState(false);

  // Create the Cytoscape instance once.
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      style: cyStyle,
      minZoom: 0.1,
      maxZoom: 3,
      wheelSensitivity: 0.2,
    });
    cy.on("tap", "node", (ev) => {
      setSelected(ev.target.data() as GraphNode);
      cy.elements().addClass("faded");
      ev.target.closedNeighborhood().removeClass("faded");
    });
    cy.on("tap", (ev) => {
      if (ev.target === cy) {
        setSelected(null);
        cy.elements().removeClass("faded");
      }
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  const scheduleLayout = (initial: boolean) => {
    if (layoutTimer.current) clearTimeout(layoutTimer.current);
    layoutTimer.current = setTimeout(() => {
      const cy = cyRef.current;
      if (!cy) return;
      // The container may have been zero-sized when the instance was created
      // (e.g. first paint); resize picks up the real box before we lay out.
      cy.resize();
      const n = cy.nodes().length;
      // cose (force-directed) is only viable for small graphs; a large one would
      // stall the main thread, so it gets a fast deterministic layout instead.
      const opts =
        n > COSE_MAX_NODES
          ? {
              name: "concentric",
              animate: false,
              fit: true,
              concentric: (node: cytoscape.NodeSingular) => node.degree(false),
              levelWidth: () => 6,
              minNodeSpacing: 8,
            }
          : {
              name: "cose",
              animate: initial,
              animationDuration: 400,
              nodeRepulsion: () => 8000,
              idealEdgeLength: () => 60,
              fit: initial,
              randomize: false,
            };
      try {
        cy.layout(opts as unknown as cytoscape.LayoutOptions).run();
      } catch {
        // A layout engine failure must never leave the canvas blank — fall back
        // to the trivial grid, which always renders.
        try {
          cy.layout({ name: "grid", fit: true } as cytoscape.LayoutOptions).run();
        } catch {
          /* ignore */
        }
      }
      recount();
    }, initial ? 0 : 350);
  };

  // Recompute the per-kind node counts directly from the graph — independent of
  // the layout, so the count shows even when a big layout is slow or fails.
  const recount = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const by: Record<string, number> = {};
    cy.nodes().forEach((n) => {
      const k = n.data("kind") as string;
      by[k] = (by[k] ?? 0) + 1;
    });
    setCounts(by);
  };

  // Add nodes (first) then edges, deduping by id against what's already in cy.
  // The element cap is enforced WHILE adding (a large REST snapshot can exceed it
  // on its own), so the canvas is always bounded regardless of payload size.
  const addElements = (nodes: GraphNode[], edges: GraphEdge[]): boolean => {
    const cy = cyRef.current;
    if (!cy) return false;
    let added = false;
    let capped = false;
    let count = cy.elements().length;
    cy.batch(() => {
      for (const n of nodes) {
        if (count >= MAX_ELEMENTS) { capped = true; break; }
        if (cy.getElementById(n.id).empty()) {
          cy.add(nodeEl(n));
          count++;
          added = true;
        }
      }
      for (const e of edges) {
        if (count >= MAX_ELEMENTS) { capped = true; break; }
        if (!cy.getElementById(e.id).empty()) continue;
        // only link nodes that exist (endpoints always ship with their edge)
        if (cy.getElementById(e.source).empty() || cy.getElementById(e.target).empty()) continue;
        cy.add(edgeEl(e));
        count++;
        added = true;
      }
    });
    if (capped) setTruncated(true);
    return added;
  };

  // Initial / refetched graph: reset the canvas and load it.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    cy.elements().remove();
    processedSeq.current = 0;
    setTruncated(graph.truncated);
    addElements(graph.nodes, graph.edges);
    recount();              // show the count immediately, before the layout settles
    scheduleLayout(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, scanId]);

  // Live deltas: fold every not-yet-processed event frame's graph delta in.
  useEffect(() => {
    if (!cyRef.current) return;
    const fresh = state.events.filter(
      (f) => f.kind === "event" && f.seq > processedSeq.current && f.graph
    );
    if (fresh.length === 0) return;
    processedSeq.current = Math.max(processedSeq.current, ...state.events.map((f) => f.seq));
    let added = false;
    for (const f of fresh) {
      if (!f.graph) continue;
      const nodes = f.graph.nodes as unknown as GraphNode[];
      const edges = f.graph.edges as unknown as GraphEdge[];
      if (addElements(nodes, edges)) added = true;
    }
    if (added) {
      recount();            // keep the count live even if the layout is debounced
      scheduleLayout(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.lastSeq]);

  const total = useMemo(() => Object.values(counts).reduce((a, b) => a + b, 0), [counts]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Asset Map</h1>
          <p className="text-xs text-muted-foreground">
            Live entity graph — {total} nodes{graph?.scan ? ` · ${graph.scan.domain}` : ""}
            {truncated && <span className="text-warning"> · capped</span>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span
              className={cn(
                "h-2 w-2 rounded-full transition-colors",
                connected ? "bg-success text-success pulse-ring" : "bg-critical"
              )}
            />
            {connected ? "streaming" : "disconnected"}
          </div>
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

      {/* The canvas is ALWAYS mounted (even before a scan is picked) so the
          one-time Cytoscape init in the effect above always finds its container;
          hiding it behind a conditional left the ref null at mount and the map
          never rendered. Empty states are overlays on top of the live canvas. */}
      <div className="relative">
          <div
            ref={containerRef}
            className="h-[72vh] w-full rounded-lg border border-border bg-panel"
          />

          {/* Empty-state overlays */}
          {!scanId ? (
            <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
              <p className="text-sm text-muted-foreground">Select a scan to map.</p>
            </div>
          ) : total === 0 ? (
            <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
              <p className="text-sm text-muted-foreground">
                {graph ? "No mappable assets yet." : "Loading graph…"}
              </p>
            </div>
          ) : null}

          {/* Legend */}
          {total > 0 && (
          <div className="absolute left-3 top-3 flex animate-fade-in flex-col gap-1 rounded-md border border-border bg-background/80 p-2 text-[11px] backdrop-blur">
            {KIND_ORDER.filter((k) => counts[k]).map((k) => (
              <div key={k} className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[k] }} />
                <span className="text-muted-foreground">{k}</span>
                <span className="ml-auto tabular-nums text-foreground">{counts[k]}</span>
              </div>
            ))}
          </div>
          )}

          {/* Selected node */}
          {selected && (
            <div className="absolute right-3 top-3 w-72 animate-scale-in rounded-md border border-border bg-background/90 p-3 text-xs backdrop-blur">
              <div className="mb-1 flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[selected.kind] }} />
                <span className="font-mono text-foreground">{selected.kind}</span>
              </div>
              <div className="break-all font-mono text-foreground">{selected.label}</div>
              <dl className="mt-2 space-y-0.5 text-muted-foreground">
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
            </div>
          )}
        </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground/70">{k}</dt>
      <dd className="break-all text-foreground">{v}</dd>
    </div>
  );
}
