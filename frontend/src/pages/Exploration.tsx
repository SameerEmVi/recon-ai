import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition } from "cytoscape";
import { listScans, getExploration } from "@/lib/api";
import type { ExploreKind, ExploreRel, ExploreNode, ExploreEdge } from "@/lib/api";
import { Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

// Node palette — one hue per reasoning stage.
const KIND_COLOR: Record<ExploreKind, string> = {
  start: "#a78bfa",         // violet — the origin
  goal: "#34d399",          // green — the objective
  intent: "#22d3ee",        // cyan — a tool/module acting
  fact: "#94a3b8",          // slate — a discovered fact
  vulnerability: "#f87171", // red — a proven weakness
};
// Live intent state recolours the intent node (like ARTEX's Running badge).
const STATE_COLOR: Record<string, string> = {
  RUNNING: "#38bdf8", VALIDATING: "#38bdf8", QUEUED: "#94a3b8", PAUSED: "#fb923c",
  FAILED: "#f87171", CANCELLED: "#f87171", PARTIAL: "#facc15",
  COMPLETED: "#34d399", OK: "#34d399",
};
// Severity recolours a vulnerability node.
const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f87171", medium: "#fbbf24", low: "#38bdf8", info: "#94a3b8",
};
// Edge palette by relationship (matches the legend).
const REL_COLOR: Record<ExploreRel, string> = {
  spawns: "#34d399",
  "intent-chain": "#818cf8",
  yields: "#f59e0b",
  proves: "#ef4444",
};

function nodeEl(n: ExploreNode): ElementDefinition {
  return { group: "nodes", data: { ...n } };
}
function edgeEl(e: ExploreEdge): ElementDefinition {
  return { group: "edges", data: { id: e.id, source: e.source, target: e.target, rel: e.rel } };
}

const cyStyle: cytoscape.Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": (el) => {
        const k = el.data("kind") as ExploreKind;
        if (k === "intent") return STATE_COLOR[el.data("state")] ?? KIND_COLOR.intent;
        if (k === "vulnerability") return SEV_COLOR[el.data("severity")] ?? KIND_COLOR.vulnerability;
        return KIND_COLOR[k] ?? "#64748b";
      },
      label: "data(label)",
      color: "#cbd5e1",
      "font-size": 8,
      "font-family": "ui-monospace, monospace",
      "text-valign": "center",
      "text-halign": "right",
      "text-margin-x": 4,
      "min-zoomed-font-size": 5,
      width: 12,
      height: 12,
    },
  },
  { selector: 'node[kind = "start"]', style: { width: 34, height: 34, "font-size": 13, "text-halign": "center", "text-valign": "bottom", "text-margin-y": 5, shape: "round-rectangle" } },
  { selector: 'node[kind = "goal"]', style: { width: 24, height: 24, "font-size": 11, shape: "round-rectangle" } },
  {
    selector: 'node[kind = "intent"]',
    style: {
      width: "mapData(count, 0, 2000, 16, 44)" as unknown as number,
      height: "mapData(count, 0, 2000, 16, 44)" as unknown as number,
      "font-size": 10,
    },
  },
  { selector: 'node[kind = "fact"]', style: { shape: "diamond", width: 13, height: 13 } },
  { selector: 'node[kind = "vulnerability"]', style: { shape: "triangle", width: 18, height: 18, "font-size": 10 } },
  {
    selector: "edge",
    style: {
      width: 1.2,
      "line-color": (el) => REL_COLOR[el.data("rel") as ExploreRel] ?? "#334155",
      "target-arrow-color": (el) => REL_COLOR[el.data("rel") as ExploreRel] ?? "#334155",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.7,
      "curve-style": "bezier",
      opacity: 0.6,
    },
  },
  { selector: ".faded", style: { opacity: 0.08 } },
];

export default function Exploration() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data } = useQuery({
    queryKey: ["exploration", scanId],
    queryFn: () => getExploration(scanId || undefined),
    enabled: !!scanId,
    refetchInterval: 4_000,       // live: the reasoning graph grows as the scan runs
  });

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<ExploreNode | null>(null);

  // Create the cytoscape instance once — container is ALWAYS mounted.
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({ container: containerRef.current, style: cyStyle, minZoom: 0.1, maxZoom: 3, wheelSensitivity: 0.2 });
    cy.on("tap", "node", (ev) => {
      setSelected(ev.target.data() as ExploreNode);
      cy.elements().addClass("faded");
      ev.target.closedNeighborhood().removeClass("faded");
    });
    cy.on("tap", (ev) => { if (ev.target === cy) { setSelected(null); cy.elements().removeClass("faded"); } });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, []);

  // Reload elements on new data and lay out as a left-to-right reasoning tree.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !data) return;
    cy.batch(() => {
      cy.elements().remove();
      cy.add(data.nodes.map(nodeEl));
      for (const e of data.edges) {
        if (!cy.getElementById(e.source).empty() && !cy.getElementById(e.target).empty()) cy.add(edgeEl(e));
      }
    });
    cy.resize();
    try {
      cy.layout({ name: "breadthfirst", directed: true, roots: ["start"], spacingFactor: 1.1,
        animate: false, fit: true, padding: 28 } as cytoscape.LayoutOptions).run();
    } catch {
      try { cy.layout({ name: "concentric", fit: true } as cytoscape.LayoutOptions).run(); } catch { /* ignore */ }
    }
  }, [data]);

  const summary = data?.summary;
  const streaming = (scans ?? []).find((s) => s.scan_id === scanId)?.status === "running";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            Exploration
            {streaming && (
              <span className="pulse-ring inline-block h-2 w-2 rounded-full bg-success" aria-label="live" />
            )}
          </h1>
          <p className="text-xs text-muted-foreground">
            How the scan reasoned through the target — objective → intents → facts → vulnerabilities
            {summary ? ` · ${summary.intents} intents · ${summary.facts} facts · ${summary.vulnerabilities} vulns` : ""}
            {data?.scan ? ` · ${data.scan.domain}` : ""}
          </p>
        </div>
        <Select value={scanId} onChange={(e) => setScanId(e.target.value)} className="w-64">
          <option value="">Select a scan…</option>
          {(scans ?? []).map((s) => (
            <option key={s.scan_id} value={s.scan_id}>{s.domain} · {s.status}</option>
          ))}
        </Select>
      </div>

      <div className="relative">
        <div ref={containerRef} className="h-[72vh] w-full rounded-lg border border-border bg-panel" />

        {(!scanId || (data && data.nodes.length <= 2)) && (
          <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
            <p className="text-sm text-muted-foreground">
              {!scanId ? "Select a scan to view its exploration graph." : "No exploration recorded yet — run a scan."}
            </p>
          </div>
        )}

        {/* Legend */}
        <div className="absolute left-3 top-3 flex animate-fade-in flex-col gap-1 rounded-md border border-border bg-background/80 p-2 text-[11px] backdrop-blur">
          <Dot color={KIND_COLOR.start} label="start" />
          <Dot color={KIND_COLOR.goal} label="goal" />
          <Dot color={KIND_COLOR.intent} label="intent (size = yield)" />
          <Dot color={KIND_COLOR.fact} label="fact" shape="diamond" />
          <Dot color={KIND_COLOR.vulnerability} label="vulnerability" shape="triangle" />
          <div className="mt-1 border-t border-border/50 pt-1 text-muted-foreground/70">edges:</div>
          <Line color={REL_COLOR.spawns} label="spawns" />
          <Line color={REL_COLOR["intent-chain"]} label="intent chain" />
          <Line color={REL_COLOR.yields} label="yields" />
          <Line color={REL_COLOR.proves} label="proves" />
        </div>

        {/* Selected node detail */}
        {selected && (
          <div className="absolute right-3 top-3 w-64 animate-scale-in rounded-md border border-border bg-background/90 p-3 text-xs backdrop-blur">
            <div className="mb-1 flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[selected.kind] }} />
              <span className="font-mono text-foreground">{selected.kind}</span>
            </div>
            <div className="break-all font-mono text-foreground">{selected.label}</div>
            <dl className="mt-2 space-y-0.5 text-muted-foreground">
              {selected.count != null && <Row k="events" v={String(selected.count)} />}
              {selected.hosts != null && <Row k="hosts" v={String(selected.hosts)} />}
              {selected.state && <Row k="state" v={selected.state} />}
              {selected.seed && <Row k="role" v="seed intent" />}
              {selected.etype && <Row k="event type" v={selected.etype} />}
              {selected.severity && <Row k="severity" v={selected.severity} />}
              {selected.category && <Row k="category" v={selected.category} />}
              {selected.host && <Row k="host" v={selected.host} />}
              {selected.mode && <Row k="mode" v={selected.mode} />}
              {selected.intents != null && <Row k="intents" v={String(selected.intents)} />}
              {selected.events != null && <Row k="total events" v={String(selected.events)} />}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}

function Dot({ color, label, shape }: { color: string; label: string; shape?: "diamond" | "triangle" }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn("h-2.5 w-2.5", shape === "diamond" ? "rotate-45" : shape === "triangle" ? "rounded-sm" : "rounded-full")}
        style={{ background: color }}
      />
      <span className="text-muted-foreground">{label}</span>
    </div>
  );
}
function Line({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-0.5 w-3 rounded-full" style={{ background: color }} />
      <span className="text-muted-foreground">{label}</span>
    </div>
  );
}
function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground/70">{k}</dt>
      <dd className={cn("break-all text-foreground")}>{v}</dd>
    </div>
  );
}
