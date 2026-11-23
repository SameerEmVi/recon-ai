import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition } from "cytoscape";
import { listScans, getExecMap } from "@/lib/api";
import type { ExecKind, ExecNode, ExecEdge } from "@/lib/api";
import { Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";

const KIND_COLOR: Record<ExecKind, string> = {
  scan: "#a78bfa",
  tool: "#22d3ee",
  etype: "#64748b",
};
const STATE_COLOR: Record<string, string> = {
  RUNNING: "#38bdf8", COMPLETED: "#34d399", OK: "#34d399",
  FAILED: "#f87171", CANCELLED: "#f87171", PARTIAL: "#facc15",
  QUEUED: "#94a3b8", PAUSED: "#fb923c", VALIDATING: "#38bdf8",
};

function nodeEl(n: ExecNode): ElementDefinition {
  return { group: "nodes", data: { ...n } };
}
function edgeEl(e: ExecEdge): ElementDefinition {
  return { group: "edges", data: { id: e.id, source: e.source, target: e.target } };
}

const cyStyle: cytoscape.Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": (el) => {
        const k = el.data("kind") as ExecKind;
        if (k === "tool") return STATE_COLOR[el.data("state")] ?? KIND_COLOR.tool;
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
      width: 10,
      height: 10,
    },
  },
  { selector: 'node[kind = "scan"]', style: { width: 30, height: 30, "font-size": 12, "text-halign": "center", "text-valign": "bottom", "text-margin-y": 4 } },
  {
    selector: 'node[kind = "tool"]',
    style: {
      width: "mapData(count, 0, 2500, 16, 46)" as unknown as number,
      height: "mapData(count, 0, 2500, 16, 46)" as unknown as number,
      "font-size": 10,
    },
  },
  {
    selector: "edge",
    style: { width: 1, "line-color": "#334155", "curve-style": "bezier", "target-arrow-shape": "none", opacity: 0.55 },
  },
  { selector: ".faded", style: { opacity: 0.1 } },
];

export default function ToolMap() {
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: listScans, refetchInterval: 5_000 });
  const [scanId, setScanId] = useState<string>("");

  useEffect(() => {
    if (scanId || !scans?.length) return;
    const running = scans.find((s) => s.status === "running");
    setScanId((running ?? scans[0]).scan_id);
  }, [scans, scanId]);

  const { data } = useQuery({
    queryKey: ["execmap", scanId],
    queryFn: () => getExecMap(scanId || undefined),
    enabled: !!scanId,
    refetchInterval: 5_000,       // live: tool yields grow as the scan runs
  });

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<ExecNode | null>(null);

  // Create the instance once — container is ALWAYS mounted (see Asset Map fix).
  useEffect(() => {
    if (!containerRef.current || cyRef.current) return;
    const cy = cytoscape({ container: containerRef.current, style: cyStyle, minZoom: 0.1, maxZoom: 3, wheelSensitivity: 0.2 });
    cy.on("tap", "node", (ev) => {
      setSelected(ev.target.data() as ExecNode);
      cy.elements().addClass("faded");
      ev.target.closedNeighborhood().removeClass("faded");
    });
    cy.on("tap", (ev) => { if (ev.target === cy) { setSelected(null); cy.elements().removeClass("faded"); } });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, []);

  // Reload elements on new data and lay out as a radial mindmap.
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
      cy.layout({ name: "breadthfirst", directed: true, roots: ["scan"], spacingFactor: 1.15,
        animate: false, fit: true, padding: 24 } as cytoscape.LayoutOptions).run();
    } catch {
      try { cy.layout({ name: "concentric", fit: true } as cytoscape.LayoutOptions).run(); } catch { /* ignore */ }
    }
  }, [data]);

  const summary = data?.summary;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Tool Execution</h1>
          <p className="text-xs text-muted-foreground">
            Every tool that ran, and what it produced
            {summary ? ` · ${summary.tools} tools · ${summary.events} events` : ""}
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

        {(!scanId || (data && data.nodes.length <= 1)) && (
          <div className="absolute inset-0 flex animate-fade-in items-center justify-center">
            <p className="text-sm text-muted-foreground">
              {!scanId ? "Select a scan to view its tool executions." : "No tool executions recorded yet."}
            </p>
          </div>
        )}

        {/* Legend */}
        <div className="absolute left-3 top-3 flex animate-fade-in flex-col gap-1 rounded-md border border-border bg-background/80 p-2 text-[11px] backdrop-blur">
          <LegendRow color={KIND_COLOR.scan} label="scan" />
          <LegendRow color={KIND_COLOR.tool} label="tool (size = yield)" />
          <LegendRow color={KIND_COLOR.etype} label="event type" />
          <div className="mt-1 border-t border-border/50 pt-1 text-muted-foreground/70">state:</div>
          <LegendRow color={STATE_COLOR.RUNNING} label="running" />
          <LegendRow color={STATE_COLOR.COMPLETED} label="completed" />
          <LegendRow color={STATE_COLOR.FAILED} label="failed" />
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
              {selected.tools != null && <Row k="tools" v={String(selected.tools)} />}
              {selected.events != null && <Row k="total events" v={String(selected.events)} />}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}

function LegendRow({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
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
