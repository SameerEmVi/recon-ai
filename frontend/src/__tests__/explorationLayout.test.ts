import { describe, expect, it } from "vitest";
import type { ExploreEdge, ExploreNode } from "@/lib/api";
import { COL_X, ROW_H, layoutExploration } from "@/lib/explorationLayout";

const n = (id: string, kind: ExploreNode["kind"], extra: Partial<ExploreNode> = {}): ExploreNode => ({
  id,
  kind,
  label: id,
  ...extra,
});
const e = (source: string, target: string, rel: ExploreEdge["rel"]): ExploreEdge => ({
  id: `${source}->${target}:${rel}`,
  source,
  target,
  rel,
});

const nodes: ExploreNode[] = [
  n("start", "start"),
  n("scope", "scope"),
  n("goal:osint", "goal", { step: 1 }),
  n("goal:recon", "goal", { step: 2 }),
  n("intent:subfinder", "intent", { order: 0 }),
  n("intent:ffuf", "intent", { order: 1 }),
  n("intent:dnsx", "intent", { order: 0 }),
  n("fact:subfinder:SUBDOMAIN", "fact", { count: 5 }),
  n("fact:subfinder:IP", "fact", { count: 1 }),
  n("vuln:1", "vulnerability", { priority: 8 }),
];
const edges: ExploreEdge[] = [
  e("start", "goal:osint", "spawns"),
  e("start", "goal:recon", "spawns"),
  e("goal:osint", "goal:recon", "next"),
  e("goal:osint", "intent:subfinder", "spawns"),
  e("goal:recon", "intent:dnsx", "spawns"),
  e("goal:recon", "intent:ffuf", "spawns"),
  e("intent:subfinder", "fact:subfinder:SUBDOMAIN", "yields"),
  e("intent:subfinder", "fact:subfinder:IP", "yields"),
  e("intent:subfinder", "vuln:1", "proves"),
  e("intent:subfinder", "intent:dnsx", "intent-chain"),
];

describe("layoutExploration", () => {
  it("puts each kind in its own left-to-right column", () => {
    const { positions } = layoutExploration(nodes, edges);
    for (const node of nodes) expect(positions.get(node.id)?.x).toBe(COL_X[node.kind]);
    expect(COL_X.start).toBeLessThan(COL_X.goal);
    expect(COL_X.goal).toBeLessThan(COL_X.intent);
    expect(COL_X.intent).toBeLessThan(COL_X.fact);
  });

  it("orders goals by step and centres each parent on its children", () => {
    const { positions } = layoutExploration(nodes, edges);
    const y = (id: string) => positions.get(id)!.y;
    expect(y("goal:osint")).toBeLessThan(y("goal:recon"));
    // subfinder has 3 leaves: vulnerability first, then facts by size.
    expect(y("vuln:1")).toBeLessThan(y("fact:subfinder:SUBDOMAIN"));
    expect(y("fact:subfinder:SUBDOMAIN")).toBeLessThan(y("fact:subfinder:IP"));
    expect(y("intent:subfinder")).toBe(y("fact:subfinder:SUBDOMAIN"));
    // Intents within a goal follow their processing order.
    expect(y("intent:dnsx")).toBeLessThan(y("intent:ffuf"));
    expect(y("intent:ffuf") - y("intent:dnsx")).toBe(ROW_H);
  });

  it("collapses a goal, hiding its members but keeping display ids stable", () => {
    const open = layoutExploration(nodes, edges);
    const shut = layoutExploration(nodes, edges, new Set(["goal:osint"]));
    expect(shut.visible.has("goal:osint")).toBe(true);
    expect(shut.visible.has("intent:subfinder")).toBe(false);
    expect(shut.visible.has("fact:subfinder:IP")).toBe(false);
    expect(shut.hiddenCount.get("goal:osint")).toBe(4);
    expect(shut.displayId.get("intent:dnsx")).toBe(open.displayId.get("intent:dnsx"));
    expect(open.displayId.get("start")).toBe("#root");
  });
});
