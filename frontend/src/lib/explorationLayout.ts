// Left-to-right layout for the exploration graph.
//
// Columns are fixed by node kind so the plan always reads the same way:
//
//   start / scope  │  goals  │  intents  │  facts / vulnerabilities
//
// Within the tree each parent is centred on its children, goals are stacked in
// processing order (step 1, 2, 3) and intents in the order they started, so the
// eye walks the scan top-to-bottom, left-to-right. Only the structural edges
// (spawns / yields / proves) shape the tree; next / constrains / intent-chain are
// overlays drawn on top.
import type { ExploreEdge, ExploreKind, ExploreNode } from "@/lib/api";

export const CARD_W = 260;
export const COL_X: Record<ExploreKind, number> = {
  start: 0,
  scope: 0,
  goal: 340,
  intent: 680,
  fact: 1020,
  vulnerability: 1020,
};
export const ROW_H = 128;
const GOAL_GAP = 56;

export interface LaidOut {
  positions: Map<string, { x: number; y: number }>;
  /** Node ids that are rendered (members of collapsed goals are hidden). */
  visible: Set<string>;
  /** Short ARTEX-style display ids: #root, #g1, #i3, #f2, #v1. */
  displayId: Map<string, string>;
  /** Intents + leaves hidden under each collapsed goal (for the goal card). */
  hiddenCount: Map<string, number>;
}

const TREE_RELS = new Set(["spawns", "yields", "proves"]);

export function layoutExploration(
  nodes: ExploreNode[],
  edges: ExploreEdge[],
  collapsed: ReadonlySet<string> = new Set(),
): LaidOut {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const children = new Map<string, string[]>();
  for (const e of edges) {
    if (!TREE_RELS.has(e.rel) || !byId.has(e.source) || !byId.has(e.target)) continue;
    const list = children.get(e.source);
    if (list) list.push(e.target);
    else children.set(e.source, [e.target]);
  }
  const kids = (id: string) => (children.get(id) ?? []).map((c) => byId.get(c)!).filter(Boolean);

  const goals = nodes
    .filter((n) => n.kind === "goal")
    .sort((a, b) => (a.step ?? 0) - (b.step ?? 0));

  // Leaves of an intent (or vulnerabilities hung directly off a goal):
  // vulnerabilities first (highest priority), then facts (largest first).
  const leafOrder = (a: ExploreNode, b: ExploreNode) =>
    (a.kind === "vulnerability" ? 0 : 1) - (b.kind === "vulnerability" ? 0 : 1) ||
    (b.priority ?? 0) - (a.priority ?? 0) ||
    (b.count ?? 0) - (a.count ?? 0) ||
    a.label.localeCompare(b.label);

  const positions = new Map<string, { x: number; y: number }>();
  const visible = new Set<string>();
  const displayId = new Map<string, string>();
  const hiddenCount = new Map<string, number>();
  const seq = { g: 0, i: 0, f: 0, v: 0 };
  const tag = (n: ExploreNode) => {
    if (displayId.has(n.id)) return;
    const k = n.kind === "goal" ? "g" : n.kind === "intent" ? "i" : n.kind === "fact" ? "f" : "v";
    seq[k] += 1;
    displayId.set(n.id, `#${k}${seq[k]}`);
  };
  const place = (n: ExploreNode, y: number) => {
    positions.set(n.id, { x: COL_X[n.kind], y });
    visible.add(n.id);
  };

  let cursor = 0;
  const goalYs: number[] = [];
  for (const goal of goals) {
    tag(goal);
    const direct = kids(goal.id);
    const intents = direct
      .filter((n) => n.kind === "intent")
      .sort((a, b) => (a.order ?? 0) - (b.order ?? 0) || a.label.localeCompare(b.label));
    const goalLeaves = direct.filter((n) => n.kind !== "intent").sort(leafOrder);

    if (collapsed.has(goal.id)) {
      let hidden = goalLeaves.length + intents.length;
      for (const it of intents) hidden += kids(it.id).length;
      hiddenCount.set(goal.id, hidden);
      // Still number the hidden members so ids stay stable when expanding.
      for (const it of intents) {
        tag(it);
        kids(it.id).sort(leafOrder).forEach(tag);
      }
      goalLeaves.forEach(tag);
      place(goal, cursor);
      goalYs.push(cursor);
      cursor += ROW_H + GOAL_GAP;
      continue;
    }

    const blockTop = cursor;
    // Vulnerabilities with no proving intent sit at the top of their goal's block.
    for (const leaf of goalLeaves) {
      tag(leaf);
      place(leaf, cursor);
      cursor += ROW_H;
    }
    for (const it of intents) {
      tag(it);
      const leaves = kids(it.id).sort(leafOrder);
      const top = cursor;
      for (const leaf of leaves) {
        tag(leaf);
        place(leaf, cursor);
        cursor += ROW_H;
      }
      if (!leaves.length) cursor += ROW_H;
      place(it, top + ((Math.max(1, leaves.length) - 1) * ROW_H) / 2);
    }
    if (cursor === blockTop) cursor += ROW_H;          // empty goal still gets a row
    const gy = blockTop + (cursor - blockTop - ROW_H) / 2;
    place(goal, gy);
    goalYs.push(gy);
    cursor += GOAL_GAP;
  }

  // Start lines up with the first goal (where the plan begins); scope sits just
  // beneath it. Centring on a tall plan would park it far from step 1.
  const top = goalYs.length ? goalYs[0] : 0;
  for (const n of nodes) {
    if (n.kind === "start") {
      displayId.set(n.id, "#root");
      place(n, top);
    } else if (n.kind === "scope") {
      displayId.set(n.id, "#scope");
      place(n, top + ROW_H + 24);
    }
  }
  return { positions, visible, displayId, hiddenCount };
}
