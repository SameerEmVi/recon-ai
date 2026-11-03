import { describe, it, expect } from "vitest";
import { applyFrame, emptyLive, type LiveFrame } from "@/lib/live";

const ev = (seq: number, scan = "a"): LiveFrame => ({
  kind: "event", seq, scan_id: scan, type: "URL", label: "x", source: "katana",
});
const stat = (seq: number): LiveFrame => ({
  kind: "stats", seq, scan_id: "a",
  limiter: { requests: seq, penalty: 1, waf_vendors: [], targets_backed_off: [], targets_in_cooldown: [] },
});

describe("applyFrame", () => {
  it("appends events newest-first and tracks lastSeq", () => {
    let s = emptyLive();
    s = applyFrame(s, ev(1));
    s = applyFrame(s, ev(2));
    expect(s.events.map((e) => e.seq)).toEqual([2, 1]);
    expect(s.lastSeq).toBe(2);
  });

  it("dedupes frames already seen (replay overlap)", () => {
    let s = emptyLive();
    s = applyFrame(s, ev(5));
    const before = s;
    s = applyFrame(s, ev(5)); // same seq → ignored
    s = applyFrame(s, ev(3)); // older seq → ignored
    expect(s).toBe(before);
    expect(s.events).toHaveLength(1);
  });

  it("routes stats frames to state.stats, not the event list", () => {
    let s = emptyLive();
    s = applyFrame(s, stat(1));
    s = applyFrame(s, ev(2));
    expect(s.stats?.limiter?.requests).toBe(1);
    expect(s.events).toHaveLength(1);
    expect(s.lastSeq).toBe(2);
  });
});
