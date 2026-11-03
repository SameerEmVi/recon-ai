import { useEffect, useRef, useState } from "react";
import { getToken } from "./auth";

export interface LiveFrame {
  kind: "event" | "stats" | "lifecycle";
  seq: number;
  scan_id?: string;
  ts?: string;
  // event
  type?: string;
  label?: string;
  source?: string;
  // lifecycle
  event?: string;
  domain?: string;
  // stats
  limiter?: {
    requests: number;
    penalty: number;
    waf_vendors: string[];
    targets_backed_off: string[];
    targets_in_cooldown: string[];
  };
  pool?: {
    max_workers: number;
    accepted: number;
    deduped: number;
    queued: number;
    running: number;
    terminal: Record<string, number>;
  };
}

export interface LiveState {
  events: LiveFrame[]; // event + lifecycle frames, newest first (capped)
  stats: LiveFrame | null;
  lastSeq: number;
}

export const emptyLive = (): LiveState => ({ events: [], stats: null, lastSeq: 0 });

const MAX_EVENTS = 500;

/** Pure reducer: fold one frame into state, deduping by seq. Exported for tests. */
export function applyFrame(state: LiveState, frame: LiveFrame): LiveState {
  if (frame.seq <= state.lastSeq) return state; // already seen (replay overlap)
  const lastSeq = frame.seq;
  if (frame.kind === "stats") {
    return { ...state, stats: frame, lastSeq };
  }
  return { ...state, events: [frame, ...state.events].slice(0, MAX_EVENTS), lastSeq };
}

function wsUrl(scanId: string | undefined, since: number): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const params = new URLSearchParams();
  const token = getToken();
  if (token) params.set("token", token);
  if (scanId) params.set("scan_id", scanId);
  if (since) params.set("since", String(since));
  return `${proto}://${location.host}/ws/live?${params.toString()}`;
}

/** Subscribe to the live monitor for a scan, with auto-reconnect that resumes
 * from the last seen seq (server replays the gap). */
export function useLiveSocket(scanId: string | undefined) {
  const [state, setState] = useState<LiveState>(emptyLive);
  const [connected, setConnected] = useState(false);
  const seqRef = useRef(0);
  const stateRef = useRef<LiveState>(state);
  stateRef.current = state;

  useEffect(() => {
    // Reset view when the selected scan changes.
    setState(emptyLive());
    seqRef.current = 0;
    if (!scanId) return;

    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl(scanId, seqRef.current));
      } catch {
        schedule();
        return;
      }
      ws.onopen = () => setConnected(true);
      ws.onmessage = (m) => {
        try {
          const frame = JSON.parse(m.data) as LiveFrame;
          seqRef.current = Math.max(seqRef.current, frame.seq);
          setState((s) => applyFrame(s, frame));
        } catch {
          /* ignore malformed frame */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        schedule();
      };
      ws.onerror = () => ws?.close();
    };

    const schedule = () => {
      if (closed || retry) return;
      retry = setTimeout(() => {
        retry = null;
        connect();
      }, 1500);
    };

    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, [scanId]);

  return { state, connected };
}
