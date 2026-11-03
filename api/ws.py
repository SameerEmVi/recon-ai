"""
Live monitor over WebSocket.

A LiveHub holds a bounded ring buffer of recent frames (each with a monotonic
`seq`) and fans them to connected clients. A reconnecting browser passes
`?since=<lastSeq>` and the hub replays buffered frames after that seq, then
streams live — so missed updates are recovered. A disconnected/slow client is
dropped without ever touching scan execution (its send queue is bounded and
non-blocking).

Frames are produced per scan by `start_live_monitor`:
  * `event`  — every scope-stamped bus event (the live discovery stream), by
    subscribing a read-only handler to the controller's EventBus.
  * `stats`  — a 1 Hz sample of the shared RateLimiter (requests, WAF backoff,
    cooldowns) and, for a hybrid run, the live worker-pool counters.
  * `lifecycle` — scan started / completed / failed / cancelled.

Everything here is read-only w.r.t. the engine: it observes, it never drives.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from datetime import datetime, timezone

from starlette.websockets import WebSocket

log = logging.getLogger("api.ws")

_BUFFER = 2000          # frames retained for reconnect replay
_CLIENT_QUEUE = 1000    # per-client backpressure bound


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _Client:
    __slots__ = ("queue", "scan_id")

    def __init__(self, scan_id: str | None) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=_CLIENT_QUEUE)
        self.scan_id = scan_id

    def offer(self, frame: dict) -> None:
        if self.scan_id and frame.get("scan_id") != self.scan_id:
            return
        try:
            self.queue.put_nowait(frame)
        except asyncio.QueueFull:
            # Drop for this slow client; the seq gap is visible to the frontend,
            # which can refetch via REST. Never block the publisher.
            pass


class LiveHub:
    def __init__(self, maxlen: int = _BUFFER) -> None:
        self._buf: deque[dict] = deque(maxlen=maxlen)
        self._seq = 0
        self._clients: set[_Client] = set()

    async def publish(self, frame: dict) -> None:
        self._seq += 1
        frame = {**frame, "seq": self._seq, "ts": frame.get("ts") or _now()}
        self._buf.append(frame)
        for c in list(self._clients):
            c.offer(frame)

    def replay(self, since: int, scan_id: str | None) -> list[dict]:
        return [
            f for f in self._buf
            if f["seq"] > since and (not scan_id or f.get("scan_id") == scan_id)
        ]

    def add(self, client: _Client) -> None:
        self._clients.add(client)

    def remove(self, client: _Client) -> None:
        self._clients.discard(client)


def start_live_monitor(hub: LiveHub, controller, scan_id: str) -> asyncio.Task:
    """Subscribe a bus observer + start a 1 Hz stats sampler. Returns the sampler
    task (the caller cancels it when the scan ends)."""
    from events.types import EventType

    async def on_event(ev) -> None:
        await hub.publish({
            "kind": "event", "scan_id": scan_id,
            "type": getattr(ev.type, "value", str(ev.type)),
            "label": getattr(ev, "dedup_key", ""),
            "source": getattr(ev, "source_tool", ""),
            "distance": getattr(ev, "distance", 0),
        })

    try:
        for et in EventType:
            controller.bus.subscribe(et, on_event)
    except Exception as exc:                       # observation must never break a scan
        log.debug("live monitor subscribe failed: %s", exc)

    async def sampler() -> None:
        try:
            while True:
                frame: dict = {"kind": "stats", "scan_id": scan_id}
                lim = getattr(controller, "rate_limiter", None)
                if lim is not None and hasattr(lim, "stats"):
                    with contextlib.suppress(Exception):
                        frame["limiter"] = lim.stats()
                with contextlib.suppress(Exception):
                    pool = controller.live_pool_stats
                    if pool is not None:
                        frame["pool"] = pool
                await hub.publish(frame)
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            raise

    return asyncio.create_task(sampler(), name=f"live-{scan_id}")


async def live_ws(websocket: "WebSocket") -> None:
    """WebSocket endpoint handler. Auth via ?token=; optional ?scan_id= filter and
    ?since= replay cursor."""
    from api.auth import websocket_token_ok

    app = websocket.app
    settings = app.state.settings
    hub: LiveHub = app.state.hub

    try:
        token = websocket.query_params.get("token")
        authorized = websocket_token_ok(settings.token, token)
    except Exception as exc:                      # surface, don't silently 403
        log.warning("ws pre-accept error: %r", exc)
        await websocket.close(code=1011)
        return
    if not authorized:
        await websocket.close(code=4401)          # policy violation (unauthorized)
        return

    scan_id = websocket.query_params.get("scan_id")
    try:
        since = int(websocket.query_params.get("since", "0"))
    except ValueError:
        since = 0

    await websocket.accept()
    client = _Client(scan_id)
    hub.add(client)
    try:
        # Replay buffered frames first (deduped client-side by seq), then live.
        for frame in hub.replay(since, scan_id):
            await websocket.send_json(frame)
        while True:
            frame = await client.queue.get()
            await websocket.send_json(frame)
    except Exception:
        # Any disconnect/send error: drop the client. Scan execution is untouched.
        pass
    finally:
        hub.remove(client)
