"""
Increment 5 — live monitor (WebSocket) tests.

LiveHub buffering/replay + filtering, start_live_monitor streaming bus events and
sampler stats, and the WebSocket auth gate (bad token is closed before accept).
"""

from __future__ import annotations

import asyncio
import types

import pytest

from api.ws import LiveHub, start_live_monitor


async def test_hub_assigns_seq_and_replays_since():
    hub = LiveHub()
    await hub.publish({"kind": "event", "scan_id": "a", "type": "SUBDOMAIN"})
    await hub.publish({"kind": "event", "scan_id": "b", "type": "URL"})
    await hub.publish({"kind": "stats", "scan_id": "a"})
    seqs = [f["seq"] for f in hub.replay(0, None)]
    assert seqs == [1, 2, 3]                                   # monotonic
    assert all("ts" in f for f in hub.replay(0, None))
    # replay cursor + scan filter
    assert [f["seq"] for f in hub.replay(1, None)] == [2, 3]
    assert [f["scan_id"] for f in hub.replay(0, "a")] == ["a", "a"]


async def test_client_offer_respects_scan_filter():
    hub = LiveHub()
    from api.ws import _Client
    c = _Client(scan_id="a")
    hub.add(c)
    await hub.publish({"kind": "event", "scan_id": "a"})
    await hub.publish({"kind": "event", "scan_id": "b"})     # filtered out for this client
    got = [c.queue.get_nowait()]
    assert c.queue.empty()
    assert got[0]["scan_id"] == "a"


class _FakeLimiter:
    def stats(self):
        return {"requests": 3, "penalty": 1.0, "waf_vendors": [], "targets_backed_off": [],
                "targets_in_cooldown": []}


async def test_live_monitor_streams_events_and_stats():
    from events.types import Event, EventType, SubdomainData
    from events.bus import EventBus
    from scope.types import ScopeStatus
    import uuid

    hub = LiveHub()
    controller = types.SimpleNamespace(
        bus=EventBus(), rate_limiter=_FakeLimiter(), live_pool_stats=None,
    )
    task = start_live_monitor(hub, controller, "scan-x")
    try:
        ev = Event.create(EventType.SUBDOMAIN, SubdomainData(hostname="a.ex.com", source="t"),
                          scan_job_id=uuid.uuid4(), source_tool="subfinder")
        ev.scope_status = ScopeStatus.IN
        await controller.bus.publish(ev)
        await controller.bus.drain()
        await asyncio.sleep(0.05)                              # let the sampler emit ≥1 stats frame
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    frames = hub.replay(0, "scan-x")
    kinds = {f["kind"] for f in frames}
    assert "event" in kinds and "stats" in kinds
    ev_frame = next(f for f in frames if f["kind"] == "event")
    assert ev_frame["type"] == "SUBDOMAIN" and ev_frame["source"] == "subfinder"
    stat_frame = next(f for f in frames if f["kind"] == "stats")
    assert stat_frame["limiter"]["requests"] == 3


def test_ws_rejects_bad_token():
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    from api.app import create_app
    from api.config import Settings

    app = create_app(Settings(token="good", db_url=None))
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live?token=bad"):
            pass


def test_ws_accepts_valid_token_and_replays_buffer():
    import asyncio as _asyncio
    from starlette.testclient import TestClient
    from api.app import create_app
    from api.config import Settings

    app = create_app(Settings(token="good", db_url=None))
    # Seed a frame so the reconnect replay (since=0) has something to deliver.
    _asyncio.run(app.state.hub.publish(
        {"kind": "event", "scan_id": "s1", "type": "SUBDOMAIN", "label": "a.ex.com"}))
    with TestClient(app).websocket_connect("/ws/live?token=good&since=0") as ws:
        frame = ws.receive_json()
    assert frame["type"] == "SUBDOMAIN" and frame["seq"] == 1
