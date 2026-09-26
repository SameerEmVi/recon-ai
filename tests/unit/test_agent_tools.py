"""Regression tests for agent tools calling real wrapper APIs.

ProbeUrlTool used to call a non-existent HttpxWrapper.probe_urls() on a wrapper
built without a controller, so every probe_url action raised at runtime.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from agent.tools import ProbeUrlTool
from events.types import EventType
from recon.httpx_wrap import HttpxWrapper
from scope.engine import ScopeEngine
from scope.types import Scope

_LINE = json.dumps({"url": "https://api.example.com/", "status_code": 200, "title": "API"})


def _controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.scope_engine = ScopeEngine(Scope.from_strings(["*.example.com"]))
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    ctrl.bus.seen_count = 0
    return ctrl


async def test_probe_urls_publishes_http_service_events():
    ctrl = _controller()
    publish = AsyncMock(return_value=True)
    sid = uuid.uuid4()
    with patch.object(HttpxWrapper, "_run", AsyncMock(return_value=[_LINE])) as run:
        await HttpxWrapper(ctrl).probe_urls(["https://api.example.com/"], publish, sid)
    assert run.await_args.args[0][:2] == ["-target", "https://api.example.com/"]
    event = publish.await_args.args[0]
    assert event.type is EventType.HTTP_SERVICE
    assert event.scan_job_id == sid and event.source_event_id is None


async def test_probe_keeps_source_event_linkage():
    ctrl = _controller()
    source = MagicMock(id=uuid.uuid4(), scan_job_id=uuid.uuid4(), distance=2)
    with patch.object(HttpxWrapper, "_run", AsyncMock(return_value=[_LINE])):
        await HttpxWrapper(ctrl).probe("api.example.com", source)
    event = ctrl.stamp_and_publish.await_args.args[0]
    assert event.source_event_id == source.id and event.distance == 2


async def test_probe_url_tool_runs_without_error():
    ctrl = _controller()
    with patch.object(HttpxWrapper, "_run", AsyncMock(return_value=[_LINE])):
        result = await ProbeUrlTool(ctrl).run("https://api.example.com/", ctrl.scan_id)
    assert "scope denied" not in result.summary
    ctrl.stamp_and_publish.assert_awaited()


async def test_probe_url_tool_refuses_out_of_scope():
    ctrl = _controller()
    with patch.object(HttpxWrapper, "_run", AsyncMock()) as run:
        result = await ProbeUrlTool(ctrl).run("https://evil.example.org/", ctrl.scan_id)
    assert result.summary.startswith("scope denied")
    run.assert_not_awaited()
