"""
paramfinder module tests — the PARAMETER event producer.

Covers:
  - query-string params extracted from URL events
  - parameter names extracted from ENDPOINT events
  - dedup within a single event (repeated keys emitted once)
  - sample_value sanitized/capped by ParameterData
  - registration + membership in the DISCOVERY group
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from events.types import EndpointData, EventType, ParameterData, UrlData
from modules.registry import DISCOVERY_MODULES, FULL_MODULES, ModuleRegistry


def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


def _url_event(url: str):
    ev = MagicMock()
    ev.type = EventType.URL
    ev.data = UrlData(url=url)
    ev.id = uuid.uuid4()
    ev.distance = 1
    return ev


def _endpoint_event(url: str, parameters: list[str]):
    ev = MagicMock()
    ev.type = EventType.ENDPOINT
    ev.data = EndpointData(url=url, method="GET", parameters=parameters)
    ev.id = uuid.uuid4()
    ev.distance = 1
    return ev


def _emitted_params(ctrl) -> list[ParameterData]:
    return [
        c[0][0].data
        for c in ctrl.stamp_and_publish.call_args_list
        if c[0][0].type == EventType.PARAMETER
    ]


async def test_extracts_query_params_from_url():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["paramfinder"], controller=ctrl)[0]

    await m.handle_event(_url_event("https://api.example.com/search?q=test&page=2"))

    params = _emitted_params(ctrl)
    names = {p.name for p in params}
    assert names == {"q", "page"}
    assert all(p.location == "query" for p in params)
    q = next(p for p in params if p.name == "q")
    assert q.sample_value == "test"


async def test_extracts_names_from_endpoint():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["paramfinder"], controller=ctrl)[0]

    await m.handle_event(
        _endpoint_event("https://example.com/api/user", ["id", "token"])
    )

    names = {p.name for p in _emitted_params(ctrl)}
    assert names == {"id", "token"}


async def test_no_params_no_emit():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["paramfinder"], controller=ctrl)[0]

    await m.handle_event(_url_event("https://example.com/about"))

    assert _emitted_params(ctrl) == []


async def test_dedup_repeated_key_within_event():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["paramfinder"], controller=ctrl)[0]

    await m.handle_event(_url_event("https://example.com/?a=1&a=2&b=3"))

    names = [p.name for p in _emitted_params(ctrl)]
    assert sorted(names) == ["a", "b"]  # 'a' emitted once


async def test_sample_value_is_capped():
    # ParameterData must sanitize/cap the target-controlled sample value.
    long_val = "x" * 5000
    pd = ParameterData(url="https://e.com/?p=1", name="p", location="query",
                        sample_value=long_val)
    assert pd.sample_value is not None
    assert len(pd.sample_value) <= 256


async def test_registered_and_in_discovery_group():
    assert "paramfinder" in DISCOVERY_MODULES
    assert "paramfinder" in FULL_MODULES
    m = ModuleRegistry.load(names=["paramfinder"], controller=_mock_controller())[0]
    assert m.name == "paramfinder"
    assert "PARAMETER" in m.produced_events
    assert set(m.watched_events) == {"URL", "ENDPOINT"}
