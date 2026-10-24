"""naabu module tests — command construction, scan-type, arg-injection guard."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from events.types import EventType, IpData
from modules.registry import ModuleRegistry


def _load(config=None):
    from ratelimit import NOOP
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.rate_limiter = NOOP
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    ModuleRegistry.discover()
    cfg = {"naabu": config} if config else None
    return ModuleRegistry.load(names=["naabu"], controller=ctrl, module_config=cfg)[0]


def test_default_scan_type_is_connect():
    m = _load()
    assert m._scan_flag() == "c"


def test_syn_scan_type_maps_to_s():
    assert _load({"scan_type": "syn"})._scan_flag() == "s"
    assert _load({"scan_type": "s"})._scan_flag() == "s"


def test_unknown_scan_type_defaults_to_connect():
    assert _load({"scan_type": "bogus"})._scan_flag() == "c"


@pytest.mark.parametrize("spec,expected", [
    ("top-1000", ["-top-ports", "1000"]),
    ("top-100", ["-top-ports", "100"]),
    ("full", ["-p", "-"]),
    ("80,443,8080", ["-p", "80,443,8080"]),
])
def test_port_flags(spec, expected):
    assert _load({"ports": spec})._port_flags() == expected


async def test_refuses_flag_like_target():
    m = _load()
    ev = MagicMock()
    ev.data = IpData(address="-oN")   # would parse as a naabu flag
    ev.id = uuid.uuid4()
    ev.distance = 2
    # Should return without emitting / scanning.
    await m.handle_event(ev)
    m._ctrl.stamp_and_publish.assert_not_awaited()


def test_naabu_has_high_expected_value():
    # Regression: port discovery must not be planner-skipped by default.
    from planner import VALUE_HIGH
    assert ModuleRegistry.get("naabu").expected_value == VALUE_HIGH
