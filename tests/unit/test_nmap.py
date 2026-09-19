"""nmap wrapper + module tests (XML parsing, event emission, arg-injection guard)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from events.types import EventType, OpenPortData
from modules.registry import ModuleRegistry
from recon.nmap import NmapWrapper


def _mock_controller():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.4p1" extrainfo="protocol 2.0">
    <cpe>cpe:/a:openbsd:openssh:8.4p1</cpe></service></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
</ports></host></nmaprun>"""


def test_parse_xml_open_only_with_version():
    svcs = NmapWrapper._parse_xml(_XML)
    assert len(svcs) == 1
    s = svcs[0]
    assert s.port == 22 and s.service == "ssh"
    assert s.product == "OpenSSH" and s.version == "8.4p1"
    assert s.banner == "OpenSSH 8.4p1 (protocol 2.0)"
    assert s.cpe == ["cpe:/a:openbsd:openssh:8.4p1"]


def test_parse_xml_empty_and_garbage():
    assert NmapWrapper._parse_xml("") == []
    assert NmapWrapper._parse_xml("<not-xml") == []


async def test_wrapper_refuses_flag_like_target():
    # Arg-injection guard: a target starting with '-' must never reach nmap.
    w = NmapWrapper()
    assert await w.scan("-oN/tmp/x", "22") == []


async def test_module_emits_technology(monkeypatch):
    ModuleRegistry.discover()
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["nmap"], controller=ctrl)[0]

    event = MagicMock()
    event.data = OpenPortData(host="51.158.147.132", port=22, protocol="tcp")
    event.id = uuid.uuid4()
    event.distance = 2

    from recon.nmap import NmapService
    fake_scan = AsyncMock(return_value=[
        NmapService(port=22, protocol="tcp", state="open",
                    service="ssh", product="OpenSSH", version="8.4p1"),
    ])
    monkeypatch.setattr("recon.nmap.NmapWrapper.scan", fake_scan)

    await m.handle_event(event)

    assert ctrl.stamp_and_publish.called
    tech = ctrl.stamp_and_publish.call_args_list[0][0][0]
    assert tech.type is EventType.TECHNOLOGY
    assert tech.data.name == "OpenSSH"
    assert tech.data.version == "8.4p1"
    assert tech.data.category == "service"
