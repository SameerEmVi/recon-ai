"""
BBOT wrapper tests — mock-based, bbot library not required.

We mock the bbot.scanner.Scanner import and fake BBOT event objects
so the translation logic can be tested without BBOT installed.

Tests cover:
  - _translate() for every BBOT event type we handle
  - Graceful handling of malformed / missing data
  - _try_import_bbot() returns None when bbot not installed
  - BBOTWrapper.run() calls stamp_and_publish for accepted events
  - BBOTWrapper.run() skips gracefully when bbot is not installed
"""

from __future__ import annotations

import sys
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from recon.bbot_wrap import _translate, BBOTWrapper, DEFAULT_MODULES

SCAN_ID = uuid.uuid4()


# ── fake BBOT event builder ───────────────────────────────────────────────────

def _bbot_event(etype: str, data, parent_type: str = "", parent_data=None) -> object:
    parent = None
    if parent_type:
        parent = SimpleNamespace(type=parent_type, data=parent_data or "", host=parent_data)
    return SimpleNamespace(type=etype, data=data, parent=parent, host=None)


# ── _translate: DNS_NAME ──────────────────────────────────────────────────────

def test_translate_dns_name():
    e = _bbot_event("DNS_NAME", "api.Example.COM.")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "SUBDOMAIN"
    assert result.data.hostname == "api.example.com"  # lowercased, dot stripped
    assert result.data.source == "bbot"


def test_translate_dns_name_empty_returns_none():
    e = _bbot_event("DNS_NAME", "")
    assert _translate(e, SCAN_ID) is None


# ── _translate: IP_ADDRESS ────────────────────────────────────────────────────

def test_translate_ip_address():
    e = _bbot_event("IP_ADDRESS", "1.2.3.4")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "IP"
    assert result.data.address == "1.2.3.4"
    assert result.data.resolved_from is None


def test_translate_ip_address_with_dns_parent():
    e = _bbot_event("IP_ADDRESS", "1.2.3.4", parent_type="DNS_NAME", parent_data="api.example.com")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.data.resolved_from == "api.example.com"


# ── _translate: OPEN_TCP_PORT ─────────────────────────────────────────────────

def test_translate_open_tcp_port():
    e = _bbot_event("OPEN_TCP_PORT", "api.example.com:443")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "OPEN_PORT"
    assert result.data.host == "api.example.com"
    assert result.data.port == 443
    assert result.data.protocol == "tcp"


def test_translate_open_tcp_port_ipv4():
    e = _bbot_event("OPEN_TCP_PORT", "1.2.3.4:80")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.data.host == "1.2.3.4"
    assert result.data.port == 80


def test_translate_open_tcp_port_ipv6():
    e = _bbot_event("OPEN_TCP_PORT", "[::1]:8080")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.data.host == "::1"
    assert result.data.port == 8080


def test_translate_open_tcp_port_bad_data_returns_none():
    e = _bbot_event("OPEN_TCP_PORT", "no-port-here")
    assert _translate(e, SCAN_ID) is None


def test_translate_open_tcp_port_nonnumeric_port_returns_none():
    e = _bbot_event("OPEN_TCP_PORT", "host:notaport")
    assert _translate(e, SCAN_ID) is None


# ── _translate: URL ───────────────────────────────────────────────────────────

def test_translate_url():
    e = _bbot_event("URL", "https://api.example.com/v1/users")
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "URL"
    assert result.data.url == "https://api.example.com/v1/users"
    assert result.data.found_via == "bbot"


def test_translate_url_non_http_returns_none():
    e = _bbot_event("URL", "ftp://files.example.com/data")
    assert _translate(e, SCAN_ID) is None


# ── _translate: HTTP_RESPONSE ─────────────────────────────────────────────────

def test_translate_http_response():
    data = {"url": "https://api.example.com/", "status_code": 200, "title": "Home"}
    e = _bbot_event("HTTP_RESPONSE", data)
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "HTTP_SERVICE"
    assert result.data.url == "https://api.example.com/"
    assert result.data.status_code == 200
    assert result.data.title == "Home"


def test_translate_http_response_hyphen_key():
    # BBOT uses status-code (with hyphen) in some versions
    data = {"url": "https://api.example.com/", "status-code": 404}
    e = _bbot_event("HTTP_RESPONSE", data)
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.data.status_code == 404


def test_translate_http_response_missing_url_returns_none():
    data = {"status_code": 200}
    e = _bbot_event("HTTP_RESPONSE", data)
    assert _translate(e, SCAN_ID) is None


def test_translate_http_response_non_dict_returns_none():
    e = _bbot_event("HTTP_RESPONSE", "not-a-dict")
    assert _translate(e, SCAN_ID) is None


# ── _translate: TECHNOLOGY ────────────────────────────────────────────────────

def test_translate_technology_dict():
    data = {"technology": "nginx", "version": "1.24", "host": "api.example.com"}
    e = _bbot_event("TECHNOLOGY", data)
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "TECHNOLOGY"
    assert result.data.name == "nginx"
    assert result.data.version == "1.24"
    assert result.data.host == "api.example.com"


def test_translate_technology_host_from_parent():
    data = {"technology": "PHP", "version": "8.1"}
    parent = SimpleNamespace(type="HTTP_RESPONSE", data={}, host="api.example.com")
    e = SimpleNamespace(type="TECHNOLOGY", data=data, parent=parent, host=None)
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.data.host == "api.example.com"
    assert result.data.name == "PHP"


def test_translate_technology_no_host_returns_none():
    data = {"technology": "nginx"}
    e = _bbot_event("TECHNOLOGY", data)
    assert _translate(e, SCAN_ID) is None


# ── _translate: FINDING ───────────────────────────────────────────────────────

def test_translate_finding():
    data = {
        "description": "Directory listing enabled",
        "type": "misconfiguration",
        "host": "api.example.com",
        "module": "badsecrets",
    }
    e = _bbot_event("FINDING", data)
    result = _translate(e, SCAN_ID)
    assert result is not None
    assert result.type.value == "FINDING_CANDIDATE"
    assert result.data.host == "api.example.com"
    assert result.data.category == "misconfiguration"
    assert result.data.severity_hint == "info"
    assert result.data.evidence["module"] == "badsecrets"


def test_translate_finding_no_host_returns_none():
    data = {"description": "something", "type": "info"}
    e = _bbot_event("FINDING", data)
    assert _translate(e, SCAN_ID) is None


# ── unknown event type ────────────────────────────────────────────────────────

def test_translate_unknown_type_returns_none():
    e = _bbot_event("WEIRD_EVENT", "data")
    assert _translate(e, SCAN_ID) is None


# ── _try_import_bbot when bbot not installed ──────────────────────────────────

def test_try_import_bbot_returns_none_when_not_installed(monkeypatch):
    import recon.bbot_wrap as bw
    # Reset the warned flag so the warning fires fresh for this test.
    bw._IMPORT_WARNED = False

    original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    # Temporarily remove bbot from sys.modules and prevent import
    sys.modules.pop("bbot", None)
    sys.modules.pop("bbot.scanner", None)

    with patch.dict(sys.modules, {"bbot": None, "bbot.scanner": None}):
        result = bw._try_import_bbot()
    assert result is None


# ── BBOTWrapper.run() integration (mocked Scanner) ───────────────────────────

async def _run_with_fake_scanner(bbot_events: list, modules=None) -> tuple[int, int]:
    """
    Run BBOTWrapper with a mocked Scanner.
    Returns (accepted_count, total_published_calls).
    """
    import recon.bbot_wrap as bw

    # Build fake scanner that yields the given events.
    async def _fake_async_start():
        for ev in bbot_events:
            yield ev

    fake_scanner = MagicMock()
    fake_scanner.async_start = _fake_async_start

    FakeScanner = MagicMock(return_value=fake_scanner)

    accepted = []

    async def fake_stamp_and_publish(event):
        accepted.append(event)
        return True

    ctrl = MagicMock()
    ctrl.stamp_and_publish = fake_stamp_and_publish

    with patch.object(bw, "_try_import_bbot", return_value=FakeScanner):
        wrapper = BBOTWrapper(ctrl, modules=modules or ["crt"])
        await wrapper.run("example.com", SCAN_ID)

    return len(accepted), FakeScanner.call_count


async def test_bbotwrapper_accepts_dns_name_events():
    events = [
        _bbot_event("DNS_NAME", "api.example.com"),
        _bbot_event("DNS_NAME", "mail.example.com"),
        _bbot_event("DNS_NAME", ""),   # malformed — should be skipped
    ]
    accepted, _ = await _run_with_fake_scanner(events)
    assert accepted == 2


async def test_bbotwrapper_accepts_mixed_event_types():
    events = [
        _bbot_event("DNS_NAME", "api.example.com"),
        _bbot_event("IP_ADDRESS", "1.2.3.4"),
        _bbot_event("OPEN_TCP_PORT", "api.example.com:443"),
        _bbot_event("URL", "https://api.example.com/robots.txt"),
        _bbot_event("WEIRD_THING", "ignored"),  # unknown — skipped
    ]
    accepted, _ = await _run_with_fake_scanner(events)
    assert accepted == 4


async def test_bbotwrapper_passes_custom_modules():
    events = [_bbot_event("DNS_NAME", "api.example.com")]
    _, call_count = await _run_with_fake_scanner(events, modules=["crt", "shodan_dns"])
    assert call_count == 1


async def test_bbotwrapper_skips_when_bbot_not_installed():
    import recon.bbot_wrap as bw

    called = []

    async def fake_publish(event):
        called.append(event)
        return True

    ctrl = MagicMock()
    ctrl.stamp_and_publish = fake_publish

    with patch.object(bw, "_try_import_bbot", return_value=None):
        wrapper = BBOTWrapper(ctrl)
        await wrapper.run("example.com", SCAN_ID)

    assert len(called) == 0   # nothing published


async def test_bbotwrapper_scanner_error_handled_gracefully():
    import recon.bbot_wrap as bw

    async def _crash_start():
        raise RuntimeError("BBOT exploded")
        yield  # make it an async generator

    fake_scanner = MagicMock()
    fake_scanner.async_start = _crash_start
    FakeScanner = MagicMock(return_value=fake_scanner)

    ctrl = MagicMock()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)

    with patch.object(bw, "_try_import_bbot", return_value=FakeScanner):
        wrapper = BBOTWrapper(ctrl)
        # Should not raise — error is caught internally
        await wrapper.run("example.com", SCAN_ID)

    ctrl.stamp_and_publish.assert_not_called()


def test_default_modules_are_passive():
    # Verify the defaults are the passive, no-API-key modules.
    assert "crt" in DEFAULT_MODULES
    assert "certspotter" in DEFAULT_MODULES
    assert "rapiddns" in DEFAULT_MODULES
    assert "dnsdumpster" in DEFAULT_MODULES
    # Active / exploit modules must NOT be in the defaults.
    assert "nuclei" not in DEFAULT_MODULES
    assert "ffuf" not in DEFAULT_MODULES
