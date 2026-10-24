"""
Proxy integration tests — real sockets, local only (no public network).

Proves: outbound HTTP actually routes through the configured proxy (Burp
visibility), direct mode is unchanged, TLS verification stays on by default, and
an explicitly-configured but unreachable proxy stops the scan (no silent
direct fallback).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.base import BaseModule
from net.proxy import ProxyConfig


class _M(BaseModule):
    name = "probe"


def _ctrl(proxy: ProxyConfig | None = None):
    from ratelimit import NOOP
    c = MagicMock()
    c.rate_limiter = NOOP
    c.response_cache = None          # uncached → direct fetch path
    if proxy is not None:
        c.proxy = proxy
    return c


async def _start_mock_proxy(recorder: list[str]):
    """Minimal forward proxy: records the request line, returns a canned 200."""
    async def handle(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=5)
            recorder.append(data.decode("latin1").split("\r\n", 1)[0])
            body = b"proxied-ok"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Content-Type: text/plain\r\n\r\n%s" % (len(body), body))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _start_origin():
    """A direct-mode origin server returning a distinct body."""
    async def handle(reader, writer):
        try:
            await asyncio.wait_for(reader.read(65536), timeout=5)
            body = b"direct-ok"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                         % (len(body), body))
            await writer.drain()
        finally:
            writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_http_request_routes_through_proxy():
    recorder: list[str] = []
    server, port = await _start_mock_proxy(recorder)
    async with server:
        proxy = ProxyConfig.from_sources(cli_proxy=f"http://127.0.0.1:{port}")
        m = _M(_ctrl(proxy))
        res = await m.fetch("http://example.test/secret-path")
    assert res.ok and res.text == "proxied-ok"
    # The proxy saw the request in absolute-URI form → traffic really went through it.
    assert recorder and "http://example.test/secret-path" in recorder[0]


async def test_direct_mode_unchanged_when_no_proxy():
    server, port = await _start_origin()
    async with server:
        m = _M(_ctrl())                         # no proxy configured
        res = await m.fetch(f"http://127.0.0.1:{port}/")
    assert res.ok and res.text == "direct-ok"


async def test_tls_verification_on_by_default():
    # The client the module builds verifies TLS unless explicitly told otherwise.
    m = _M(_ctrl(ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080")))
    assert m.proxy.client_kwargs()["verify"] is True


async def test_explicit_verify_false_is_warned_not_silent():
    m = _M(_ctrl())
    with patch.object(m._log, "warning") as warn:
        client = m.http_client(verify=False)
        await client.aclose()
    assert warn.called   # disabling TLS is logged, never silent


async def test_proxy_failure_is_classified_not_crash():
    # Unreachable proxy → fetch returns a classified failure, never raises.
    proxy = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:1")
    m = _M(_ctrl(proxy))
    res = await m.fetch("http://example.test/")
    assert res.ok is False and res.error


async def test_controller_refuses_scan_when_mandatory_proxy_down():
    # An explicitly-configured but unreachable proxy must STOP the scan — no
    # silent direct fallback.
    from controller.controller import ScanController
    from net.errors import ProxyConnectionError
    from scope.types import Scope

    ctrl = ScanController(
        Scope.from_strings(in_scope=["*.t.com", "t.com"]),
        results_enabled=False,
        proxy=ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:1"),
    )
    with patch.object(ctrl, "_do_run", new=AsyncMock()) as do_run, \
         patch.object(ctrl, "print_summary"):
        with pytest.raises(ProxyConnectionError):
            await ctrl.run("t.com")
    do_run.assert_not_awaited()    # never reached the scan


async def test_controller_debug_writes_correlated_diagnostics(tmp_path):
    import glob
    import json
    import os

    from controller.controller import ScanController
    from scope.types import Scope

    ctrl = ScanController(
        Scope.from_strings(in_scope=["*.t.com", "t.com"]),
        results_enabled=False, out_dir=str(tmp_path), debug=True)
    with patch.object(ctrl, "_do_run", new=AsyncMock()), patch.object(ctrl, "print_summary"):
        await ctrl.run("t.com")

    files = glob.glob(os.path.join(str(tmp_path), "t.com", "run-*",
                                   "diagnostics", "events.jsonl"))
    assert files, "diagnostics events.jsonl not written"
    recs = [json.loads(ln) for ln in open(files[0], encoding="utf-8") if ln.strip()]
    events = {r["event"] for r in recs}
    assert {"scan_start", "scan_complete"} <= events
    assert all(r["run_id"] == str(ctrl.scan_id) for r in recs)
