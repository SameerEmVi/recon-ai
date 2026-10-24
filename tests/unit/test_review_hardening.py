"""
Regression tests for the code-review hardening fixes:

  1. the seed domain is scope-gated (controller, CLI, MCP) — fail closed;
  2. a failed scan is recorded as failed, never overwritten as complete;
  3. MCP background scan tasks are strongly referenced until done;
  4. Set-Cookie headers are kept per cookie (no flag masking on merge);
  5. the response cache keys followed vs. non-followed GETs separately.

(The hyphen-label scope fix lives in tests/security/test_scope_engine.py.)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from scope.types import Scope


def _scope(in_scope, out_scope=None):
    return Scope.from_strings(in_scope=in_scope, out_scope=out_scope or [])


def _mock_client_factory(handler):
    """Patch target for httpx.AsyncClient that routes to a MockTransport."""
    real_client = httpx.AsyncClient

    def factory(*a, **kw):
        return real_client(transport=httpx.MockTransport(handler), **kw)

    return factory


# ── 1. seed scope gate ────────────────────────────────────────────────────────

@pytest.mark.parametrize("in_scope,out_scope", [
    (["*.other.com", "other.com"], []),                 # seed not covered by allow
    (["*.target.com", "target.com"], ["target.com"]),   # seed explicitly denied
])
async def test_controller_refuses_out_of_scope_seed(in_scope, out_scope):
    from controller.controller import ScanController, SeedOutOfScope

    ctrl = ScanController(_scope(in_scope, out_scope), results_enabled=False)
    with patch.object(ctrl, "_do_run", new=AsyncMock()) as do_run, \
         patch.object(ctrl, "_init_db", new=AsyncMock()) as init_db:
        with pytest.raises(SeedOutOfScope):
            await ctrl.run("target.com")
    # Nothing ran: no DB, no modules, no seed event.
    do_run.assert_not_awaited()
    init_db.assert_not_awaited()
    assert ctrl.bus.seen_count == 0


async def test_controller_accepts_in_scope_seed():
    from controller.controller import ScanController

    ctrl = ScanController(_scope(["*.target.com", "target.com"]), results_enabled=False)
    with patch.object(ctrl, "_do_run", new=AsyncMock()) as do_run, \
         patch.object(ctrl, "print_summary"):
        await ctrl.run("target.com")
    do_run.assert_awaited_once_with("target.com")


def test_cli_rejects_out_of_scope_seed():
    from typer.testing import CliRunner

    from cli.main import app

    with patch("controller.controller.ScanController.run", new=AsyncMock()) as run:
        result = CliRunner().invoke(
            app, ["scan", "target.com", "--out-scope", "target.com", "--no-results"]
        )
    assert result.exit_code == 1
    assert "not in scope" in result.output
    run.assert_not_awaited()


async def test_mcp_start_scan_rejects_out_of_scope_seed():
    from mcpserver import server

    with patch.object(server, "_run_scan_bg", new=AsyncMock()) as bg:
        out = await server.start_scan(
            "target.com", db_url="sqlite+aiosqlite://", in_scope=["*.other.com"]
        )
    assert "error" in out and "not in scope" in out["error"]
    bg.assert_not_called()


async def test_mcp_start_scan_rejects_invalid_scope_rule():
    from mcpserver import server

    out = await server.start_scan("target.com", db_url="sqlite+aiosqlite://",
                                  in_scope=["foo.*.com"])
    assert "invalid scope rule" in out["error"]


# ── 3. MCP background task is strongly referenced ─────────────────────────────

async def test_mcp_start_scan_keeps_task_reference():
    from mcpserver import server

    gate = asyncio.Event()

    async def fake_bg(**_kw):
        await gate.wait()

    with patch.object(server, "_run_scan_bg", new=fake_bg):
        out = await server.start_scan("target.com", db_url="sqlite+aiosqlite://")
        assert out["status"] == "running"
        assert len(server._scan_tasks) == 1          # held while running
        task = next(iter(server._scan_tasks))
        gate.set()
        await task
        await asyncio.sleep(0)                       # let the done-callback run
    assert task not in server._scan_tasks            # released once finished


# ── 2. failed scan status is not overwritten ──────────────────────────────────

class _FakePersister:
    def __init__(self):
        self.calls: list[str] = []

    async def scan_fail(self, _sid):
        self.calls.append("fail")

    async def scan_end(self, _sid, _n):
        self.calls.append("end")


async def _run_with_persister(do_run):
    from controller.controller import ScanController

    ctrl = ScanController(_scope(["*.target.com", "target.com"]), results_enabled=False)
    persister = _FakePersister()
    ctrl._persister = persister
    with patch.object(ctrl, "_do_run", new=do_run), patch.object(ctrl, "print_summary"):
        try:
            await ctrl.run("target.com")
        except (Exception, asyncio.CancelledError):
            pass
    return persister.calls


async def test_failed_scan_recorded_as_failed_only():
    calls = await _run_with_persister(AsyncMock(side_effect=RuntimeError("boom")))
    assert calls == ["fail"]


async def test_cancelled_scan_recorded_as_failed():
    calls = await _run_with_persister(AsyncMock(side_effect=asyncio.CancelledError()))
    assert calls == ["fail"]


async def test_successful_scan_recorded_as_complete():
    calls = await _run_with_persister(AsyncMock())
    assert calls == ["end"]


# ── 4. per-cookie Set-Cookie handling ─────────────────────────────────────────

async def test_cookie_check_flags_cookie_masked_by_hardened_sibling():
    from recon.fetch import FetchResult
    from vulnscan.checks import CheckContext, CookieSecurityCheck
    from vulnscan.engine import AssessmentEngine

    url = "https://app.target.com/"
    cookies = ("sid=abc; Path=/", "pref=1; Secure; HttpOnly; SameSite=Lax")

    async def fetch(_u):
        # `headers` carries httpx's merged value, exactly as dict(r.headers) does.
        return FetchResult(url=url, status_code=200, text="", ok=True,
                           headers={"set-cookie": ", ".join(cookies)},
                           set_cookies=cookies)

    ctx = CheckContext("app.target.com", fetch=fetch)
    ctx.services = [{"url": url, "status": 200}]
    await AssessmentEngine()._prefetch_services(ctx)
    results = await CookieSecurityCheck().run(ctx)

    assert len(results) == 1
    flagged = results[0].evidence["cookies"]
    assert "sid(-Secure/HttpOnly/SameSite)" in flagged
    assert "pref" not in flagged


async def test_fetch_populates_set_cookies_per_header():
    from modules.base import BaseModule

    def handler(_req):
        return httpx.Response(200, text="ok", headers=[
            ("set-cookie", "sid=abc; Path=/"),
            ("set-cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
        ])

    class _M(BaseModule):
        name = "t"

    with patch("httpx.AsyncClient", new=_mock_client_factory(handler)):
        res = await _M(MagicMock()).fetch("https://app.target.com/")
    assert res.set_cookies == ("sid=abc; Path=/", "pref=1; Secure; HttpOnly; SameSite=Lax")


# ── 5. cache keys separate redirect modes ─────────────────────────────────────

def test_cache_key_distinguishes_redirect_mode():
    from recon.fetch import ResponseCache

    u = "https://app.target.com/admin"
    assert ResponseCache.key(u) == ResponseCache.key(u, follow_redirects=True)
    assert ResponseCache.key(u, follow_redirects=False) != ResponseCache.key(u)


async def test_fetch_does_not_share_entry_across_redirect_modes():
    from modules.base import BaseModule
    from recon.fetch import ResponseCache

    def handler(req):
        if req.url.path == "/admin":
            return httpx.Response(302, headers={"location": "/login"})
        return httpx.Response(200, text="login page")

    ctrl = MagicMock()
    ctrl.response_cache = ResponseCache()

    class _M(BaseModule):
        name = "t"

    m = _M(ctrl)
    with patch("httpx.AsyncClient", new=_mock_client_factory(handler)):
        raw = await m.fetch("https://app.target.com/admin", follow_redirects=False)
        followed = await m.fetch("https://app.target.com/admin", follow_redirects=True)
    assert raw.status_code == 302
    assert followed.status_code == 200
    assert ctrl.response_cache.stats()["entries"] == 2
