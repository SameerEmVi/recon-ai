"""
Shared HTTP response cache (recon/fetch.py) + BaseModule.fetch integration.

Covers:
  - in-flight de-duplication: concurrent callers for one URL → ONE fetcher run
  - cache hit: a completed URL is not re-fetched
  - distinct URLs fetch independently
  - a fetcher that raises is turned into an ok=False result (no wedged waiters)
  - LRU bound evicts least-recently-used
  - get_response_cache test-safety (real cache vs mock vs missing)
  - BaseModule.fetch de-dups one network GET across two modules sharing a scan
"""

from __future__ import annotations

import asyncio
import types
import uuid
from unittest.mock import MagicMock

from ratelimit import NOOP
from recon.fetch import FetchResult, ResponseCache, get_response_cache


# ── ResponseCache: in-flight de-dup ───────────────────────────────────────────

async def test_concurrent_callers_fetch_once():
    cache = ResponseCache()
    calls = 0
    gate = asyncio.Event()

    async def fetcher():
        nonlocal calls
        calls += 1
        await gate.wait()           # hold both callers in-flight
        return FetchResult(url="u", status_code=200, text="body", ok=True)

    key = ResponseCache.key("https://e.com/x")
    task_a = asyncio.create_task(cache.get_or_fetch(key, fetcher))
    task_b = asyncio.create_task(cache.get_or_fetch(key, fetcher))
    await asyncio.sleep(0)          # let both reach the in-flight await
    gate.set()
    a, b = await asyncio.gather(task_a, task_b)

    assert calls == 1              # ONE real fetch shared by both
    assert a.text == b.text == "body"
    assert cache.stats()["hits"] == 1 and cache.stats()["misses"] == 1


async def test_cache_hit_not_refetched():
    cache = ResponseCache()
    calls = 0

    async def fetcher():
        nonlocal calls
        calls += 1
        return FetchResult(url="u", status_code=200, text="v", ok=True)

    key = ResponseCache.key("https://e.com/x")
    await cache.get_or_fetch(key, fetcher)
    r = await cache.get_or_fetch(key, fetcher)   # served from cache
    assert calls == 1
    assert r.text == "v"


async def test_distinct_urls_fetched_separately():
    cache = ResponseCache()
    calls = 0

    async def fetcher():
        nonlocal calls
        calls += 1
        return FetchResult(url="u", ok=True)

    await cache.get_or_fetch(ResponseCache.key("https://e.com/a"), fetcher)
    await cache.get_or_fetch(ResponseCache.key("https://e.com/b"), fetcher)
    assert calls == 2


async def test_raising_fetcher_becomes_error_result():
    cache = ResponseCache()

    async def boom():
        raise RuntimeError("kaboom")

    r = await cache.get_or_fetch(ResponseCache.key("https://e.com/x"), boom)
    assert r.ok is False
    assert "kaboom" in (r.error or "")
    # a second caller gets the cached error without re-running the fetcher
    r2 = await cache.get_or_fetch(ResponseCache.key("https://e.com/x"), boom)
    assert r2.ok is False


async def test_lru_eviction_bound():
    cache = ResponseCache(max_entries=2)

    async def make(v):
        async def f():
            return FetchResult(url=v, text=v, ok=True)
        return f

    await cache.get_or_fetch(ResponseCache.key("a"), await make("a"))
    await cache.get_or_fetch(ResponseCache.key("b"), await make("b"))
    await cache.get_or_fetch(ResponseCache.key("c"), await make("c"))  # evicts "a"
    assert cache.stats()["entries"] == 2

    # "a" was evicted → fetched again (fetcher runs), proving it wasn't cached
    ran = False

    async def a_again():
        nonlocal ran
        ran = True
        return FetchResult(url="a", text="a2", ok=True)

    await cache.get_or_fetch(ResponseCache.key("a"), a_again)
    assert ran is True


# ── get_response_cache test-safety ────────────────────────────────────────────

def test_get_response_cache_real_mock_and_missing():
    real = ResponseCache()
    ctrl = types.SimpleNamespace(response_cache=real)
    assert get_response_cache(ctrl) is real

    mock_ctrl = MagicMock()                      # .response_cache is a MagicMock
    assert get_response_cache(mock_ctrl) is None

    assert get_response_cache(object()) is None  # no attribute at all


# ── BaseModule.fetch integration (cache dedup across modules) ─────────────────

def _fake_httpx(monkeypatch, counter, body="<html>hi</html>", status=200):
    import httpx

    class _Resp:
        def __init__(self):
            self.status_code = status
            self.headers = {"content-type": "text/html"}
            self.content = body.encode()
            self.text = body

    class _Client:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def get(self, url, **k):
            counter["n"] += 1
            await asyncio.sleep(0.01)   # keep concurrent callers overlapping
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


def _module_on(ctrl):
    from modules.base import BaseModule

    class _M(BaseModule):
        name = "t"
    return _M(ctrl)


async def test_basemodule_fetch_dedups_across_modules(monkeypatch):
    counter = {"n": 0}
    _fake_httpx(monkeypatch, counter)
    ctrl = types.SimpleNamespace(
        scan_id=uuid.uuid4(), response_cache=ResponseCache(), rate_limiter=NOOP
    )
    m1, m2 = _module_on(ctrl), _module_on(ctrl)

    r1, r2 = await asyncio.gather(
        m1.fetch("https://e.com/page"), m2.fetch("https://e.com/page")
    )
    assert counter["n"] == 1                 # one network GET shared
    assert r1.text == r2.text == "<html>hi</html>"
    assert r1.status_code == 200 and r1.content_type == "text/html"


async def test_percaller_cap_applied_at_read_not_at_fetch(monkeypatch):
    # A big body fetched first by a SMALL-cap caller must still be available to a
    # later LARGE-cap caller: the cache holds the full body, each caller applies
    # its own max_body_kb at read time. One network GET total.
    counter = {"n": 0}
    big = "A" * (700 * 1024)            # 700 KB body
    _fake_httpx(monkeypatch, counter, body=big)
    ctrl = types.SimpleNamespace(
        scan_id=uuid.uuid4(), response_cache=ResponseCache(), rate_limiter=NOOP
    )
    small, large = _module_on(ctrl), _module_on(ctrl)

    # small-cap caller fetches first (512 KB) → body over ITS cap → text hidden
    r_small = await small.fetch("https://e.com/big.js", max_body_kb=512)
    # large-cap caller reads the SAME cached body (2048 KB) → still gets it
    r_large = await large.fetch("https://e.com/big.js", max_body_kb=2048)

    assert counter["n"] == 1                 # one network GET, shared
    assert r_small.text is None              # exceeded 512 KB cap for this caller
    assert r_large.text == big               # within 2048 KB cap → full body
    assert r_small.size_kb == r_large.size_kb == 700.0


async def test_basemodule_fetch_without_cache_is_direct(monkeypatch):
    # A mock controller (no real ResponseCache) → uncached direct fetch, still works.
    counter = {"n": 0}
    _fake_httpx(monkeypatch, counter)
    ctrl = MagicMock()
    ctrl.rate_limiter = NOOP
    m = _module_on(ctrl)

    r = await m.fetch("https://e.com/x")
    assert r.ok and r.text == "<html>hi</html>"
    assert counter["n"] == 1
