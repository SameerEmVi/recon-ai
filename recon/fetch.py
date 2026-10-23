"""
Shared HTTP response cache — one network GET per URL per scan, fanned out to
every body-consuming module.

Historically each web module (secretfinder, linkfinder, jsintel, apifinder,
corscanner, csprecon, …) opened its own httpx client and GET the same URLs
independently, so a single page body was downloaded N times — N rate-limiter
ops, N WAF observations, N× the latency. This module centralizes that: a
per-scan `ResponseCache` keyed by (method, url) that fetches a URL at most once
and shares the immutable `FetchResult` with every caller.

Design:
  - `FetchResult` is a frozen snapshot (status, text, headers, content_type).
  - `ResponseCache.get_or_fetch(key, fetcher)` runs `fetcher` exactly once per
    key even under concurrency (in-flight de-dup via a shared future), so two
    modules reacting to the same URL at the same time trigger ONE real fetch;
    the second awaits the first's result.
  - The cache is bounded (LRU) so a huge scan can't grow it without limit.

The cache stores results only; the actual network op (rate-limit guard + httpx
GET + WAF `inspect_response`) lives in `BaseModule.fetch`, which owns the
limiter. That keeps this module pure and unit-testable with a fake fetcher.

Test-safety: `get_response_cache(obj)` returns `obj.response_cache` only when
it is a real `ResponseCache` (mirrors `ratelimit.get_limiter`); a MagicMock
controller falls through to None, so `BaseModule.fetch` fetches directly with
no sharing — unit tests that construct modules with mock controllers are
unaffected.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping

# Global ceiling on a cached body (KB). A URL is fetched once and shared, so the
# cache stores the FULL body and each caller applies its own smaller max_body_kb
# at read time (BaseModule.fetch) — otherwise whichever module fetched first
# would bake in its cap and starve a later module with a larger one. This ceiling
# only bounds cache memory; it sits above every module's per-call cap (≤2048 KB),
# so no real caller is affected. A body over the ceiling is cached as text=None.
CACHE_MAX_BODY_KB = 8192


@dataclass(frozen=True)
class FetchResult:
    """An immutable snapshot of one HTTP GET, shared across modules.

    `text` is None when the body was too large (over the caller's cap) or the
    request failed; it is populated for any response within the cap regardless
    of status. `status_code`/`headers` are still populated on any real response
    so probing modules can reason about it. `ok` means a response was received
    (regardless of status); `error` carries the transport failure otherwise.
    """

    url: str
    status_code: int | None = None
    text: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    content_type: str | None = None
    ok: bool = False
    error: str | None = None
    size_kb: float | None = None   # real body size (KB) on any response, for per-caller caps
    # Each Set-Cookie header kept separately. `headers` is a plain mapping, and
    # httpx merges repeated headers into one comma-joined value there — which
    # lets one hardened cookie's flags mask another cookie that lacks them.
    set_cookies: tuple[str, ...] = ()

    @property
    def is_2xx(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300


class ResponseCache:
    """Per-scan URL → FetchResult cache with in-flight de-duplication.

    Not thread-safe; intended for a single asyncio event loop (the scan loop),
    exactly like the EventBus and RateLimiter it sits beside.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self._max = max_entries
        self._cache: "OrderedDict[str, FetchResult]" = OrderedDict()
        self._inflight: dict[str, asyncio.Future[FetchResult]] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(url: str, method: str = "GET", *, follow_redirects: bool = True) -> str:
        # A followed and a non-followed GET of the same URL are different
        # responses (final page vs. the 3xx itself), so they must not share an
        # entry — otherwise whichever module fetched first decides for the rest.
        suffix = "" if follow_redirects else " [no-redirect]"
        return f"{method.upper()} {url}{suffix}"

    async def get_or_fetch(
        self, key: str, fetcher: Callable[[], Awaitable[FetchResult]]
    ) -> FetchResult:
        """Return the cached result for `key`, or run `fetcher` once to produce it.

        Concurrent callers for the same key share a single `fetcher` run: the
        first caller executes it; the rest await its future. `fetcher` must not
        raise — it returns a FetchResult (ok=False on failure) — but we defend
        against it anyway so a stray exception can't wedge waiters.
        """
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            self.hits += 1
            return cached

        inflight = self._inflight.get(key)
        if inflight is not None:
            self.hits += 1
            return await inflight

        self.misses += 1
        loop = asyncio.get_event_loop()
        fut: asyncio.Future[FetchResult] = loop.create_future()
        self._inflight[key] = fut
        try:
            result = await fetcher()
        except Exception as exc:  # fetcher is supposed to be total; be safe
            result = FetchResult(url=key, ok=False, error=repr(exc))
        finally:
            self._inflight.pop(key, None)
        self._store(key, result)
        if not fut.done():
            fut.set_result(result)
        return result

    def _store(self, key: str, result: FetchResult) -> None:
        self._cache[key] = result
        self._cache.move_to_end(key)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)  # evict least-recently-used

    def stats(self) -> dict[str, int]:
        return {
            "entries": len(self._cache),
            "hits": self.hits,
            "misses": self.misses,
        }


def get_response_cache(obj) -> ResponseCache | None:
    """Return obj.response_cache if it's a real ResponseCache, else None.

    Mirrors ratelimit.get_limiter's test-safety: a MagicMock controller yields
    a MagicMock attribute (not a ResponseCache), so callers fall back to an
    uncached direct fetch rather than sharing through a mock.
    """
    cache = getattr(obj, "response_cache", None)
    return cache if isinstance(cache, ResponseCache) else None
