"""
ratelimit — central, WAF-aware rate limiting for the whole platform.

One RateLimiter is created per scan (owned by the ScanController) and shared by
every recon module, subprocess wrapper, and agent tool. It provides three things
through a single `guard()` context manager:

  * requests-per-second spacing  — a min-interval between op starts, per bucket
  * concurrency capping          — a global semaphore over in-flight ops
  * adaptive WAF backoff         — when observe_http() sees a WAF/block response,
                                   the spacing is multiplied (and recovers slowly
                                   on clean responses)

Everything is opt-in. `RateLimiter()` with no arguments applies no static limits;
it only kicks in if the user supplies a rate/concurrency OR a WAF is detected
mid-scan, at which point it self-imposes a polite baseline and backs off.

Usage
-----
    limiter = RateLimiter(rate_per_sec=5, max_concurrency=20)

    async with limiter.guard(bucket="crt.sh"):
        r = await client.get(url)
    limiter.observe_http(status=r.status_code, headers=r.headers)   # feeds WAF backoff

Test-safety: `get_limiter(obj)` returns a shared no-op limiter unless
`obj.rate_limiter` is a real RateLimiter, so MagicMock controllers used in unit
tests transparently get a working (no-op) limiter.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from ratelimit.waf import WafSignal, detect as waf_detect

log = logging.getLogger("ratelimit")

# Adaptive-backoff tuning.
_MAX_PENALTY = 32.0          # cap on the spacing multiplier
_PENALTY_STEP = 2.0          # multiply penalty by this on each blocking response
_PRESENCE_PENALTY = 1.5      # floor penalty when a WAF is merely present (200 + fingerprint)
_RECOVER_FACTOR = 0.9        # multiply penalty by this on each clean response
# Baseline spacing (seconds) self-imposed once a WAF blocks us, if the user set
# no explicit rate. 1.0s => at most ~1 req/s/bucket before the penalty multiplier.
_WAF_BASELINE_INTERVAL = 1.0

__all__ = ["RateLimiter", "WafSignal", "get_limiter", "NOOP"]


class RateLimiter:
    def __init__(
        self,
        rate_per_sec: float | None = None,
        max_concurrency: int | None = None,
        *,
        name: str = "global",
        frozen: bool = False,
    ) -> None:
        # A frozen limiter never throttles and never adapts — used for the shared
        # NOOP fallback so WAF detection on a controller-less path (or a unit-test
        # MagicMock) can't mutate global state.
        self._frozen = frozen
        self._rate = rate_per_sec if (rate_per_sec and rate_per_sec > 0) else None
        self._base_interval = (1.0 / self._rate) if self._rate else 0.0
        self._max_conc = max_concurrency if (max_concurrency and max_concurrency > 0) else None
        self._sem = asyncio.Semaphore(self._max_conc) if self._max_conc else None
        self._next: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()
        self._penalty = 1.0
        self._name = name
        self._waf_seen: set[str] = set()

    # ── introspection ────────────────────────────────────────────────────────

    @property
    def penalty(self) -> float:
        return self._penalty

    @property
    def waf_vendors(self) -> set[str]:
        return set(self._waf_seen)

    def describe(self) -> str:
        r = f"{self._rate:g}/s" if self._rate else "unlimited"
        c = str(self._max_conc) if self._max_conc else "unlimited"
        return f"rate={r} concurrency={c} adaptive-waf=on"

    # ── the one entry point every network/subprocess op uses ──────────────────

    @asynccontextmanager
    async def guard(self, bucket: str = "global"):
        """Acquire a concurrency slot, then space this op's start, then run."""
        if self._sem is not None:
            await self._sem.acquire()
        try:
            await self._throttle(bucket)
            yield
        finally:
            if self._sem is not None:
                self._sem.release()

    async def _throttle(self, bucket: str) -> None:
        interval = self._base_interval * self._penalty
        if interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next[bucket])
            self._next[bucket] = start + interval
            wait = start - now
        if wait > 0:
            await asyncio.sleep(wait)

    # ── adaptive WAF backoff ──────────────────────────────────────────────────

    def observe_http(self, *, status=None, headers=None, body=None) -> WafSignal | None:
        """Inspect one HTTP response; back off on WAF/block, recover on clean.

        Returns the WafSignal if one was detected, else None.
        """
        if self._frozen:
            return None
        sig = waf_detect(status=status, headers=headers, body=body)
        if sig is None:
            self._recover()
            return None
        self.penalize(sig)
        return sig

    def penalize(self, signal: WafSignal) -> None:
        """Increase backoff in response to a detected WAF signal."""
        if self._frozen:
            return
        # Self-impose a baseline interval so backoff has something to scale even
        # when the user supplied no static rate limit.
        if self._base_interval == 0.0:
            self._base_interval = _WAF_BASELINE_INTERVAL

        old = self._penalty
        if signal.blocking:
            self._penalty = min(self._penalty * _PENALTY_STEP, _MAX_PENALTY)
        else:
            self._penalty = min(max(self._penalty, _PRESENCE_PENALTY), _MAX_PENALTY)

        if signal.vendor not in self._waf_seen:
            self._waf_seen.add(signal.vendor)
            log.warning(
                "[%s] WAF detected: %s (%s) — enabling adaptive backoff",
                self._name, signal.vendor, signal.reason,
            )
        if self._penalty != old:
            eff = self._base_interval * self._penalty
            log.info(
                "[%s] backoff x%.1f (~%.2fs/op) after %s",
                self._name, self._penalty, eff, signal.reason,
            )

    def _recover(self) -> None:
        if self._penalty > 1.0:
            self._penalty = max(1.0, self._penalty * _RECOVER_FACTOR)


# Shared no-op limiter for code paths without a real controller (e.g. unit tests
# with a MagicMock controller, or standalone wrapper use).
NOOP = RateLimiter(name="noop", frozen=True)


def get_limiter(obj) -> "RateLimiter":
    """Return obj.rate_limiter if it's a real RateLimiter, else the NOOP limiter."""
    lim = getattr(obj, "rate_limiter", None)
    return lim if isinstance(lim, RateLimiter) else NOOP
