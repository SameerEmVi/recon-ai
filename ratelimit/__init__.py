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

# A detected Retry-After is honoured, but capped so a hostile/huge value can't
# stall a scan indefinitely (we log when we clamp).
_MAX_RETRY_AFTER = 300.0
# Sentinel bucket key for scan-wide (global) cooldown state.
_GLOBAL_KEY = "*"

__all__ = ["RateLimiter", "WafSignal", "get_limiter", "NOOP"]


class RateLimiter:
    def __init__(
        self,
        rate_per_sec: float | None = None,
        max_concurrency: int | None = None,
        *,
        global_rate_per_sec: float | None = None,
        burst: int | None = None,
        per_target_concurrency: int | None = None,
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

        # ── parallel-engine extensions (all opt-in; unset ⇒ prior behaviour) ──
        # Aggregate requests/sec across ALL buckets (a token bucket with burst),
        # so N workers over N hosts can't exceed the configured TOTAL budget —
        # worker count must never multiply the request rate.
        self._g_rate = global_rate_per_sec if (global_rate_per_sec and global_rate_per_sec > 0) else None
        self._g_cap = float(burst) if (burst and burst > 0) else (
            max(1.0, self._g_rate) if self._g_rate else 1.0)
        self._g_tokens = self._g_cap
        self._g_ts = time.monotonic()
        # Per-target (per-bucket) concurrency, on top of the global semaphore —
        # one slow/blocked host can't starve the global pool.
        self._per_target_conc = per_target_concurrency if (
            per_target_concurrency and per_target_concurrency > 0) else None
        self._target_sems: dict[str, asyncio.Semaphore] = {}
        # Per-target adaptive backoff + cooldown: a WAF/429 on one target pauses
        # THAT target (so other authorized targets keep going), rather than the
        # old single scan-wide penalty. _GLOBAL_KEY holds any scan-wide cooldown.
        self._bucket_penalty: dict[str, float] = defaultdict(lambda: 1.0)
        self._cooldown_until: dict[str, float] = defaultdict(float)
        # Total guarded ops (≈ outbound requests) — feeds the unified report's
        # "total requests" / aggregate request-rate stats.
        self._ops = 0

    # ── introspection ────────────────────────────────────────────────────────

    @property
    def penalty(self) -> float:
        return self._penalty

    @property
    def rate_per_sec(self) -> float | None:
        """Configured static rate (req/s), or None if unlimited. Read-only —
        lets subprocess wrappers (ffuf -rate, …) honour the scan-wide -r."""
        return self._rate

    @property
    def max_concurrency(self) -> int | None:
        """Configured global concurrency cap, or None if unlimited."""
        return self._max_conc

    @property
    def waf_vendors(self) -> set[str]:
        return set(self._waf_seen)

    @property
    def global_rate_per_sec(self) -> float | None:
        """Configured aggregate req/s across all buckets, or None if unlimited."""
        return self._g_rate

    @property
    def per_target_concurrency(self) -> int | None:
        return self._per_target_conc

    def describe(self) -> str:
        r = f"{self._rate:g}/s" if self._rate else "unlimited"
        c = str(self._max_conc) if self._max_conc else "unlimited"
        extra = ""
        if self._g_rate:
            extra += f" global={self._g_rate:g}/s(burst {self._g_cap:g})"
        if self._per_target_conc:
            extra += f" per-target-conc={self._per_target_conc}"
        return f"rate={r} concurrency={c}{extra} adaptive-waf=on"

    # ── the one entry point every network/subprocess op uses ──────────────────

    def _target_sem(self, bucket: str) -> asyncio.Semaphore | None:
        if self._per_target_conc is None:
            return None
        sem = self._target_sems.get(bucket)
        if sem is None:
            sem = asyncio.Semaphore(self._per_target_conc)
            self._target_sems[bucket] = sem
        return sem

    @asynccontextmanager
    async def guard(self, bucket: str = "global"):
        """Acquire a per-target slot, then a global slot, then space this op's
        start (per-bucket spacing + aggregate token bucket + any cooldown), then
        run. Per-target is acquired first so a host at its per-target cap blocks
        there instead of holding global slots and starving other hosts."""
        self._ops += 1
        tsem = self._target_sem(bucket)
        if tsem is not None:
            await tsem.acquire()
        try:
            if self._sem is not None:
                await self._sem.acquire()
            try:
                await self._throttle(bucket)
                yield
            finally:
                if self._sem is not None:
                    self._sem.release()
        finally:
            if tsem is not None:
                tsem.release()

    async def _throttle(self, bucket: str) -> None:
        # 1. Aggregate (global) token bucket — the scan-wide rps ceiling that
        #    makes worker count independent of request budget.
        await self._consume_global_token()
        # 2. Per-bucket spacing at the effective penalty (max of scan-wide and
        #    this target's own penalty) plus any active cooldown for this target
        #    or the whole scan (Retry-After / WAF pause).
        eff_penalty = max(self._penalty, self._bucket_penalty.get(bucket, 1.0))
        interval = self._base_interval * eff_penalty
        cooldown = max(self._cooldown_until.get(bucket, 0.0),
                       self._cooldown_until.get(_GLOBAL_KEY, 0.0))
        if interval <= 0 and cooldown <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next[bucket], cooldown)
            self._next[bucket] = start + interval if interval > 0 else start
            wait = start - now
        if wait > 0:
            await asyncio.sleep(wait)

    async def _consume_global_token(self) -> None:
        """Token bucket over ALL buckets: refill at _g_rate (cap _g_cap), spend 1
        token per op, reserving future capacity so concurrent callers can't burst
        past the aggregate rate. No-op when no global rate is configured."""
        if self._g_rate is None:
            return
        async with self._lock:
            now = time.monotonic()
            self._g_tokens = min(self._g_cap, self._g_tokens + (now - self._g_ts) * self._g_rate)
            self._g_ts = now
            if self._g_tokens >= 1.0:
                self._g_tokens -= 1.0
                wait = 0.0
            else:
                wait = (1.0 - self._g_tokens) / self._g_rate
                self._g_tokens = 0.0
                self._g_ts = now + wait   # reserve: later refill accounts for this grant
        if wait > 0:
            await asyncio.sleep(wait)

    # ── adaptive WAF backoff ──────────────────────────────────────────────────

    def observe_http(self, *, status=None, headers=None, body=None,
                     bucket: str | None = None) -> WafSignal | None:
        """Inspect one HTTP response; back off on WAF/block, recover on clean.

        When `bucket` is given, backoff/cooldown apply to THAT target only so a
        block on one host doesn't throttle other authorized targets; without it,
        behaviour is the prior scan-wide backoff (backward compatible). A
        `Retry-After` header on a 429/503 is honoured (shared cooldown) regardless.
        Returns the WafSignal if one was detected, else None.
        """
        if self._frozen:
            return None
        sig = waf_detect(status=status, headers=headers, body=body)
        # Honour Retry-After even if no WAF fingerprint matched (a bare 429/503).
        retry = self._retry_after_seconds(status, headers)
        if retry is not None:
            self._set_cooldown(bucket, retry)
        if sig is None:
            if retry is None:
                self._recover(bucket)
            return None
        self.penalize(sig, bucket=bucket)
        return sig

    def penalize(self, signal: WafSignal, *, bucket: str | None = None) -> None:
        """Increase backoff in response to a detected WAF signal — scan-wide, or
        for one target when `bucket` is given."""
        if self._frozen:
            return
        # Self-impose a baseline interval so backoff has something to scale even
        # when the user supplied no static rate limit.
        if self._base_interval == 0.0:
            self._base_interval = _WAF_BASELINE_INTERVAL

        if bucket is None:
            old = self._penalty
            if signal.blocking:
                self._penalty = min(self._penalty * _PENALTY_STEP, _MAX_PENALTY)
            else:
                self._penalty = min(max(self._penalty, _PRESENCE_PENALTY), _MAX_PENALTY)
            new = self._penalty
        else:
            cur = self._bucket_penalty.get(bucket, 1.0)
            old = cur
            if signal.blocking:
                cur = min(cur * _PENALTY_STEP, _MAX_PENALTY)
            else:
                cur = min(max(cur, _PRESENCE_PENALTY), _MAX_PENALTY)
            self._bucket_penalty[bucket] = cur
            new = cur

        if signal.vendor not in self._waf_seen:
            self._waf_seen.add(signal.vendor)
            log.warning(
                "[%s] WAF detected: %s (%s) — enabling adaptive backoff",
                self._name, signal.vendor, signal.reason,
            )
        if new != old:
            eff = self._base_interval * new
            log.info(
                "[%s] backoff x%.1f (~%.2fs/op%s) after %s",
                self._name, new, eff, f" on {bucket}" if bucket else "", signal.reason,
            )

    def _set_cooldown(self, bucket: str | None, seconds: float) -> None:
        if seconds <= 0:
            return
        if seconds > _MAX_RETRY_AFTER:
            log.warning("[%s] Retry-After %.0fs capped to %.0fs", self._name, seconds, _MAX_RETRY_AFTER)
            seconds = _MAX_RETRY_AFTER
        key = bucket if bucket is not None else _GLOBAL_KEY
        until = time.monotonic() + seconds
        if until > self._cooldown_until.get(key, 0.0):
            self._cooldown_until[key] = until
            log.info("[%s] cooldown %.0fs%s (Retry-After)", self._name, seconds,
                     f" on {bucket}" if bucket else "")

    @staticmethod
    def _retry_after_seconds(status, headers) -> float | None:
        """Parse a Retry-After header (delta-seconds or HTTP-date) on a 429/503."""
        if status not in (429, 503) or not headers:
            return None
        try:
            raw = headers.get("retry-after") or headers.get("Retry-After")
        except Exception:
            raw = None
        if not raw:
            return None
        raw = str(raw).strip()
        if raw.isdigit():
            return float(raw)
        try:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            dt = parsedate_to_datetime(raw)
            if dt is None:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            return None

    def _recover(self, bucket: str | None = None) -> None:
        if bucket is None:
            if self._penalty > 1.0:
                self._penalty = max(1.0, self._penalty * _RECOVER_FACTOR)
        else:
            cur = self._bucket_penalty.get(bucket, 1.0)
            if cur > 1.0:
                self._bucket_penalty[bucket] = max(1.0, cur * _RECOVER_FACTOR)

    def stats(self) -> dict:
        """A sanitized snapshot for the scheduler's unified report."""
        return {
            "requests": self._ops,
            "penalty": round(self._penalty, 2),
            "waf_vendors": sorted(self._waf_seen),
            "targets_backed_off": sorted(b for b, p in self._bucket_penalty.items() if p > 1.0),
            "targets_in_cooldown": sorted(
                b for b, t in self._cooldown_until.items()
                if b != _GLOBAL_KEY and t > time.monotonic()),
        }


# Shared no-op limiter for code paths without a real controller (e.g. unit tests
# with a MagicMock controller, or standalone wrapper use).
NOOP = RateLimiter(name="noop", frozen=True)


def get_limiter(obj) -> "RateLimiter":
    """Return obj.rate_limiter if it's a real RateLimiter, else the NOOP limiter."""
    lim = getattr(obj, "rate_limiter", None)
    return lim if isinstance(lim, RateLimiter) else NOOP
