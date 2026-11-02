"""
Rate limiter + WAF-detection tests.

Covers:
  - static rps spacing and concurrency capping
  - no-op behavior when unconfigured
  - WAF fingerprint / block detection (headers, status, body)
  - adaptive backoff on block, recovery on clean responses
  - self-imposed baseline once a WAF blocks even with no static limit
  - get_limiter() test-safety with a MagicMock controller
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from ratelimit import NOOP, RateLimiter, get_limiter
from ratelimit.waf import detect


# ── WAF detection ─────────────────────────────────────────────────────────────

def test_waf_detect_none_on_clean_response():
    assert detect(status=200, headers={"server": "nginx"}) is None


def test_cdn_presence_alone_is_not_a_signal():
    # A pure CDN/LB fingerprint (no block page / 429 / WAF product) is NOT a WAF
    # signal — a CDN is not a firewall. Covers the 200 case for several CDNs.
    assert detect(status=200, headers={"Server": "cloudflare", "CF-RAY": "abc"}) is None
    assert detect(status=200, headers={"x-amz-cf-id": "deadbeef"}) is None
    assert detect(status=200, headers={"server": "AkamaiGHost"}) is None


def test_waf_product_presence_not_blocking():
    # A dedicated WAF product on a 200 is presence only (mild), not blocking.
    sig = detect(status=200, headers={"x-iinfo": "1"})
    assert sig is not None
    assert sig.vendor == "Imperva Incapsula"
    assert sig.blocking is False


def test_waf_product_blocking_status():
    sig = detect(status=403, headers={"x-iinfo": "1"})
    assert sig is not None
    assert sig.blocking is True
    assert sig.status == 403


def test_cloudfront_403_during_fuzzing_is_not_a_block():
    # REGRESSION: an S3/CloudFront 403 for a non-existent path (what ffuf /
    # bypass403 generate by the hundred) must NOT be read as a WAF block,
    # or the global backoff ramps to x32 and starves the whole scan.
    assert detect(status=403, headers={"x-amz-cf-id": "abc", "server": "AmazonS3"}) is None
    assert detect(status=404, headers={"x-amz-cf-id": "abc"}) is None


def test_cloudfront_real_block_still_detected():
    # A genuine block behind CloudFront still fires: a WAF-product header...
    assert detect(status=403, headers={"x-amz-cf-id": "abc",
                                       "x-amzn-waf-action": "block"}).blocking is True
    # ...a block-page body...
    assert detect(status=403, headers={"x-amz-cf-id": "abc"},
                  body="This request has been blocked").blocking is True
    # ...or an explicit 429.
    assert detect(status=429, headers={"x-amz-cf-id": "abc"}).blocking is True


def test_waf_detect_block_page_body():
    sig = detect(status=200, headers={}, body="<h1>Attention Required! | Cloudflare</h1>")
    assert sig is not None
    assert sig.blocking is True


def test_waf_detect_various_vendors():
    assert detect(status=200, headers={"x-sucuri-id": "1"}).vendor == "Sucuri"
    assert detect(status=200, headers={"x-iinfo": "1"}).vendor == "Imperva Incapsula"
    assert detect(status=200, headers={"x-datadome": "1"}).vendor == "DataDome"


def test_waf_detect_mock_headers_safe():
    # A MagicMock (as used for httpx responses in unit tests) must not raise.
    assert detect(status=MagicMock(), headers=MagicMock()) is None


# ── static limiting ───────────────────────────────────────────────────────────

async def test_noop_is_instant():
    lim = RateLimiter()
    t0 = time.monotonic()
    for _ in range(5):
        async with lim.guard("b"):
            pass
    assert time.monotonic() - t0 < 0.05


async def test_rate_spacing():
    lim = RateLimiter(rate_per_sec=20)  # 50ms apart
    t0 = time.monotonic()
    for _ in range(4):
        async with lim.guard("same-bucket"):
            pass
    elapsed = time.monotonic() - t0
    # 4 ops spaced 50ms => ~150ms minimum (first is free)
    assert elapsed >= 0.12


async def test_concurrency_cap():
    lim = RateLimiter(max_concurrency=2)
    active = 0
    peak = 0

    async def op():
        nonlocal active, peak
        async with lim.guard("b"):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(*[op() for _ in range(6)])
    assert peak <= 2


# ── adaptive WAF backoff ──────────────────────────────────────────────────────

def test_penalty_grows_on_block_and_recovers():
    lim = RateLimiter(rate_per_sec=10)
    assert lim.penalty == 1.0
    lim.observe_http(status=429, headers={"server": "cloudflare"})
    p1 = lim.penalty
    assert p1 > 1.0
    lim.observe_http(status=429, headers={"server": "cloudflare"})
    assert lim.penalty > p1
    # clean responses recover
    for _ in range(50):
        lim.observe_http(status=200, headers={"server": "nginx"})
    assert lim.penalty == 1.0


def test_backoff_self_imposes_baseline_without_static_limit():
    lim = RateLimiter()  # no static rate
    assert lim._base_interval == 0.0
    lim.observe_http(status=403, headers={"x-iinfo": "1"})  # Imperva WAF block
    # a WAF block now creates a real interval so guard() actually slows down
    assert lim._base_interval > 0.0
    assert lim.penalty > 1.0
    assert "Imperva Incapsula" in lim.waf_vendors


# ── get_limiter test-safety ───────────────────────────────────────────────────

def test_get_limiter_returns_noop_for_mock_controller():
    assert get_limiter(MagicMock()) is NOOP


def test_get_limiter_returns_real_limiter():
    ctrl = MagicMock()
    real = RateLimiter(rate_per_sec=1)
    ctrl.rate_limiter = real
    assert get_limiter(ctrl) is real


async def test_noop_never_backs_off_even_on_block():
    # The shared NOOP must stay inert: a 403 with WAF headers must not turn it
    # into a throttling limiter (regression: NOOP mutation slowed the whole suite).
    NOOP.observe_http(status=403, headers={"server": "cloudflare"})
    assert NOOP.penalty == 1.0
    assert NOOP._base_interval == 0.0
    t0 = time.monotonic()
    for _ in range(5):
        async with NOOP.guard("b"):
            pass
    assert time.monotonic() - t0 < 0.05


# ── bare-status classification (regression: 503 must NOT be a WAF) ─────────────

def test_bare_503_is_not_waf():
    # web.archive.org 503 with no WAF fingerprint must not trigger backoff.
    assert detect(status=503, headers={"server": "nginx"}) is None
    assert detect(status=503, headers={}) is None


def test_bare_403_and_406_without_vendor_are_not_waf():
    assert detect(status=403, headers={"server": "nginx"}) is None
    assert detect(status=406, headers={}) is None


def test_bare_429_is_a_ratelimit_signal():
    sig = detect(status=429, headers={"server": "nginx"})
    assert sig is not None
    assert sig.blocking is True
    assert "429" in sig.vendor


def test_cdn_503_not_block_but_waf_product_503_is():
    # A CDN 503 is a transient/origin error, NOT a firewall block.
    assert detect(status=503, headers={"server": "cloudflare", "cf-ray": "x"}) is None
    # But a 503 from a dedicated WAF product IS a block.
    sig = detect(status=503, headers={"x-iinfo": "1"})
    assert sig is not None and sig.vendor == "Imperva Incapsula" and sig.blocking is True


async def test_bare_503_does_not_back_off_limiter():
    lim = RateLimiter(rate_per_sec=10)
    for _ in range(5):
        lim.observe_http(status=503, headers={"server": "nginx"})
    assert lim.penalty == 1.0            # no backoff
    assert lim._base_interval > 0        # unchanged from its static rate


# ── parallel-engine extensions ────────────────────────────────────────────────
# (global rps/burst · per-target concurrency · per-target cooldown · Retry-After)

async def test_global_rate_bounds_aggregate_across_buckets():
    """The spec's hard rule: a worker count can't multiply the request budget.
    Many concurrent ops across DIFFERENT buckets must still obey the aggregate
    global rps, not just per-bucket spacing."""
    rate, burst, n = 20.0, 1, 24
    lim = RateLimiter(global_rate_per_sec=rate, burst=burst)

    async def op(i):
        async with lim.guard(bucket=f"host{i}"):   # every op a distinct bucket
            pass

    t0 = time.monotonic()
    await asyncio.gather(*(op(i) for i in range(n)))
    elapsed = time.monotonic() - t0
    # n tokens at `rate`/s with `burst` free ⇒ at least (n-burst)/rate seconds.
    floor = (n - burst) / rate
    assert elapsed >= floor * 0.9, f"aggregate rate exceeded: {elapsed:.3f}s < {floor:.3f}s"


async def test_burst_allows_initial_then_paces():
    lim = RateLimiter(global_rate_per_sec=5.0, burst=5)
    t0 = time.monotonic()
    for _ in range(5):                               # burst of 5 → ~immediate
        async with lim.guard(bucket="x"):
            pass
    assert time.monotonic() - t0 < 0.2


async def test_per_target_concurrency_caps_one_host_not_others():
    import asyncio as _a
    lim = RateLimiter(per_target_concurrency=2)
    active = {"a": 0}
    peak = {"a": 0}

    async def op(host, hold=0.05):
        async with lim.guard(bucket=host):
            if host == "a":
                active["a"] += 1
                peak["a"] = max(peak["a"], active["a"])
                await _a.sleep(hold)
                active["a"] -= 1
            else:
                await _a.sleep(hold)

    await _a.gather(*([op("a") for _ in range(6)] + [op("b") for _ in range(6)]))
    assert peak["a"] <= 2                            # host 'a' never exceeded its cap


async def test_per_target_cooldown_isolates_blocked_target():
    lim = RateLimiter()
    # a 429 with Retry-After on host 'a' only
    lim.observe_http(status=429, headers={"retry-after": "1"}, bucket="a")
    # 'a' is in cooldown; 'b' is not
    snap = lim.stats()
    assert "a" in snap["targets_in_cooldown"]
    assert "b" not in snap["targets_in_cooldown"]

    # 'b' passes through immediately; 'a' is delayed by the cooldown
    t0 = time.monotonic()
    async with lim.guard(bucket="b"):
        pass
    assert time.monotonic() - t0 < 0.3


async def test_retry_after_seconds_sets_cooldown_delay():
    lim = RateLimiter()
    lim.observe_http(status=429, headers={"Retry-After": "0.0"}, bucket="a")  # 0 → no delay
    # a real small delay is honoured
    lim._set_cooldown("a", 0.3)
    t0 = time.monotonic()
    async with lim.guard(bucket="a"):
        pass
    assert time.monotonic() - t0 >= 0.25


def test_retry_after_parse_http_date_and_cap():
    # delta-seconds
    assert RateLimiter._retry_after_seconds(429, {"retry-after": "30"}) == 30.0
    # non-429/503 ignored
    assert RateLimiter._retry_after_seconds(200, {"retry-after": "30"}) is None
    # garbage → None
    assert RateLimiter._retry_after_seconds(429, {"retry-after": "soon"}) is None


async def test_per_target_backoff_does_not_touch_global_penalty():
    lim = RateLimiter(rate_per_sec=10)
    lim.observe_http(status=403, headers={"x-iinfo": "1"}, bucket="a")   # WAF-product block on 'a'
    assert lim.penalty == 1.0                        # scan-wide penalty untouched
    assert "a" in lim.stats()["targets_backed_off"]


async def test_extensions_are_opt_in_and_noop_frozen():
    # unconfigured limiter: new paths are inert
    lim = RateLimiter()
    assert lim.global_rate_per_sec is None and lim.per_target_concurrency is None
    t0 = time.monotonic()
    async with lim.guard(bucket="x"):
        pass
    assert time.monotonic() - t0 < 0.05
    # frozen NOOP never adapts, even per-bucket
    NOOP.observe_http(status=429, headers={"retry-after": "100"}, bucket="a")
    assert NOOP.stats()["targets_in_cooldown"] == []
