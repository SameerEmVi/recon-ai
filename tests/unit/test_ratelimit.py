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


def test_waf_detect_cloudflare_header_presence_not_blocking():
    sig = detect(status=200, headers={"Server": "cloudflare", "CF-RAY": "abc"})
    assert sig is not None
    assert sig.vendor == "Cloudflare"
    assert sig.blocking is False


def test_waf_detect_blocking_status():
    sig = detect(status=403, headers={"Server": "cloudflare"})
    assert sig is not None
    assert sig.blocking is True
    assert sig.status == 403


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
    lim.observe_http(status=403, headers={"server": "cloudflare"})
    # a WAF block now creates a real interval so guard() actually slows down
    assert lim._base_interval > 0.0
    assert lim.penalty > 1.0
    assert "Cloudflare" in lim.waf_vendors


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


def test_vendor_503_is_still_a_waf_block():
    # A Cloudflare 503 IS a WAF block (vendor fingerprint present).
    sig = detect(status=503, headers={"server": "cloudflare", "cf-ray": "x"})
    assert sig is not None and sig.vendor == "Cloudflare" and sig.blocking is True


async def test_bare_503_does_not_back_off_limiter():
    lim = RateLimiter(rate_per_sec=10)
    for _ in range(5):
        lim.observe_http(status=503, headers={"server": "nginx"})
    assert lim.penalty == 1.0            # no backoff
    assert lim._base_interval > 0        # unchanged from its static rate
