"""
dnsbrute — wildcard-recovery decision logic (pure helpers) + capability wiring.

The HTTP wildcard-recovery pass keeps a wildcard-covered name only when its HTTP
response is provably different from the wildcard's own baseline response. These
tests pin that decision (so `smtp/webmail/cpanel` on an identical-content
CloudFront wildcard stay dropped, while a content-distinct host is recovered).
"""

from __future__ import annotations

from modules.active.dnsbrute import DnsBruteModule, is_distinct, response_signature
from policy import CAP_ACTIVE_DISCOVERY, CAP_TARGET_HTTP_REQUEST


# ── response_signature ────────────────────────────────────────────────────────

def test_signature_none_status_is_none():
    assert response_signature(None, "body") is None


def test_signature_same_body_same_sig():
    a = response_signature(200, "hello world")
    b = response_signature(200, "hello world")
    assert a == b and a is not None


def test_signature_differs_on_body_and_status():
    assert response_signature(200, "a") != response_signature(200, "b")
    assert response_signature(200, "a") != response_signature(404, "a")
    # empty vs None body collapse to the same (both hash "")
    assert response_signature(200, None) == response_signature(200, "")


# ── is_distinct: stable wildcard (both baseline probes identical) ─────────────

def _sig(status, body):
    return response_signature(status, body)


def test_stable_identical_content_is_not_distinct():
    base = _sig(200, "WILDCARD PAGE")
    baseline = [base, base]
    # smtp/webmail/cpanel case: same status + same body as the wildcard
    host = _sig(200, "WILDCARD PAGE")
    assert is_distinct(host, baseline, stable=True) is False


def test_stable_different_content_is_distinct():
    baseline = [_sig(200, "WILDCARD PAGE"), _sig(200, "WILDCARD PAGE")]
    host = _sig(200, "REAL API — different body")
    assert is_distinct(host, baseline, stable=True) is True


def test_stable_different_status_is_distinct():
    baseline = [_sig(200, "WILDCARD PAGE"), _sig(200, "WILDCARD PAGE")]
    assert is_distinct(_sig(401, "WILDCARD PAGE"), baseline, stable=True) is True


# ── is_distinct: dynamic wildcard (baseline probes differ → status-only) ──────

def test_dynamic_same_status_is_not_distinct():
    # Wildcard returns 200 with per-request nonce (bodies differ) → unstable.
    baseline = [_sig(200, "nonce-aaa"), _sig(200, "nonce-bbb")]
    # A covered host also returns 200 (different body) — can't trust the body diff.
    assert is_distinct(_sig(200, "nonce-ccc"), baseline, stable=False) is False


def test_dynamic_novel_status_is_distinct():
    baseline = [_sig(200, "nonce-aaa"), _sig(200, "nonce-bbb")]
    assert is_distinct(_sig(403, "forbidden"), baseline, stable=False) is True


# ── guards: no response / empty baseline never resurrect a host ───────────────

def test_no_host_response_is_not_distinct():
    baseline = [_sig(200, "x"), _sig(200, "x")]
    assert is_distinct(None, baseline, stable=True) is False


def test_empty_baseline_is_not_distinct():
    assert is_distinct(_sig(200, "x"), [None, None], stable=False) is False
    assert is_distinct(_sig(200, "x"), [], stable=True) is False


# ── capability wiring: HTTP recovery means dnsbrute declares the HTTP cap ──────

def test_dnsbrute_declares_active_and_http_capabilities():
    caps = DnsBruteModule.capabilities
    assert CAP_ACTIVE_DISCOVERY in caps and CAP_TARGET_HTTP_REQUEST in caps
