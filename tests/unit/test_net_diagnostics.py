"""
Tests for the net/ (proxy, redaction, error taxonomy) and diagnostics/ layers.

Hermetic — no real network. Proxy behaviour is covered via config/kwargs and a
mock; redaction and error classification are pure.
"""

from __future__ import annotations

import json

import httpx
import pytest

from diagnostics.logger import DiagnosticsLogger, correlation, get_diagnostics
from net.errors import (
    CONNECT_TIMEOUT,
    DNS_RESOLUTION,
    PROXY_CONNECTION,
    READ_TIMEOUT,
    TLS_VERIFICATION,
    classify_http_error,
)
from net.proxy import DISABLED, ProxyConfig, get_proxy
from net.redact import redact_headers, redact_json, sanitize_message, sanitize_url


# ── redaction ─────────────────────────────────────────────────────────────────

def test_redact_headers_masks_secrets_keeps_others():
    out = redact_headers({"Authorization": "Bearer abc", "Cookie": "s=1",
                          "User-Agent": "recon", "X-Api-Key": "k"})
    assert out["Authorization"] == "***REDACTED***"
    assert out["Cookie"] == "***REDACTED***"
    assert out["X-Api-Key"] == "***REDACTED***"
    assert out["User-Agent"] == "recon"


def test_sanitize_url_strips_userinfo_and_masks_token():
    u = sanitize_url("https://user:pass@api.example.com/x?token=SEKRET&page=2")
    assert "user:pass@" not in u and "pass" not in u
    assert "SEKRET" not in u and "REDACTED" in u   # token value masked (url-encoded mask)
    assert "token=" in u and "page=2" in u


def test_redact_json_nested_keys():
    obj = {"ok": 1, "password": "p", "nested": {"api_key": "k", "list": [{"secret": "s"}]}}
    r = redact_json(obj)
    assert r["ok"] == 1
    assert r["password"] == "***REDACTED***"
    assert r["nested"]["api_key"] == "***REDACTED***"
    assert r["nested"]["list"][0]["secret"] == "***REDACTED***"


def test_redact_json_depth_bounded():
    # Deeply nested structure must not blow the stack.
    d = cur = {}
    for _ in range(50):
        cur["next"] = {}
        cur = cur["next"]
    assert redact_json(d) is not None


def test_sanitize_message_strips_control_chars():
    assert sanitize_message("line1\nline2\r\x00evil") == "line1 line2 evil"


# ── error taxonomy ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc,cat,retry", [
    (httpx.ConnectTimeout("x"), CONNECT_TIMEOUT, True),
    (httpx.ReadTimeout("x"), READ_TIMEOUT, True),
    (httpx.ProxyError("407 auth required"), "ProxyAuthenticationError", False),
    (httpx.ProxyError("connection refused"), PROXY_CONNECTION, False),
    (httpx.ConnectError("getaddrinfo failed"), DNS_RESOLUTION, True),
])
def test_classify_http_error(exc, cat, retry):
    info = classify_http_error(exc)
    assert info.category == cat and info.retryable is retry


def test_classify_tls_error_not_retryable():
    import ssl
    info = classify_http_error(ssl.SSLError("certificate verify failed"))
    assert info.category == TLS_VERIFICATION and info.retryable is False


# ── proxy config ──────────────────────────────────────────────────────────────

def test_proxy_disabled_default_is_direct_and_verifies():
    p = ProxyConfig()
    assert not p.active
    assert p.client_kwargs() == {"verify": True}   # TLS on, no proxy key


def test_proxy_from_cli_builds_active_config():
    p = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080")
    assert p.active and p.client_kwargs()["proxy"] == "http://127.0.0.1:8080"
    assert p.client_kwargs()["verify"] is True


def test_proxy_precedence_cli_over_env():
    p = ProxyConfig.from_sources(cli_proxy="http://cli:8080",
                                 env={"RECON_AI_PROXY": "http://env:9090"})
    assert p.url == "http://cli:8080"


def test_proxy_env_used_when_no_cli():
    p = ProxyConfig.from_sources(env={"RECON_AI_PROXY": "http://env:9090"})
    assert p.url == "http://env:9090" and p.active


def test_proxy_invalid_url_raises():
    from net.errors import ConfigurationError
    with pytest.raises(ConfigurationError):
        ProxyConfig.from_sources(cli_proxy="127.0.0.1:8080")  # missing scheme


def test_proxy_missing_ca_raises():
    from net.errors import ConfigurationError
    with pytest.raises(ConfigurationError):
        ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080",
                                 cli_ca="/no/such/ca.pem")


def test_proxy_insecure_disables_verify_explicitly():
    # --proxy-insecure → verify off (explicit; for Burp CAs that strict OpenSSL
    # rejects, e.g. missing keyUsage). Never the silent default.
    p = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080", cli_verify=False)
    assert p.active and p.client_kwargs()["verify"] is False
    assert "verify=OFF" in p.describe()
    # Default stays ON.
    assert ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080").verify is True


def test_proxy_ca_bundle_sets_verify_to_path(tmp_path):
    ca = tmp_path / "burp.pem"
    ca.write_text("---CERT---", encoding="utf-8")
    p = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080", cli_ca=str(ca))
    assert p.client_kwargs()["verify"] == str(ca)


def test_get_proxy_test_safety():
    from types import SimpleNamespace
    assert get_proxy(SimpleNamespace()) is DISABLED
    cfg = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:8080")
    assert get_proxy(SimpleNamespace(proxy=cfg)) is cfg


async def test_proxy_probe_disabled_is_ok():
    ok, msg = await ProxyConfig().probe()
    assert ok and "disabled" in msg


async def test_proxy_probe_unreachable_reports_classified_error():
    # Nothing listens on this port → classified failure, never raises.
    p = ProxyConfig.from_sources(cli_proxy="http://127.0.0.1:1")
    ok, msg = await p.probe(timeout=2)
    assert ok is False and msg


# ── diagnostics logger ────────────────────────────────────────────────────────

def _read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_diagnostics_writes_events_and_errors(tmp_path):
    d = DiagnosticsLogger("run-1", str(tmp_path), proxy="http://127.0.0.1:8080")
    d.event("INFO", "scan_start", module="controller", target="https://x.com")
    d.event("ERROR", "module_failed", module="ffuf", error_type="ExternalToolError")
    d.summary()
    d.close()

    events = _read(tmp_path / "diagnostics" / "events.jsonl")
    errors = _read(tmp_path / "diagnostics" / "errors.jsonl")
    assert len(events) == 2 and len(errors) == 1
    assert events[0]["run_id"] == "run-1" and events[0]["proxy"] == "http://127.0.0.1:8080"
    assert d.error_count == 1
    summary = json.loads((tmp_path / "diagnostics" / "summary.json").read_text())
    assert summary["total_errors"] == 1
    assert summary["errors_by_category"]["ExternalToolError"] == 1


def test_diagnostics_redacts_and_sanitizes(tmp_path):
    d = DiagnosticsLogger("r", str(tmp_path))
    with correlation("corr-123"):
        d.http(module="secretfinder", operation="fetch", method="GET",
               url="https://user:pw@x.com/a?token=SEKRET", status=200,
               duration_ms=12.3, response_bytes=100, verify=True)
    d.close()
    rec = _read(tmp_path / "diagnostics" / "http.jsonl")[0]
    assert rec["correlation_id"] == "corr-123"
    assert "SEKRET" not in rec["target"] and "pw@" not in rec["target"]
    assert rec["status"] == 200 and rec["tls_verify"] is True


def test_diagnostics_unwritable_dir_degrades(tmp_path):
    # Point base at a path under a FILE → makedirs fails → disabled, never raises.
    f = tmp_path / "afile"
    f.write_text("x", encoding="utf-8")
    d = DiagnosticsLogger("r", str(f / "sub"))
    d.event("INFO", "x")        # must not raise
    d.http(module="m", operation="o", method="GET", url="https://x.com")
    assert d.summary() == {} or isinstance(d.summary(), dict)


def test_get_diagnostics_test_safety():
    from types import SimpleNamespace
    from diagnostics.logger import NOOP_DIAGNOSTICS
    assert get_diagnostics(SimpleNamespace()) is NOOP_DIAGNOSTICS
