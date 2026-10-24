"""
net — shared HTTP transport configuration for the whole platform.

  * `proxy.py`  — ProxyConfig (Burp/explicit proxy, TLS trust) + get_proxy().
  * `redact.py` — centralized redaction of secrets/credentials before anything
                  is logged or persisted.
  * `errors.py` — the error taxonomy + classify() mapping transport exceptions
                  to a stable category + retry-safety.

Every outbound HTTP request is built through `BaseModule.http_client()` /
`BaseModule.fetch()`, which apply the scan's ProxyConfig, so routing all traffic
through Burp is one setting — no module opens an unconfigured client.
"""

from __future__ import annotations

from net.errors import ErrorInfo, classify_http_error
from net.proxy import ProxyConfig, get_proxy
from net.redact import redact_headers, redact_json, sanitize_message, sanitize_url

__all__ = [
    "ProxyConfig", "get_proxy",
    "redact_headers", "redact_json", "sanitize_url", "sanitize_message",
    "ErrorInfo", "classify_http_error",
]
