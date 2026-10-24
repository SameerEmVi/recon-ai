"""
Centralized redaction — scrub secrets/credentials before anything is logged or
persisted. Everything diagnostic (events, HTTP exchanges, error messages) passes
through here first.

Covers (requirement §3/§6): authorization/cookie/api-key headers, URL userinfo
and sensitive query parameters, and nested JSON keys (password/token/secret/…).
Also prevents log injection by stripping control characters from any message
built from attacker-controlled input (headers, URLs, error strings).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_MASK = "***REDACTED***"

# Header names (lowercased) whose VALUES must never be logged.
_SECRET_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "auth-token",
    "x-amz-security-token", "x-csrf-token", "x-xsrf-token",
    "x-access-token", "access-token", "x-session-token", "token",
})

# Query-parameter names (lowercased) whose VALUES are sensitive.
_SECRET_PARAMS = frozenset({
    "token", "access_token", "refresh_token", "id_token", "apikey", "api_key",
    "key", "secret", "client_secret", "password", "passwd", "pwd", "pass",
    "sig", "signature", "auth", "session", "sessionid", "sid", "code",
    "sas", "sig_token", "x-amz-security-token", "awsaccesskeyid", "signature",
})

# JSON keys (lowercased, matched as substrings) whose VALUES are sensitive.
_SECRET_JSON_KEYS = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "authorization",
    "cookie", "private_key", "privatekey", "client_secret", "access_key",
    "session", "credential", "auth",
)

_MAX_MSG = 2000


def sanitize_message(msg: object, *, max_len: int = _MAX_MSG) -> str:
    """Strip control chars (log-injection defense) and cap length."""
    s = str(msg)
    out = []
    for ch in s:
        if ch in ("\n", "\r", "\t"):
            out.append(" ")
        elif ch.isprintable():
            out.append(ch)
        # else: drop non-printable / control chars
    return "".join(out)[:max_len]


def redact_headers(headers) -> dict[str, str]:
    """Return a copy of `headers` with secret header values masked."""
    out: dict[str, str] = {}
    try:
        items = headers.items() if hasattr(headers, "items") else headers
    except Exception:
        return {}
    for k, v in items:
        name = str(k)
        if name.lower() in _SECRET_HEADERS:
            out[name] = _MASK
        else:
            out[name] = sanitize_message(v, max_len=512)
    return out


def sanitize_url(url: str) -> str:
    """Strip userinfo (user:pass@) and mask sensitive query-param values.

    Keeps the URL shape intact for correlation/inspection; never leaks a token.
    Returns the input sanitized; never raises.
    """
    try:
        parts = urlsplit(str(url))
    except Exception:
        return sanitize_message(url, max_len=512)

    netloc = parts.netloc
    if "@" in netloc:                      # strip credentials in user:pass@host
        netloc = netloc.rsplit("@", 1)[-1]

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode([
            (k, _MASK if k.lower() in _SECRET_PARAMS else v) for k, v in pairs
        ])

    try:
        cleaned = urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except Exception:
        return sanitize_message(url, max_len=512)
    return sanitize_message(cleaned, max_len=1024)


def redact_json(obj, *, _depth: int = 0):
    """Recursively mask values of sensitive keys in a dict/list structure.

    Bounded recursion depth so an adversarial/cyclic structure can't blow the
    stack. Matches key names as substrings (so 'user_password' is caught).
    """
    if _depth > 12:
        return _MASK
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = str(k)
            if any(s in key.lower() for s in _SECRET_JSON_KEYS):
                out[key] = _MASK
            else:
                out[key] = redact_json(v, _depth=_depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_json(v, _depth=_depth + 1) for v in obj]
    return obj
