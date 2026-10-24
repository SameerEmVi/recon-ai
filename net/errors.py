"""
Error taxonomy — a stable category + retry-safety for every failure, instead of
catching broadly and continuing blind.

`classify_http_error(exc)` maps an httpx/OS/TLS exception to an ErrorInfo
(category, retryable, sanitized message). Categories are stable strings so
diagnostics can aggregate counts by category. The ReconError hierarchy is for
code that wants to *raise* a classified error (config/scope/dependency).

Retry policy (requirement §4): only idempotent transient transport failures are
retryable (connect/read timeouts, transient connection resets). A proxy-auth
failure, a TLS-verification failure, or a protocol error is NOT retried — those
are configuration/trust problems, retrying just repeats them.
"""

from __future__ import annotations

from dataclasses import dataclass

from net.redact import sanitize_message

# ── stable category constants ────────────────────────────────────────────────
CONFIGURATION = "ConfigurationError"
SCOPE_POLICY = "ScopePolicyError"
PROXY_CONNECTION = "ProxyConnectionError"
PROXY_AUTH = "ProxyAuthenticationError"
TLS_VERIFICATION = "TLSVerificationError"
DNS_RESOLUTION = "DNSResolutionError"
CONNECT_TIMEOUT = "ConnectTimeout"
READ_TIMEOUT = "ReadTimeout"
HTTP_PROTOCOL = "HTTPProtocolError"
RESPONSE_PARSING = "ResponseParsingError"
EXTERNAL_TOOL = "ExternalToolError"
DATABASE = "DatabaseError"
DEPENDENCY = "DependencyError"
UNEXPECTED = "UnexpectedError"


@dataclass(frozen=True)
class ErrorInfo:
    category: str
    retryable: bool
    message: str          # sanitized, safe to log

    def as_dict(self) -> dict:
        return {"error_type": self.category, "retryable": self.retryable,
                "error_message": self.message}


# ── raisable classified errors ───────────────────────────────────────────────
class ReconError(Exception):
    category: str = UNEXPECTED
    retryable: bool = False

    def info(self) -> ErrorInfo:
        return ErrorInfo(self.category, self.retryable, sanitize_message(self))


class ConfigurationError(ReconError):
    category = CONFIGURATION


class ScopePolicyError(ReconError):
    category = SCOPE_POLICY


class ProxyConnectionError(ReconError):
    category = PROXY_CONNECTION


class DependencyError(ReconError):
    category = DEPENDENCY


class ExternalToolError(ReconError):
    category = EXTERNAL_TOOL


def _is_tls_error(exc: BaseException) -> bool:
    import ssl
    if isinstance(exc, ssl.SSLError):
        return True
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(t in text for t in (
        "certificate verify failed", "ssl", "tlsv1", "self-signed",
        "self signed", "certificate", "wrong_version_number"))


def classify_http_error(exc: BaseException) -> ErrorInfo:
    """Classify a transport exception into (category, retryable, message).

    Defensive and import-light: works whether or not httpx is importable, and
    falls back to name/text heuristics for anything unrecognized.
    """
    msg = sanitize_message(f"{type(exc).__name__}: {exc}")
    name = type(exc).__name__

    try:
        import httpx
    except ImportError:
        httpx = None  # type: ignore

    # TLS first — a cert/verify failure can surface as ConnectError.
    if _is_tls_error(exc):
        return ErrorInfo(TLS_VERIFICATION, False, msg)

    if httpx is not None:
        if isinstance(exc, httpx.ProxyError):
            low = str(exc).lower()
            if any(t in low for t in ("407", "auth", "forbidden", "credential")):
                return ErrorInfo(PROXY_AUTH, False, msg)
            return ErrorInfo(PROXY_CONNECTION, False, msg)
        if isinstance(exc, httpx.ConnectTimeout):
            return ErrorInfo(CONNECT_TIMEOUT, True, msg)
        if isinstance(exc, httpx.ReadTimeout):
            return ErrorInfo(READ_TIMEOUT, True, msg)
        if isinstance(exc, (httpx.PoolTimeout, httpx.WriteTimeout)):
            return ErrorInfo(CONNECT_TIMEOUT, True, msg)
        if isinstance(exc, httpx.RemoteProtocolError):
            return ErrorInfo(HTTP_PROTOCOL, False, msg)
        if isinstance(exc, httpx.DecodingError):
            return ErrorInfo(RESPONSE_PARSING, False, msg)
        if isinstance(exc, httpx.ConnectError):
            low = str(exc).lower()
            if any(t in low for t in ("name or service not known", "nodename",
                                      "getaddrinfo", "no address", "name resolution")):
                return ErrorInfo(DNS_RESOLUTION, True, msg)
            return ErrorInfo(CONNECT_TIMEOUT, True, msg)   # transient connect failure
        if isinstance(exc, httpx.ProtocolError):
            return ErrorInfo(HTTP_PROTOCOL, False, msg)

    # Name/text heuristics for non-httpx or wrapped errors.
    low = name.lower() + " " + str(exc).lower()
    if "proxy" in low:
        return ErrorInfo(PROXY_CONNECTION, False, msg)
    if "getaddrinfo" in low or "name resolution" in low or "nodename" in low:
        return ErrorInfo(DNS_RESOLUTION, True, msg)
    if "connecttimeout" in low:
        return ErrorInfo(CONNECT_TIMEOUT, True, msg)
    if "readtimeout" in low or "timed out" in low:
        return ErrorInfo(READ_TIMEOUT, True, msg)
    return ErrorInfo(UNEXPECTED, False, msg)
