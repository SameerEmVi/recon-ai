"""
Turn a raw request/response into a safe, persistable `HttpExchange`.

`build_exchange` is the single place a captured exchange is assembled, so every
row is redacted and size-capped the same way regardless of which tool captured
it:

  - URL is run through `net.redact.sanitize_url` (userinfo + sensitive query
    params stripped); headers through `redact_headers` (secret headers masked) —
    before anything is stored, so secrets never land on disk even in ciphertext.
  - Bodies are capped at `MAX_BODY_BYTES` (response truncation is flagged) and
    encrypted with the scan's `EvidenceCipher`. With encryption disabled (no key)
    the bodies are dropped and `bodies_dropped` records why — the store degrades
    to redacted-metadata-only rather than writing plaintext.

`exchange_for_display` is the inverse for the authorized operator's UI: it
decrypts the bodies (when the key is available) and never returns ciphertext. The
LLM path uses the row's metadata only and must not call this.
"""

from __future__ import annotations

from dataclasses import dataclass

from database.models import HttpExchange
from evidence.crypto import EvidenceCipher
from net.redact import redact_headers, sanitize_url

# Per-body cap. A pentest proof rarely needs more than this, and it bounds the
# evidence DB. The request body is kept whole up to the cap; an over-cap response
# body is truncated (and flagged) rather than dropped, so the proof is preserved.
MAX_BODY_BYTES = 512 * 1024


def _as_bytes(body: str | bytes | None) -> bytes | None:
    if body is None:
        return None
    return body if isinstance(body, bytes) else body.encode("utf-8", "replace")


@dataclass(frozen=True)
class CapturedExchange:
    """The raw material for one exchange, before redaction/encryption."""

    host: str
    method: str
    url: str
    status_code: int | None = None
    request_headers: dict | None = None
    response_headers: dict | None = None
    request_body: str | bytes | None = None
    response_body: str | bytes | None = None
    duration_ms: float | None = None
    source_tool: str | None = None


def build_exchange(
    captured: CapturedExchange,
    cipher: EvidenceCipher,
    *,
    scan_id,
    finding_id=None,
) -> HttpExchange:
    """Assemble a persistable, redacted, (optionally) encrypted `HttpExchange`."""
    req = _as_bytes(captured.request_body)
    resp = _as_bytes(captured.response_body)
    req_size = len(req) if req is not None else None
    resp_size = len(resp) if resp is not None else None

    # Cap bodies (preserve the proof: truncate the response rather than drop it).
    truncated = False
    if req is not None and len(req) > MAX_BODY_BYTES:
        req = req[:MAX_BODY_BYTES]
    if resp is not None and len(resp) > MAX_BODY_BYTES:
        resp = resp[:MAX_BODY_BYTES]
        truncated = True

    enc_req = enc_resp = None
    encrypted = False
    dropped: str | None = None
    if req is None and resp is None:
        pass                                   # nothing to store; not a "drop"
    elif cipher.enabled:
        enc_req = cipher.encrypt(req) if req is not None else None
        enc_resp = cipher.encrypt(resp) if resp is not None else None
        encrypted = True
    else:
        dropped = "evidence key not configured (RECON_AI_EVIDENCE_KEY) — bodies not stored"

    return HttpExchange(
        scan_job_id=scan_id,
        finding_id=finding_id,
        host=captured.host,
        method=(captured.method or "GET").upper()[:16],
        url=sanitize_url(captured.url),
        status_code=captured.status_code,
        request_headers=redact_headers(captured.request_headers or {}) or None,
        response_headers=redact_headers(captured.response_headers or {}) or None,
        request_body=enc_req,
        response_body=enc_resp,
        body_encrypted=encrypted,
        bodies_dropped=dropped,
        request_size=req_size,
        response_size=resp_size,
        response_truncated=truncated,
        duration_ms=captured.duration_ms,
        source_tool=captured.source_tool,
    )


def exchange_from_fetch(
    result,
    *,
    host: str,
    source_tool: str,
    method: str = "GET",
    request_headers: dict | None = None,
    duration_ms: float | None = None,
) -> CapturedExchange:
    """Build a CapturedExchange from a recon.fetch.FetchResult (a GET snapshot:
    status, response headers, body text). The verbatim response body is the
    proof; request body is None for a GET."""
    return CapturedExchange(
        host=host,
        method=method,
        url=getattr(result, "url", "") or "",
        status_code=getattr(result, "status_code", None),
        request_headers=request_headers,
        response_headers=dict(getattr(result, "headers", {}) or {}),
        request_body=None,
        response_body=getattr(result, "text", None),
        duration_ms=duration_ms,
        source_tool=source_tool,
    )


async def record_exchange(controller, captured: CapturedExchange, *, finding_id=None):
    """Capture-and-store glue: build the (redacted, encrypted) exchange and
    persist it. The single entry point a tool/check calls after a request.

    Off-by-default and never raises: returns None when there is no evidence key
    (bodies-not-stored would still persist metadata, but we only record when the
    operator opted into the evidence store), no persister (no --db-url), or any
    failure. Returns the stored exchange id otherwise (for later finding-link)."""
    from evidence.crypto import get_cipher

    cipher = get_cipher(controller)
    persister = getattr(controller, "persister", None)
    if not cipher.enabled or persister is None:
        return None
    try:
        scan_id = getattr(controller, "scan_id", None)
        exchange = build_exchange(captured, cipher, scan_id=scan_id, finding_id=finding_id)
        return await persister.save_exchange(exchange)
    except Exception:
        return None


def _decrypt_text(blob, cipher: EvidenceCipher, encrypted: bool) -> str | None:
    if blob is None:
        return None
    if not encrypted:
        return None                            # unexpected; never expose raw ciphertext
    if not cipher.enabled:
        return None                            # no key here; can't show the body
    try:
        return cipher.decrypt(blob).decode("utf-8", "replace")
    except Exception:
        return None


def exchange_for_display(row: HttpExchange, cipher: EvidenceCipher) -> dict:
    """A redacted-safe, operator-facing view: metadata + decrypted body text (or
    None when the key is absent). Never returns ciphertext; not for the LLM."""
    return {
        "id": str(row.id),
        "finding_id": str(row.finding_id) if row.finding_id else None,
        "host": row.host,
        "method": row.method,
        "url": row.url,
        "status_code": row.status_code,
        "request_headers": row.request_headers or {},
        "response_headers": row.response_headers or {},
        "request_body": _decrypt_text(row.request_body, cipher, row.body_encrypted),
        "response_body": _decrypt_text(row.response_body, cipher, row.body_encrypted),
        "request_size": row.request_size,
        "response_size": row.response_size,
        "response_truncated": row.response_truncated,
        "bodies_available": bool((row.request_body or row.response_body) and cipher.enabled),
        "bodies_dropped": row.bodies_dropped,
        "duration_ms": row.duration_ms,
        "source_tool": row.source_tool,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
