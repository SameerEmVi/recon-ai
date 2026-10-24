"""
DiagnosticsLogger — per-run structured JSONL diagnostics with correlation IDs.

Streams (bounded, one line per event, UTC timestamps) under <base>/diagnostics/:
  * events.jsonl      — every lifecycle/operation event (all levels)
  * errors.jsonl      — the ERROR/CRITICAL subset (fast failure triage)
  * http.jsonl        — one record per HTTP exchange (metadata only, never bodies)
  * summary.json      — final error counts by category and module

Async-safe correlation: `correlation_id` is a contextvar, so concurrent tasks
never mix request context. Everything is redacted via `net.redact` before it is
written. Never raises into the caller — an unwritable directory degrades to a
no-op (logged once to stderr via the stdlib logger), so diagnostics can never
break a scan.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import uuid
from collections import Counter
from datetime import UTC, datetime

from net.redact import redact_json, sanitize_message, sanitize_url

log = logging.getLogger("diagnostics")

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "recon_correlation_id", default=None)

# Bound each stream so a pathological scan can't fill the disk.
_MAX_LINES_PER_STREAM = 200_000

_ERROR_LEVELS = frozenset({"ERROR", "CRITICAL"})


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


@contextlib.contextmanager
def correlation(cid: str | None = None):
    """Bind a correlation id for the duration of a block (one HTTP operation)."""
    token = _correlation_id.set(cid or new_correlation_id())
    try:
        yield _correlation_id.get()
    finally:
        _correlation_id.reset(token)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class DiagnosticsLogger:
    def __init__(self, run_id: str, base_dir: str, *, proxy: str = "off",
                 debug: bool = False) -> None:
        self.run_id = str(run_id)
        self.proxy = proxy
        self.debug = debug
        self._dir = os.path.join(base_dir, "diagnostics")
        self._files: dict[str, object] = {}
        self._counts: dict[str, int] = {}
        self._by_category: Counter = Counter()
        self._by_module: Counter = Counter()
        self._errors = 0
        self._disabled = False
        try:
            os.makedirs(self._dir, exist_ok=True)
        except OSError as exc:
            log.warning("diagnostics disabled — cannot create %s: %s", self._dir, exc)
            self._disabled = True

    # ── low-level write ───────────────────────────────────────────────────────
    def _handle(self, stream: str):
        fh = self._files.get(stream)
        if fh is not None:
            return fh
        if self._counts.get(stream, 0) >= _MAX_LINES_PER_STREAM:
            return None
        try:
            fh = open(os.path.join(self._dir, f"{stream}.jsonl"), "a",
                      encoding="utf-8")
            # Best-effort tighten perms (POSIX); ignored where unsupported.
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(self._dir, f"{stream}.jsonl"), 0o600)
        except OSError as exc:
            log.debug("diagnostics: cannot open %s: %s", stream, exc)
            self._disabled = True
            return None
        self._files[stream] = fh
        return fh

    def _write(self, stream: str, record: dict) -> None:
        if self._disabled:
            return
        if self._counts.get(stream, 0) >= _MAX_LINES_PER_STREAM:
            return
        fh = self._handle(stream)
        if fh is None:
            return
        try:
            fh.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")
            fh.flush()
            self._counts[stream] = self._counts.get(stream, 0) + 1
        except (OSError, TypeError) as exc:
            log.debug("diagnostics: write to %s failed: %s", stream, exc)

    def _base(self, level: str, event: str, **fields) -> dict:
        rec = {
            "timestamp": _now(),
            "level": level,
            "event": event,
            "run_id": self.run_id,
            "correlation_id": _correlation_id.get(),
            "proxy": self.proxy,
        }
        # Sanitize well-known fields, redact everything else.
        if "target" in fields:
            rec["target"] = sanitize_url(fields.pop("target"))
        if "module" in fields:
            m = fields.pop("module")
            rec["module"] = sanitize_message(m, max_len=64) if m else None
        for k, v in fields.items():
            if v is not None:
                rec[k] = redact_json(v) if isinstance(v, (dict, list)) else v
        return rec

    # ── public API ────────────────────────────────────────────────────────────
    def event(self, level: str, event: str, **fields) -> None:
        """Record a lifecycle/operation event. ERROR/CRITICAL also → errors.jsonl."""
        level = str(level).upper()
        rec = self._base(level, event, **fields)
        self._write("events", rec)
        if level in _ERROR_LEVELS:
            self._errors += 1
            self._by_category[rec.get("error_type", event)] += 1
            if rec.get("module"):
                self._by_module[rec["module"]] += 1
            self._write("errors", rec)

    def http(self, *, module: str | None, operation: str, method: str, url: str,
             status: int | None = None, duration_ms: float | None = None,
             response_bytes: int | None = None, verify=None,
             error: dict | None = None) -> None:
        """Record one HTTP exchange (metadata only — never the body)."""
        level = "ERROR" if error else "DEBUG"
        rec = self._base(level, "http_request_failed" if error else "http_request",
                         module=module, operation=operation, target=url)
        rec.update({
            "method": str(method).upper()[:16],
            "status": status,
            "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
            "response_bytes": response_bytes,
            "tls_verify": verify if isinstance(verify, bool) else bool(verify),
        })
        if error:
            rec.update(error)
            self._errors += 1
            self._by_category[error.get("error_type", "UnexpectedError")] += 1
            if module:
                self._by_module[sanitize_message(module, max_len=64)] += 1
        self._write("http", rec)
        if error:
            self._write("errors", rec)

    @property
    def error_count(self) -> int:
        return self._errors

    def summary(self) -> dict:
        s = {
            "run_id": self.run_id,
            "generated_at": _now(),
            "total_errors": self._errors,
            "errors_by_category": dict(self._by_category),
            "errors_by_module": dict(self._by_module),
            "streams": dict(self._counts),
        }
        self._write("summary", s)   # also persisted as one line
        try:
            if not self._disabled:
                with open(os.path.join(self._dir, "summary.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump(s, fh, indent=2)
        except OSError:
            pass
        return s

    def close(self) -> None:
        for fh in self._files.values():
            with contextlib.suppress(Exception):
                fh.close()
        self._files.clear()

    @property
    def directory(self) -> str:
        return self._dir


class _NoopDiagnostics:
    """Shared no-op used for mock/unconfigured controllers (test-safety)."""
    run_id = "noop"
    proxy = "off"
    debug = False
    error_count = 0
    directory = ""

    def event(self, *a, **k) -> None: ...
    def http(self, *a, **k) -> None: ...
    def summary(self) -> dict: return {}
    def close(self) -> None: ...


NOOP_DIAGNOSTICS = _NoopDiagnostics()


def get_diagnostics(obj):
    """Return obj.diagnostics if it's a real DiagnosticsLogger, else the no-op."""
    d = getattr(obj, "diagnostics", None)
    return d if isinstance(d, DiagnosticsLogger) else NOOP_DIAGNOSTICS
