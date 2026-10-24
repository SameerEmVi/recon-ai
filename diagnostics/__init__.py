"""
diagnostics — structured, persistent run diagnostics (JSON Lines).

A `DiagnosticsLogger` is created per scan (owned by ScanController, exposed as
`controller.diagnostics`). It writes correlated, redacted events to a per-run
directory so a failed operation can be investigated after the scan finishes.

All field values pass through `net.redact` before hitting disk, so secrets /
credentials / sensitive query params never land in a log.
"""

from __future__ import annotations

from diagnostics.logger import (
    NOOP_DIAGNOSTICS,
    DiagnosticsLogger,
    correlation,
    get_diagnostics,
    new_correlation_id,
)

__all__ = [
    "DiagnosticsLogger", "get_diagnostics", "correlation",
    "new_correlation_id", "NOOP_DIAGNOSTICS",
]
