"""
Shared server-level state.

Scans launched via start_scan run as asyncio background tasks.
Their status is tracked here so get_scan_status can report progress
without the client needing to block on the scan completing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class ScanEntry:
    scan_id: str
    domain: str
    status: str = "running"  # "running" | "complete" | "failed"
    event_count: int = 0
    error: str = ""


_scans: dict[str, ScanEntry] = {}


def register_scan(scan_id: str, domain: str) -> ScanEntry:
    entry = ScanEntry(scan_id=scan_id, domain=domain)
    _scans[scan_id] = entry
    return entry


def get_scan_entry(scan_id: str) -> ScanEntry | None:
    return _scans.get(scan_id)


def complete_scan(scan_id: str, event_count: int) -> None:
    if scan_id in _scans:
        _scans[scan_id].status = "complete"
        _scans[scan_id].event_count = event_count


def fail_scan(scan_id: str, error: str) -> None:
    if scan_id in _scans:
        _scans[scan_id].status = "failed"
        _scans[scan_id].error = str(error)[:500]


def get_db_url() -> str | None:
    return os.environ.get("RECON_AI_DB_URL")


def get_api_key() -> str | None:
    return os.environ.get("ANTHROPIC_API_KEY")
