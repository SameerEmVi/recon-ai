"""
Scan-to-scan diff — compare two completed scans of the same target.

Design: compare dedup_key sets per event type. Same key = same logical entity
(same subdomain, same URL, same port, etc.) regardless of when it was found.
New = in scan B but not A. Gone = in A but not B.

This is the foundation for the AI triage layer (Phase 3) which will reason
about what changed, not just that it changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from events.types import EventType


@dataclass
class TypeDiff:
    event_type: EventType
    new_keys: set[str] = field(default_factory=set)
    gone_keys: set[str] = field(default_factory=set)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_keys or self.gone_keys)

    def __str__(self) -> str:
        return f"{self.event_type.value}: +{len(self.new_keys)} new, -{len(self.gone_keys)} gone"


@dataclass
class ScanDiff:
    scan_a: UUID   # baseline (older)
    scan_b: UUID   # current (newer)
    diffs: list[TypeDiff] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(d.has_changes for d in self.diffs)

    @property
    def total_new(self) -> int:
        return sum(len(d.new_keys) for d in self.diffs)

    @property
    def total_gone(self) -> int:
        return sum(len(d.gone_keys) for d in self.diffs)

    def for_type(self, event_type: EventType) -> TypeDiff | None:
        for d in self.diffs:
            if d.event_type is event_type:
                return d
        return None

    def summary(self) -> str:
        if not self.has_changes:
            return f"no changes between {self.scan_a} and {self.scan_b}"
        lines = [f"diff  {self.scan_a}  →  {self.scan_b}"]
        for d in self.diffs:
            if d.has_changes:
                lines.append(f"  {d}")
        lines.append(f"  total: +{self.total_new} new, -{self.total_gone} gone")
        return "\n".join(lines)


async def compute_diff(
    event_repo: "EventRepository",  # type: ignore[name-defined]
    scan_a: UUID,
    scan_b: UUID,
    types: list[EventType] | None = None,
) -> ScanDiff:
    """Compare two scans by event type. O(n) — fetches dedup_key sets only."""
    from database.repository import EventRepository  # local import avoids circular
    assert isinstance(event_repo, EventRepository)

    if types is None:
        types = list(EventType)

    diffs = []
    for et in types:
        keys_a = await event_repo.dedup_keys(scan_a, et)
        keys_b = await event_repo.dedup_keys(scan_b, et)
        diffs.append(TypeDiff(
            event_type=et,
            new_keys=keys_b - keys_a,
            gone_keys=keys_a - keys_b,
        ))
    return ScanDiff(scan_a=scan_a, scan_b=scan_b, diffs=diffs)
