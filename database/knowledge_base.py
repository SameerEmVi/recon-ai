"""
KnowledgeBase — the persistent reconnaissance learning service.

Sits on top of ``VocabularyRepository`` and runs the learn pipeline:

    normalization → quality-filter → (multi-scope) dedup → scoring → persistence

A learned string is a *candidate* — a proposal for future wordlists. It is never
treated as proof that a resource exists (requirement #10). Confidence reflects
how reusable a token looks (breadth across targets + frequency), not existence.

Every candidate is learned into up to four knowledge scopes (requirement: create
multiple knowledge scopes):

    global        — across all targets/technologies
    target        — the scan's seed domain
    technology     — the candidate's technology context (if any)
    organization  — an operator-supplied program/org label (if given & distinct)

Writes are serialized by the caller (the controller gives the KB its own
AsyncSession and only one scan runs against it at a time); uniqueness is
additionally DB-enforced so counts can't be duplicated or lost.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from database.models import VocabularyItem
from database.repository import VocabularyRepository
from recon import vocabulary
from recon.vocabulary import (
    SCOPE_GLOBAL,
    SCOPE_ORGANIZATION,
    SCOPE_TARGET,
    SCOPE_TECHNOLOGY,
    Candidate,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LearnResult:
    value: str
    category: str
    scope_type: str
    scope_key: str
    novelty: str      # "NEW" | "KNOWN"
    confidence: float


class KnowledgeBase:
    def __init__(self, session: AsyncSession) -> None:
        self._repo = VocabularyRepository(session)
        self._session = session
        # A single AsyncSession is not safe for concurrent use. The bus fans out
        # events to handlers as parallel tasks, so wordlist_learner may call
        # learn() while extfuzz calls generate_wordlist() — *both* touch this one
        # session. Serialize EVERY session access (reads and writes alike) through
        # this lock; a read racing a write otherwise raises "concurrent operations
        # are not permitted". Same discipline as database.persister.Persister.
        self._lock = asyncio.Lock()

    # ── learning ────────────────────────────────────────────────────────────

    async def learn(
        self,
        candidate: Candidate,
        *,
        scan_domain: str | None = None,
        organization: str | None = None,
        source_scan_id: UUID | None = None,
        source_event_id: UUID | None = None,
    ) -> list[LearnResult]:
        """Normalize, quality-filter and persist one candidate across all scopes.

        Returns one LearnResult per scope it was written to (empty if the
        candidate was rejected by normalization or the quality gate)."""
        value = vocabulary.normalize(candidate.value, candidate.category)
        if not value or not vocabulary.is_quality(value, candidate.category):
            return []

        target = (scan_domain or "").strip().lower()
        results: list[LearnResult] = []

        # scope_type, scope_key
        scopes: list[tuple[str, str]] = [(SCOPE_GLOBAL, "")]
        if target:
            scopes.append((SCOPE_TARGET, target))
        if candidate.context:
            tech = candidate.context.strip().lower()
            if tech:
                scopes.append((SCOPE_TECHNOLOGY, tech))
        if organization:
            org = organization.strip().lower()
            if org and org != target:
                scopes.append((SCOPE_ORGANIZATION, org))

        async with self._lock:
            for scope_type, scope_key in scopes:
                try:
                    res = await self._learn_one(
                        scope_type, scope_key, candidate, value, target or "unknown",
                        source_scan_id, source_event_id,
                    )
                except Exception as exc:
                    log.debug("kb: learn failed (%s) — rolling back", exc)
                    await self._session.rollback()
                    continue
                if res:
                    results.append(res)
        return results

    async def learn_many(self, candidates: list[Candidate], **kwargs) -> list[LearnResult]:
        out: list[LearnResult] = []
        for c in candidates:
            out.extend(await self.learn(c, **kwargs))
        return out

    async def _learn_one(
        self,
        scope_type: str,
        scope_key: str,
        candidate: Candidate,
        value: str,
        target: str,
        source_scan_id: UUID | None,
        source_event_id: UUID | None,
    ) -> LearnResult | None:
        category = candidate.category
        is_new_target = await self._repo.target_seen(scope_type, scope_key, category, value, target)

        existing = await self._repo.get_item(scope_type, scope_key, category, value)
        now = datetime.now(UTC)

        if existing is None:
            conf = vocabulary.confidence(1, 1)
            item = VocabularyItem(
                scope_type=scope_type, scope_key=scope_key,
                category=category, value=value,
                occurrence_count=1, target_count=1, confidence=conf,
                context=candidate.context, first_seen=now, last_seen=now,
                source_scan_id=source_scan_id, source_event_id=source_event_id,
                source_url=candidate.source_url,
            )
            inserted = await self._repo.add_item(item)
            if inserted:
                return LearnResult(value, category, scope_type, scope_key, "NEW", conf)
            # Lost an insert race — fall through to update the now-existing row.
            existing = await self._repo.get_item(scope_type, scope_key, category, value)
            if existing is None:
                return None

        # Update path (KNOWN).
        existing.occurrence_count += 1
        if is_new_target:
            existing.target_count += 1
        existing.confidence = vocabulary.confidence(existing.target_count, existing.occurrence_count)
        existing.last_seen = now
        await self._repo.save_item(existing)
        return LearnResult(value, category, scope_type, scope_key, "KNOWN", existing.confidence)

    # ── wordlist generation / export ──────────────────────────────────────────

    async def generate_wordlist(
        self,
        category: str,
        *,
        scope_type: str = SCOPE_GLOBAL,
        scope_key: str = "",
        min_target_count: int = 1,
        min_occurrence: int = 1,
        min_confidence: float = 0.0,
        limit: int | None = None,
    ) -> list[str]:
        """Build a target-appropriate wordlist for one category+scope.

        Ordering is deterministic (breadth → frequency → confidence → value) and
        the filters let callers demand a minimum breadth/frequency/confidence.
        This is *not* the whole global KB dumped to a file — it is a ranked,
        filtered selection. The resulting words are candidates for probing, never
        assertions that any of them exist."""
        async with self._lock:
            rows = await self._repo.list_items(
                scope_type, scope_key, category,
                min_target_count=min_target_count,
                min_occurrence=min_occurrence,
                min_confidence=min_confidence,
                limit=limit,
            )
        return [r.value for r in rows]

    async def export_to_file(self, category: str, path: str, **kwargs) -> int:
        """Write a generated wordlist to `path` (one token per line). Returns the
        number of words written. The file can be consumed directly by the
        ffuf module via its ``wordlist=<path>`` option."""
        words = await self.generate_wordlist(category, **kwargs)
        with open(path, "w", encoding="utf-8") as fh:
            for w in words:
                fh.write(w + "\n")
        return len(words)

    # Path-shaped categories worth promoting into a content-discovery wordlist
    # (parameters / param-values / api-versions are not path tokens, so excluded).
    _PATH_CATEGORIES: tuple[str, ...] = (
        vocabulary.DIRECTORIES, vocabulary.FILES, vocabulary.ENDPOINTS,
        vocabulary.API_PATHS, vocabulary.RESOURCE_NAMES,
    )

    async def export_discovered_paths(
        self,
        out_path: str,
        *,
        exclude_file: str | None = None,
        scope_type: str = SCOPE_GLOBAL,
        scope_key: str = "",
        min_confidence: float = 0.0,
        limit_per_category: int | None = None,
    ) -> int:
        """Write a REVIEW BACKLOG of learned path tokens that are NOT already in a
        generic wordlist (`exclude_file`, e.g. wordlists/combined.txt), ranked by
        the KB's breadth/frequency/confidence ordering.

        This is the manual-promote workflow: the generic list stays generic and is
        NEVER written here — you review this backlog and move the good tokens into
        the generic list yourself. Returns the count written. Never raises on an
        unwritable/unreadable path side (caller may still see OSError on open)."""
        import os

        have: set[str] = set()
        if exclude_file:
            try:
                with open(exclude_file, encoding="utf-8") as fh:
                    have = {
                        ln.strip().lower() for ln in fh
                        if ln.strip() and not ln.lstrip().startswith("#")
                    }
            except OSError:
                have = set()

        seen: set[str] = set()
        rows: list[str] = []
        for cat in self._PATH_CATEGORIES:
            for w in await self.generate_wordlist(
                cat, scope_type=scope_type, scope_key=scope_key,
                min_confidence=min_confidence, limit=limit_per_category,
            ):
                key = w.strip().lower()
                if not key or key in have or key in seen:
                    continue
                seen.add(key)
                rows.append(w)

        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("# Recon-AI — discovered paths pending review (NOT auto-merged).\n")
            fh.write("# Learned path tokens not already in the generic wordlist.\n")
            fh.write("# Review these, then promote the good ones into the generic "
                     "wordlist (e.g. wordlists/combined.txt) yourself.\n")
            for w in rows:
                fh.write(w + "\n")
        return len(rows)

    async def stats(
        self, scope_type: str | None = None, scope_key: str | None = None
    ) -> dict:
        async with self._lock:
            return await self._repo.stats(scope_type, scope_key)
