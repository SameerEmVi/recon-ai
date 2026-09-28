"""
wordlist_learner — the event-driven front end of the persistent reconnaissance
learning system.

Watches the discovery events the bus has already scope-checked (URL, ENDPOINT,
PARAMETER, TECHNOLOGY), extracts reusable vocabulary candidates with the pure
`recon.vocabulary` engine, and learns them into the cross-scan `KnowledgeBase`
(directories, files, endpoints, api paths/versions, parameters, safe param
values, resource names, and — from technologies — technology-scoped tokens).

Deterministic and network-free: it only consumes events other modules already
produced; it never fetches anything or asserts a resource exists. Needs
``--db-url`` (the controller only builds a KnowledgeBase when persistence is on);
without it the module warn-and-skips and the scan is otherwise unchanged.

In the DISCOVERY group / ``--full``; ``-m wordlist_learner`` to run it alone.
"""

from __future__ import annotations

import urllib.parse

from events.types import Event, EventType
from modules.base import BaseModule
from modules.registry import register
from recon import vocabulary


@register
class WordlistLearnerModule(BaseModule):
    name = "wordlist_learner"
    description = "Learns reusable recon vocabulary from discoveries into the persistent knowledge base"
    watched_events = ["URL", "ENDPOINT", "PARAMETER", "TECHNOLOGY"]
    produced_events = []          # a learner, not an emitter
    flags = ["passive", "web", "discovery", "learning"]
    options = {
        # Group learned vocabulary under a program/organization label so the KB
        # can accumulate an organization-scoped wordlist across many targets.
        # Optional — leave unset to use only global/target/technology scopes.
        "organization": None,
        # Cap candidates extracted per event so a pathological URL can't flood.
        "max_candidates_per_event": 64,
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        # host -> a representative technology name, learned from TECHNOLOGY events,
        # used to tag that host's path/param candidates into the technology scope.
        self._tech_by_host: dict[str, str] = {}

    async def setup(self) -> bool:
        if getattr(self._ctrl, "knowledge_base", None) is None:
            self._log.warning("no knowledge base (needs --db-url) — module disabled")
            return False
        return True

    # ── event handling ────────────────────────────────────────────────────────

    async def handle_event(self, event: Event) -> None:
        kb = self._ctrl.knowledge_base
        if kb is None:
            return

        candidates = self._extract(event)
        if not candidates:
            return
        cap = int(self.opt("max_candidates_per_event") or 64)

        await kb.learn_many(
            candidates[:cap],
            scan_domain=self._ctrl.scan_domain,
            organization=self.opt("organization"),
            source_scan_id=self._ctrl.scan_id,
            source_event_id=event.id,
        )

    def _extract(self, event: Event) -> list[vocabulary.Candidate]:
        d = event.data
        if event.type is EventType.TECHNOLOGY:
            host = (getattr(d, "host", "") or "").lower()
            name = getattr(d, "name", "") or ""
            if host and name:
                self._tech_by_host.setdefault(host, name)
            return vocabulary.extract_from_technology(name, host)

        if event.type is EventType.URL:
            url = getattr(d, "url", "") or ""
            cands = vocabulary.extract_from_path(url, self._context_for(url))
            # A URL may carry query parameters worth learning too.
            cands += self._params_from_url(url)
            return cands

        if event.type is EventType.ENDPOINT:
            url = getattr(d, "url", "") or ""
            ctx = self._context_for(url)
            cands = vocabulary.extract_from_path(url, ctx)
            for pname in (getattr(d, "parameters", None) or []):
                cands += vocabulary.extract_from_parameter(pname, None, url, ctx)
            return cands

        if event.type is EventType.PARAMETER:
            url = getattr(d, "url", "") or ""
            return vocabulary.extract_from_parameter(
                getattr(d, "name", "") or "",
                getattr(d, "sample_value", None),
                url,
                self._context_for(url),
            )
        return []

    # ── helpers ─────────────────────────────────────────────────────────────

    def _context_for(self, url: str) -> str | None:
        try:
            host = (urllib.parse.urlparse(url).hostname or "").lower()
        except Exception:
            return None
        return self._tech_by_host.get(host)

    def _params_from_url(self, url: str) -> list[vocabulary.Candidate]:
        out: list[vocabulary.Candidate] = []
        try:
            q = urllib.parse.urlparse(url).query
        except Exception:
            return out
        if not q:
            return out
        ctx = self._context_for(url)
        for name, values in urllib.parse.parse_qs(q, keep_blank_values=False).items():
            sample = values[0] if values else None
            out += vocabulary.extract_from_parameter(name, sample, url, ctx)
        return out
