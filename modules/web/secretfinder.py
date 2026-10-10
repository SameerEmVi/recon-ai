"""
secretfinder — scan live web content for exposed secrets/credentials.

Reactive: fires when a web app is found (HTTP_SERVICE) and on text-like URLs
(JS bundles, source maps, JSON/config). Fetches the body through the shared
rate limiter + WAF backoff, runs recon.secrets.scan_text over it, and emits a
FINDING_CANDIDATE per unique secret.

Secrets are REDACTED before they touch an event: the full value is never stored,
logged, or shown to the LLM (honours the 'no raw content downstream' rule).

Watches:  HTTP_SERVICE, URL
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

# URL path suffixes worth fetching for secret scanning (besides text content-types).
_TEXT_SUFFIXES = (
    ".js", ".mjs", ".cjs", ".ts", ".map", ".json", ".txt", ".xml",
    ".yml", ".yaml", ".env", ".config", ".cfg", ".ini", ".properties", ".bak",
)


@register
class SecretFinderModule(BaseModule):
    name = "secretfinder"
    description = "Scan HTTP responses / JS bundles for exposed secrets (regex + entropy)"
    watched_events = ["HTTP_SERVICE", "URL"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "secrets", "fast"]
    options = {
        "timeout": 20,
        "max_body_kb": 2048,       # skip bodies larger than this
        "include_entropy": True,   # generic high-entropy assignment pass
    }

    async def setup(self) -> bool:
        return True  # pure Python, no binary needed

    def _should_fetch_url(self, url: str, content_type: str | None) -> bool:
        path = urlparse(url).path.lower()
        if path.endswith(_TEXT_SUFFIXES):
            return True
        if content_type:
            ct = content_type.lower()
            if any(t in ct for t in ("javascript", "json", "text/", "xml")):
                return True
        return False

    def _target_url(self, event: Event) -> str | None:
        """URL to fetch for `event`, or None (URL events are gated on text-like content)."""
        url = event.data.url
        if event.type is EventType.URL and not self._should_fetch_url(
            url, getattr(event.data, "content_type", None)
        ):
            return None
        return url or None

    async def _fetch(self, url: str) -> tuple[str, int] | None:
        """Fetch `url` through the shared limiter + WAF backoff → (body, status).

        Error responses are NOT discarded: a 4xx/5xx debug page or stack trace
        that dumps env/config is one of the likeliest places a secret leaks.
        None only on transport failure / oversize body.
        """
        # Shared per-scan cache: one GET per URL across all body-consumers.
        res = await self.fetch(
            url, timeout=self.opt("timeout"), max_body_kb=self.opt("max_body_kb")
        )
        if not res.ok or res.text is None:
            return None
        return res.text, res.status_code

    async def handle_event(self, event: Event) -> None:
        url = self._target_url(event)
        if not url:
            return
        fetched = await self._fetch(url)
        if fetched is None:
            return
        body, status = fetched

        from recon.secrets import scan_text
        matches = scan_text(body, include_entropy=self.opt("include_entropy"))
        if not matches:
            return

        host = urlparse(url).hostname or url
        where = f"an HTTP {status} error page at {url}" if status >= 400 else f"web content at {url}"
        count = 0
        for sec in matches:
            emitted = await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    # Redacted value in the title keeps distinct keys of the same
                    # type on one host from collapsing under the finding dedup key.
                    title=f"Exposed secret: {sec.name} ({sec.redacted})",
                    description=(
                        f"A {sec.name} was found exposed in {where}. "
                        f"Value redacted: {sec.redacted}. Verify it is live and "
                        f"rotate/revoke if valid."
                    ),
                    category="exposed-secret",
                    severity_hint=sec.severity,
                    evidence={
                        "type": sec.name,
                        "match_redacted": sec.redacted,   # never the full secret
                        "location": url[:512],
                        "offset": sec.index,
                        "http_status": status,
                    },
                ),
                source_event=event,
            )
            if emitted:
                count += 1
                self._log.warning(
                    "secretfinder: [%s] %s at %s (%s)",
                    sec.severity.upper(), sec.name, url, sec.redacted,
                )

        if count:
            self._log.info("secretfinder: %d secret(s) found at %s", count, url)
