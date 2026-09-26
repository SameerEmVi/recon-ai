"""
cloud_intel — the Cloud Asset Intelligence subsystem (event-driven front end).

Evidence-based correlation of the cloud infrastructure behind an authorized
target. Passive by default: it consumes events the pipeline already gathered
(SUBDOMAIN, DNS_RECORD, HTTP_SERVICE, TECHNOLOGY, URL) and correlates cloud
signals from DNS/CNAME, HTTP `server` headers, fingerprinted technologies, and
cloud URLs referenced in JS/config — never touching a cloud resource.

  * Passive identification (default) — classify + correlate from existing events.
  * Active verification (opt-in, `verify=True`) — a single benign, read-only GET
    to a scope-approved storage host to see whether it returns a public bucket
    listing. No enumeration, no writes, no auth, no destructive action.

Per host it accumulates a `CloudAsset` (provider, service, kind, confidence via
noisy-OR of independent signals, evidence list, provenance sources). Assets are
represented in the knowledge graph as:
  * TECHNOLOGY  — emitted live, so the host's tech profile shows the cloud stack
  * ANOMALY     — one `cloud-asset` record per asset (>= min_confidence) at finish
  * FINDING_CANDIDATE — only for a *verified* public storage exposure (opt-in)

All emission goes through `self.emit` → scope gate; dedup is per (host, provider,
service). Watches SUBDOMAIN, DNS_RECORD, HTTP_SERVICE, TECHNOLOGY, URL.
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import (
    AnomalyData,
    Event,
    EventType,
    FindingCandidateData,
    TechnologyData,
)
from modules.base import BaseModule
from modules.registry import register
from recon import cloudintel
from scope.types import ScopeStatus


@register
class CloudIntelModule(BaseModule):
    name = "cloud_intel"
    description = "Cloud Asset Intelligence: evidence-based AWS/Azure/GCP/CDN correlation from DNS/HTTP/TLS/tech/JS"
    watched_events = ["SUBDOMAIN", "DNS_RECORD", "HTTP_SERVICE", "TECHNOLOGY", "URL"]
    produced_events = ["TECHNOLOGY", "ANOMALY", "FINDING_CANDIDATE"]
    flags = ["passive", "web", "cloud", "correlation"]
    expected_value = 8
    options = {
        "min_confidence": 0.5,   # emit a cloud-asset ANOMALY at/above this
        "verify": False,         # opt-in active (benign, read-only) verification
        "timeout": 15,
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._correlator = cloudintel.CloudCorrelator()
        self._tech_emitted: set[tuple[str, str]] = set()   # (host, provider+service)
        self._events: dict[tuple[str, str, str], Event] = {}  # provenance: asset → source event

    async def setup(self) -> bool:
        return True  # pure Python; correlation needs no binary

    # ── evidence intake ─────────────────────────────────────────────────────

    async def handle_event(self, event: Event) -> None:
        d = event.data
        host, signals = "", []

        if event.type is EventType.SUBDOMAIN:
            host = getattr(d, "hostname", "") or ""
            signals = cloudintel.classify_hostname(host, source="dns")

        elif event.type is EventType.DNS_RECORD:
            host = getattr(d, "hostname", "") or ""
            rtype = getattr(d, "record_type", "")
            value = getattr(d, "value", "") or ""
            if rtype in ("CNAME", "NS", "MX"):
                signals = cloudintel.classify_hostname(value, source="dns")

        elif event.type is EventType.HTTP_SERVICE:
            url = getattr(d, "url", "") or ""
            host = urlparse(url).hostname or ""
            signals = cloudintel.classify_headers(None, server=getattr(d, "server", None))
            for tech in (getattr(d, "technologies", None) or []):
                signals += cloudintel.classify_technology(tech)
            signals += cloudintel.classify_hostname(host, source="http")

        elif event.type is EventType.TECHNOLOGY:
            host = getattr(d, "host", "") or ""
            signals = cloudintel.classify_technology(getattr(d, "name", "") or "")

        elif event.type is EventType.URL:
            url = getattr(d, "url", "") or ""
            host = urlparse(url).hostname or ""
            signals = cloudintel.classify_url(url, source="js")

        if not host or not signals:
            return

        for asset in self._correlator.add(host, signals):
            key = (asset.host, asset.provider, asset.service)
            self._events.setdefault(key, event)
            await self._emit_technology(asset, event)

    async def _emit_technology(self, asset, event: Event) -> None:
        key = (asset.host, asset.label())
        if key in self._tech_emitted:
            return
        self._tech_emitted.add(key)
        await self.emit(
            EventType.TECHNOLOGY,
            TechnologyData(
                host=asset.host, name=asset.label(),
                category=f"cloud-{asset.kind}", source="cloud_intel",
            ),
            source_event=event,
        )

    # ── finalization: emit correlated cloud-asset records ─────────────────────

    async def finish(self) -> None:
        min_conf = float(self.opt("min_confidence") or 0.5)
        assets = self._correlator.assets(min_confidence=min_conf)
        for asset in sorted(assets, key=lambda a: (-a.confidence, a.host)):
            key = (asset.host, asset.provider, asset.service)
            src = self._events.get(key)

            if self.opt("verify") and asset.kind == cloudintel.STORAGE:
                await self._verify_storage(asset)

            await self.emit(
                EventType.ANOMALY,
                AnomalyData(
                    host=asset.host,
                    description=(
                        f"cloud asset: {asset.label()} "
                        f"(confidence {asset.confidence:.2f}; "
                        f"sources {','.join(sorted(asset.sources))}; "
                        f"evidence: {'; '.join(asset.evidence[:5])})"
                        + ("  [verified public]" if asset.verified else "")
                    ),
                    category="cloud-asset",
                ),
                source_event=src,
            )
            self._log.info(
                "cloud_intel: %s → %s (%.2f) via %s",
                asset.host, asset.label(), asset.confidence, ",".join(sorted(asset.sources)),
            )

    # ── opt-in active verification (benign, read-only) ────────────────────────

    async def _verify_storage(self, asset) -> None:
        """A single scope-approved, read-only GET to check for a public bucket
        listing. Never enumerates, writes, or authenticates."""
        host = asset.host
        decision = self._ctrl.scope_engine.evaluate(host)
        if decision.status is not ScopeStatus.IN:
            self._log.debug("cloud_intel: verify skipped (out of scope): %s", host)
            return
        try:
            import httpx
        except ImportError:
            return
        url = f"https://{host}/"
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{host}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                if cloudintel.looks_like_public_bucket_listing(r.text):
                    asset.verified = True
                    await self.emit(
                        EventType.FINDING_CANDIDATE,
                        FindingCandidateData(
                            host=host,
                            title=f"Publicly listable {asset.label()}",
                            description=(
                                f"{asset.label()} at {url} returned a public bucket "
                                f"listing on an unauthenticated GET."
                            ),
                            category="exposed-cloud-storage",
                            evidence={"url": url, "status": str(r.status_code),
                                      "provider": asset.provider, "service": asset.service},
                            severity_hint="medium",
                        ),
                    )
        except Exception as exc:
            self._log.debug("cloud_intel: verify failed for %s: %s", host, exc)
