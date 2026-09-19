"""
BBOT wrapper — passive intelligence gathering via the BBOT Python library.

BBOT is consumed as a library (not a subprocess). Its async_start() generator
yields BBOT events which are translated one-by-one into our event model and
pushed through stamp_and_publish() — so the scope gate applies identically
to BBOT-sourced events as to everything else.

Default passive modules (no API keys required):
    crt           — cert.sh certificate transparency
    certspotter   — certspotter.com certificate transparency
    rapiddns      — rapiddns.io passive DNS
    dnsdumpster   — dnsdumpster.com passive DNS

Install: pip install recon-ai[bbot]   or   pip install bbot

If bbot is not installed this wrapper logs a warning and returns without error,
so the rest of the scan continues normally.

Trust boundary: all BBOT event.data values go through our Pydantic validators
at Event.create() time — the same sanitization that applies to subfinder output.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse
from uuid import UUID

if TYPE_CHECKING:
    from controller.controller import ScanController

from events.types import (
    Event,
    EventType,
    FindingCandidateData,
    HttpServiceData,
    IpData,
    OpenPortData,
    SubdomainData,
    TechnologyData,
    UrlData,
)

log = logging.getLogger(__name__)

DEFAULT_MODULES = ["crt", "certspotter", "rapiddns", "dnsdumpster"]

_IMPORT_WARNED = False


def _try_import_bbot() -> Any:
    """Import bbot.Scanner. Returns None and warns once if bbot is not installed."""
    global _IMPORT_WARNED
    try:
        from bbot.scanner import Scanner  # type: ignore[import]
        return Scanner
    except ImportError:
        if not _IMPORT_WARNED:
            log.warning(
                "[bbot] bbot not installed — skipping. "
                "Install with: pip install recon-ai[bbot]  or  pip install bbot"
            )
            _IMPORT_WARNED = True
        return None


# ── event translation ─────────────────────────────────────────────────────────

def _translate(bbot_event: Any, scan_job_id: UUID) -> Event | None:
    """
    Translate one BBOT event into our event model.

    Returns None for event types we don't handle or when required fields
    are missing / malformed. All string fields go through Pydantic validators
    at Event.create() time — BBOT output is target-controlled and hostile.
    """
    etype = str(getattr(bbot_event, "type", ""))

    try:
        if etype == "DNS_NAME":
            hostname = str(bbot_event.data).lower().strip().rstrip(".")
            if not hostname:
                return None
            return Event.create(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=hostname, source="bbot"),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "IP_ADDRESS":
            address = str(bbot_event.data).strip()
            parent = getattr(bbot_event, "parent", None)
            resolved_from = None
            if parent and str(getattr(parent, "type", "")) == "DNS_NAME":
                resolved_from = str(parent.data).lower().strip()
            return Event.create(
                EventType.IP,
                IpData(address=address, resolved_from=resolved_from),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "OPEN_TCP_PORT":
            # BBOT format: "host:port"
            raw = str(bbot_event.data)
            # handle IPv6 [::1]:443 and plain host:port
            if raw.startswith("["):
                close = raw.index("]")
                host = raw[1:close]
                port_str = raw[close + 2:]
            elif ":" in raw:
                host, port_str = raw.rsplit(":", 1)
            else:
                return None
            try:
                port = int(port_str)
            except ValueError:
                return None
            return Event.create(
                EventType.OPEN_PORT,
                OpenPortData(host=host.strip(), port=port, protocol="tcp"),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "URL":
            url = str(bbot_event.data).strip()
            if not url.startswith(("http://", "https://")):
                return None
            return Event.create(
                EventType.URL,
                UrlData(url=url, found_via="bbot"),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "HTTP_RESPONSE":
            d = bbot_event.data
            if not isinstance(d, dict):
                return None
            url = str(d.get("url", "")).strip()
            # BBOT uses "status-code" (httpx JSON convention)
            status_code = d.get("status_code") or d.get("status-code")
            if not url or not status_code:
                return None
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                return None
            return Event.create(
                EventType.HTTP_SERVICE,
                HttpServiceData(
                    url=url,
                    status_code=status_code,
                    title=str(d.get("title", ""))[:200] or None,
                    server=str(d.get("server", "") or d.get("Server", ""))[:100] or None,
                    content_length=d.get("content-length") or d.get("content_length"),
                ),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "TECHNOLOGY":
            d = bbot_event.data
            # BBOT TECHNOLOGY data: {"technology": "nginx", "version": "1.24", "host": "..."}
            # or sometimes just a string
            if isinstance(d, dict):
                name = str(d.get("technology", d.get("name", ""))).strip()
                version = str(d.get("version", "")).strip() or None
                host = str(d.get("host", "")).strip()
            else:
                name = str(d).strip()
                version = None
                host = ""
            if not name:
                return None
            # Fall back to parent event's host if not in data dict.
            if not host:
                parent = getattr(bbot_event, "parent", None)
                if parent:
                    h = getattr(parent, "host", None)
                    if h:
                        host = str(h).strip()
            if not host:
                return None
            return Event.create(
                EventType.TECHNOLOGY,
                TechnologyData(host=host, name=name, version=version),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

        if etype == "FINDING":
            d = bbot_event.data
            if not isinstance(d, dict):
                return None
            # Try host from data dict, then from bbot_event.host attribute.
            host = str(
                d.get("host") or getattr(bbot_event, "host", "") or ""
            ).strip()
            if not host:
                return None
            title = str(d.get("description", "") or d.get("title", "BBOT finding"))[:200]
            description = str(d.get("description", ""))[:512]
            category = str(d.get("type", "bbot-finding"))[:50]
            evidence: dict[str, str] = {
                "source": "bbot",
                "module": str(d.get("module", ""))[:64],
            }
            return Event.create(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    title=title or "BBOT finding",
                    description=description or title,
                    category=category,
                    severity_hint="info",
                    evidence=evidence,
                ),
                scan_job_id=scan_job_id,
                source_tool="bbot",
            )

    except Exception as exc:
        log.debug("[bbot] translation error for %s event: %s", etype, exc)

    return None


# ── wrapper class ─────────────────────────────────────────────────────────────

class BBOTWrapper:
    """
    Run a BBOT scan (passive modules) and translate output into our event model.

    All events pass through stamp_and_publish() so the scope gate applies.
    BBOT's own whitelist is set to the target domain for defence-in-depth,
    but our scope gate is the authoritative check.
    """

    def __init__(
        self,
        controller: "ScanController",
        modules: list[str] | None = None,
        timeout: int = 300,
    ) -> None:
        self._ctrl = controller
        self._modules = modules or DEFAULT_MODULES
        self._timeout = timeout

    async def run(self, domain: str, scan_job_id: UUID) -> None:
        Scanner = _try_import_bbot()
        if Scanner is None:
            return

        log.info("[bbot] starting passive scan: %s  modules=%s", domain, self._modules)

        try:
            scanner = Scanner(
                domain,
                modules=self._modules,
                output_modules=[],   # suppress BBOT's own file/console output
                config={
                    "scope_search_distance": 0,  # stay focused on the target
                    "dns_resolve_distance": 1,
                    "silent": True,
                },
                whitelist=[domain],  # BBOT's own scope guard
            )
        except Exception as exc:
            log.error("[bbot] failed to initialise scanner: %s", exc)
            return

        accepted = 0
        total = 0

        try:
            async for bbot_event in scanner.async_start():
                total += 1
                event = _translate(bbot_event, scan_job_id)
                if event is None:
                    continue
                try:
                    if await self._ctrl.stamp_and_publish(event):
                        accepted += 1
                except Exception as exc:
                    log.debug("[bbot] publish error: %s", exc)
        except Exception as exc:
            log.error("[bbot] scan error: %s", exc)

        log.info("[bbot] done: %d BBOT events → %d accepted", total, accepted)
