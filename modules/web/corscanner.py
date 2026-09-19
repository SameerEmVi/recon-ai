"""
corscanner — CORS misconfiguration detection (pure Python, no binary).

Reactive: fires on HTTP_SERVICE events. Sends a request with a spoofed
Origin header and analyzes the CORS response headers to detect:

  - Reflected origin with credentials → critical misconfiguration
  - Reflected origin without credentials → low severity info
  - Wildcard (*) origin with credentials → critical misconfiguration
  - Null origin reflection → misconfiguration

Watches:  HTTP_SERVICE
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

_TEST_ORIGIN = "https://evil-cors-test.recon.internal"


@register
class CorsScannerModule(BaseModule):
    name = "corscanner"
    description = "CORS misconfiguration detection (pure Python, no binary)"
    watched_events = ["HTTP_SERVICE"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "cors", "fast"]
    options = {"timeout": 10}

    async def setup(self) -> bool:
        return True  # pure Python

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not url:
            return

        try:
            import httpx
        except ImportError:
            self._log.warning("httpx not installed")
            return

        host = urlparse(url).hostname or url

        tests = [
            (_TEST_ORIGIN, "reflected"),
            ("null",        "null"),
        ]

        try:
            async with httpx.AsyncClient(
                timeout=self.opt("timeout"),
                follow_redirects=False,
            ) as client:
                for origin_value, label in tests:
                    await self._test_origin(client, url, host, origin_value, label, event)
        except Exception as exc:
            self._log.debug("corscanner: error on %s: %s", url, exc)

    async def _test_origin(
        self, client, url: str, host: str, origin: str, label: str, source: Event
    ) -> None:
        try:
            async with self.guard(f"http:{host}"):
                r = await client.get(url, headers={"Origin": origin})
        except Exception:
            return
        self.inspect_response(r)

        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        allow_creds = acac == "true"

        finding = None
        severity = "info"

        if acao == "*" and allow_creds:
            # Wildcard + credentials — browsers block this, but still misconfigured.
            finding = "CORS: wildcard origin with credentials header (browser-blocked but misconfigured)"
            severity = "medium"
        elif acao == origin and allow_creds:
            finding = f"CORS: origin reflected ({label}) with Access-Control-Allow-Credentials: true — credential theft possible"
            severity = "high"
        elif acao == origin and not allow_creds:
            finding = f"CORS: origin reflected ({label}) without credentials — limited impact"
            severity = "low"
        elif label == "null" and acao == "null":
            finding = "CORS: null origin reflected — sandbox iframe bypass possible"
            severity = "medium"

        if finding:
            await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    title=f"CORS Misconfiguration ({label} origin)",
                    description=finding,
                    category="cors",
                    severity_hint=severity,
                    evidence={
                        "url": url[:512],
                        "tested_origin": origin[:128],
                        "acao_header": acao[:256],
                        "acac_header": acac[:64],
                    },
                ),
                source_event=source,
            )
            self._log.info("corscanner: [%s] %s — %s", severity.upper(), url, finding[:80])
