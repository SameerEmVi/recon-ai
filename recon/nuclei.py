"""
nuclei wrapper — configurable severity template scanning.

Default severity is "info" for safe passive checks (banners, version
disclosure, header checks). Paranoid mode can pass all severities.

nuclei JSON output format (one JSON object per line):
  {"template-id": ..., "host": ..., "matched-at": ...,
   "info": {"name": ..., "severity": ..., "description": ...}}
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from events.types import Event, EventType, FindingCandidateData

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False


class NucleiWrapper:
    def __init__(self, timeout: int = 180, limiter=None) -> None:
        self._timeout = timeout
        from ratelimit import NOOP
        self._limiter = limiter if limiter is not None else NOOP

    async def scan(
        self,
        target_url: str,
        publish: Callable[[Event], Coroutine[Any, Any, None]],
        scan_job_id: "UUID | None" = None,
        severity: str = "info",
    ) -> None:
        global _NOT_FOUND_WARNED

        cmd = [
            "nuclei",
            "-u", target_url,
            "-severity", severity,
            "-json",
            "-silent",
            "-no-interactsh",   # disable OAST/interactsh callbacks
            "-timeout", "10",
        ]
        log.debug("[nuclei] %s", " ".join(cmd))

        async with self._limiter.guard("nuclei"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                if not _NOT_FOUND_WARNED:
                    log.warning("[nuclei] binary not found — skipping nuclei scan")
                    _NOT_FOUND_WARNED = True
                return

            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[nuclei] timed out after %ds", self._timeout)
                return

        import uuid as _uuid
        sid = scan_job_id or _uuid.uuid4()
        parsed_host = urlparse(target_url).hostname or target_url
        count = 0

        for raw_line in stdout.splitlines():
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = obj.get("info", {})
            name = str(info.get("name", obj.get("template-id", "unknown")))[:200]
            description = str(info.get("description", ""))[:512]
            matched_at = str(obj.get("matched-at", target_url))[:512]
            template_id = str(obj.get("template-id", ""))[:100]
            sev = str(info.get("severity", "info")).lower()

            evidence: dict[str, Any] = {
                "template_id": template_id,
                "matched_at": matched_at,
            }
            if description:
                evidence["description"] = description[:256]

            try:
                event = Event.create(
                    EventType.FINDING_CANDIDATE,
                    FindingCandidateData(
                        host=parsed_host,
                        title=name,
                        description=description or f"nuclei template {template_id}",
                        category=f"nuclei-{sev}",
                        severity_hint=sev,
                        evidence=evidence,
                    ),
                    scan_job_id=sid,
                    source_tool="nuclei",
                )
                await publish(event)
                count += 1
            except Exception as exc:
                log.debug("[nuclei] skipped result %s: %s", template_id, exc)

        log.info("[nuclei] %s → %d finding(s)", target_url, count)
