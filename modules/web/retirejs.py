"""
retirejs — detect vulnerable JavaScript libraries via the retire.js binary.

Reactive module (same JS-file trigger surface as linkfinder/jsluice): on each
JavaScript URL it fetches the body through the shared limiter/WAF/cache
(`BaseModule.fetch`) and stores it in a private temp dir, de-duplicated by
(host, content-hash). At `finish()` it runs **one** `retire --path <dir>
--outputformat json` over the whole collection and maps each result back to its
source URL by file name.

Emission (scope-gated via `self.emit → stamp_and_publish → ScopeEngine`):
  * TECHNOLOGY per detected library (`component` + `version`, `source="retire.js"`,
    category `js-library`) — a precise, content-derived version fingerprint that
    enriches the fingerprint/vulnassess picture;
  * FINDING_CANDIDATE per advisory (`vuln:vulnerable-js-library`), carrying the
    CVE/GHSA identifiers, severity, CWE and reference URLs.

ACCURACY: a retire.js hit is a **version-range match** against its advisory DB.
The version is read from the actual served file (stronger than a server banner),
but a backported/patched fork can still be a false positive, so findings are
POTENTIAL — never "confirmed exploitable". The LLM triage may annotate but never
promotes them.

Capability: VULNERABILITY_CHECK + TARGET_HTTP_REQUEST (fetches JS and reports
vulns) → runs in vuln/active/full, never osint.

Watches:  URL
Produces: TECHNOLOGY, FINDING_CANDIDATE (category "vuln:vulnerable-js-library")
Requires: retire on PATH (warn-and-skips otherwise)
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData, TechnologyData
from modules.base import BaseModule
from modules.registry import register
from modules.web.linkfinder import _is_js_url
from recon.retirejs import build_command, parse_retire_json


@register
class RetireJsModule(BaseModule):
    name = "retirejs"
    description = "Detect vulnerable JS libraries (retire.js) → TECHNOLOGY + findings"
    watched_events = ["URL"]
    produced_events = ["TECHNOLOGY", "FINDING_CANDIDATE"]
    flags = ["active", "web", "vuln", "js-analysis"]
    deps_binary = ["retire"]
    estimated_cost = 4
    expected_value = 7
    options = {
        "timeout": 20,           # per-fetch HTTP timeout (s)
        "max_js_size_kb": 1024,  # skip JS bodies larger than this
        "proc_timeout": 180,     # the single retire run (s)
        "max_files": 300,        # cap bodies collected (bounds work)
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._dir: str | None = None
        self._seen: set[str] = set()                     # host:bodyhash dedup
        self._map: dict[str, tuple[str, str, Event]] = {}  # filename → (url, host, event)
        self._n = 0

    async def handle_event(self, event: Event) -> None:
        url = event.data.url
        if not _is_js_url(url, getattr(event.data, "content_type", None)):
            return
        if self._n >= int(self.opt("max_files")):
            return

        res = await self.fetch(
            url, timeout=int(self.opt("timeout")),
            max_body_kb=int(self.opt("max_js_size_kb")),
        )
        if not res.is_2xx or res.text is None:
            return

        host = urlparse(url).hostname or "js"
        digest = hashlib.sha256(res.text.encode("utf-8", "replace")).hexdigest()
        key = f"{host}:{digest}"
        if key in self._seen:
            return
        self._seen.add(key)

        if self._dir is None:
            self._dir = tempfile.mkdtemp(prefix="retirejs_")
        fname = f"{self._n:04d}.js"
        try:
            with open(os.path.join(self._dir, fname), "w",
                      encoding="utf-8", errors="replace") as fh:
                fh.write(res.text)
        except OSError as exc:
            self._log.debug("retirejs: write failed for %s: %s", url, exc)
            return
        self._map[fname] = (url, host, event)
        self._n += 1

    async def finish(self) -> None:
        if not self._dir or not self._map:
            self._cleanup()
            return
        try:
            # Resolve the full binary path. On Windows the npm shim is
            # `retire.CMD`; create_subprocess_exec needs the resolved path (with
            # extension), not the bare name, to launch it.
            binary = shutil.which("retire") or "retire"
            out = await self.run_proc(
                build_command(self._dir, binary=binary),
                timeout=int(self.opt("proc_timeout")),
                bucket="retirejs",
            )
            if out:
                await self._emit(out)
        finally:
            self._cleanup()

    async def _emit(self, out: str) -> None:
        techs = findings = 0
        for comp in parse_retire_json(out):
            url, host, event = self._map.get(comp.file, ("", "", None))
            if not host:
                continue

            if comp.version and await self.emit(
                EventType.TECHNOLOGY,
                TechnologyData(host=host, name=comp.component, version=comp.version,
                               category="js-library", source="retire.js"),
                source_event=event,
            ):
                techs += 1

            for v in comp.vulns:
                cve = ", ".join(v.cves) if v.cves else ""
                refs = ", ".join(v.info)
                label = cve or (v.summary[:40] if v.summary else "advisory")
                evidence = {
                    "component": comp.component,
                    "version": comp.version,
                    "detection": comp.detection or "filecontent",
                    "status": "POTENTIAL",
                    "cve": cve or "n/a",
                    "cwe": ", ".join(v.cwe) or "n/a",
                    "affected_range": f"{v.at_or_above or '0'} ..< {v.below or '?'}",
                    "source": (url or host)[:512],
                    "references": refs[:512],
                }
                if await self.emit(
                    EventType.FINDING_CANDIDATE,
                    FindingCandidateData(
                        host=host,
                        # CVE in the title so distinct advisories on one library
                        # don't collapse under the host:title:category dedup key.
                        title=f"Vulnerable JS library: {comp.component} {comp.version} ({label})",
                        description=(
                            f"retire.js matched {comp.component} {comp.version} "
                            f"(served at {url or host}) against a known advisory"
                            f"{' ' + cve if cve else ''}: {v.summary or 'see references'}. "
                            f"Version-range match (POTENTIAL) — a backported/patched build "
                            f"can be a false positive; verify the actual library before reporting."
                        ),
                        category="vuln:vulnerable-js-library",
                        severity_hint=v.severity if v.severity in
                        ("low", "medium", "high", "critical") else "medium",
                        evidence=evidence,
                    ),
                    source_event=event,
                ):
                    findings += 1
        self._log.info("retirejs: %d library fingerprint(s), %d vulnerable-library finding(s)",
                       techs, findings)

    def _cleanup(self) -> None:
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None
