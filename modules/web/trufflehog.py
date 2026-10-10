"""
trufflehog — secret scanning of live web content via the trufflehog binary.

The binary-backed complement to `secretfinder` (regex + entropy, no binary):
trufflehog brings ~800 provider-specific detectors plus decoders (base64,
escaped-unicode, …) and optional live verification.

Reactive, same trigger surface as secretfinder (it subclasses it and reuses its
URL gating + fetch): HTTP_SERVICE pages and text-like URLs (JS bundles, source
maps, JSON/config/.env …). Every fetch goes through the shared rate limiter +
WAF backoff.

Batching: trufflehog's start-up (~1s, loading every detector) dwarfs the scan of
one document (~10ms), so fetched bodies are written into a private temp
directory and scanned `batch_size` at a time with ONE `trufflehog filesystem`
run (one guarded op); the remainder is flushed in `finish()`. Results map back
to their source URL/event by file name. Identical bodies on the same host are
scanned once.

Secrets are REDACTED inside `recon/trufflehog.py` before they reach this module:
the full value is never stored, logged, or shown to the LLM. Verification is OFF
by default — `verify=True` sends candidate credentials to the provider's API
(third-party traffic using a leaked credential; check program rules first).

Watches:  HTTP_SERVICE, URL
Produces: FINDING_CANDIDATE (category "exposed-secret")
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register
from modules.web.secretfinder import SecretFinderModule
from recon.trufflehog import build_command, parse_trufflehog_json, severity_for


@dataclass
class _Doc:
    file: str       # basename inside the batch dir
    url: str
    status: int     # HTTP status (error pages are scanned too)
    event: Event


@register
class TruffleHogModule(SecretFinderModule):
    name = "trufflehog"
    description = "Scan HTTP responses / JS bundles for exposed secrets via trufflehog"
    watched_events = ["HTTP_SERVICE", "URL"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "secrets"]
    deps_binary = ["trufflehog"]
    options = {
        "timeout": 20,             # per-fetch HTTP timeout (s)
        "max_body_kb": 2048,       # skip bodies larger than this
        "batch_size": 25,          # documents per trufflehog run
        "proc_timeout": 300,       # per trufflehog run (s)
        "verify": False,           # opt-in: verify candidates against provider APIs
        "results": None,           # e.g. "verified,unknown" (trufflehog --results)
        "exclude_detectors": None, # e.g. "JWT,URI" (trufflehog --exclude-detectors)
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._workdir: Path | None = None
        self._batch_dir: Path | None = None
        self._batch: list[_Doc] = []
        self._batch_no = 0
        self._doc_no = 0
        self._seen_bodies: set[tuple[str, str]] = set()   # (host, sha1(body))

    async def setup(self) -> bool:
        if not await BaseModule.setup(self):   # deps_binary check (warn-and-skip)
            return False
        self._workdir = Path(tempfile.mkdtemp(prefix="recon-trufflehog-"))
        self._new_batch_dir()
        return True

    def _new_batch_dir(self) -> None:
        assert self._workdir is not None
        self._batch_no += 1
        self._batch_dir = self._workdir / f"batch-{self._batch_no:04d}"
        self._batch_dir.mkdir()

    async def handle_event(self, event: Event) -> None:
        if self._batch_dir is None:
            return   # setup() not run / disabled
        url = self._target_url(event)
        if not url:
            return
        fetched = await self._fetch(url)
        if fetched is None or not fetched[0]:
            return
        body, status = fetched

        host = urlparse(url).hostname or url
        digest = hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()
        if (host, digest) in self._seen_bodies:
            return
        self._seen_bodies.add((host, digest))

        self._doc_no += 1
        fname = f"{self._doc_no:06d}.txt"
        (self._batch_dir / fname).write_text(body, encoding="utf-8", errors="replace")
        self._batch.append(_Doc(file=fname, url=url, status=status, event=event))

        if len(self._batch) >= int(self.opt("batch_size") or 25):
            await self._flush()

    async def _flush(self) -> None:
        """Scan the current batch dir with one trufflehog run and emit findings."""
        if not self._batch or self._batch_dir is None:
            return
        # Swap before awaiting so concurrent handlers start a fresh batch.
        docs, batch_dir = self._batch, self._batch_dir
        self._batch = []
        self._new_batch_dir()

        try:
            cmd = build_command(
                str(batch_dir),
                verify=bool(self.opt("verify")),
                results=self.opt("results"),
                exclude_detectors=self.opt("exclude_detectors"),
            )
            out = await self.run_proc(cmd, timeout=int(self.opt("proc_timeout") or 300))
            if out:
                await self._emit_findings(out, {d.file: d for d in docs})
        finally:
            shutil.rmtree(batch_dir, ignore_errors=True)

    async def _emit_findings(self, output: str, by_file: dict[str, _Doc]) -> None:
        count = 0
        for f in parse_trufflehog_json(output):
            doc = by_file.get(f.file)
            if doc is None:
                continue
            host = urlparse(doc.url).hostname or doc.url
            status = "verified live" if f.verified else "unverified"
            where = (f"an HTTP {doc.status} error page at {doc.url}" if doc.status >= 400
                     else f"web content at {doc.url}")
            evidence = {
                "type": f.detector,
                "match_redacted": f.redacted,   # never the full secret
                "location": doc.url[:512],
                "line": f.line,
                "http_status": doc.status,
                "verified": f.verified,
                "decoder": f.decoder,
                "engine": "trufflehog",
            }
            if f.rotation_guide:
                evidence["rotation_guide"] = f.rotation_guide[:256]
            emitted = await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    # Redacted value in the title keeps distinct keys of the same
                    # type on one host from collapsing under the finding dedup key.
                    title=f"Exposed secret: {f.detector} ({f.redacted})",
                    description=(
                        f"trufflehog {f.detector} detector matched ({status}) in "
                        f"{where} line {f.line}. Value redacted: "
                        f"{f.redacted}. Rotate/revoke if valid."
                    ),
                    category="exposed-secret",
                    severity_hint=severity_for(f),
                    evidence=evidence,
                ),
                source_event=doc.event,
            )
            if emitted:
                count += 1
                self._log.warning(
                    "trufflehog: [%s] %s at %s (%s, %s)",
                    severity_for(f).upper(), f.detector, doc.url, f.redacted, status,
                )
        if count:
            self._log.info("trufflehog: %d secret(s) found", count)

    async def finish(self) -> None:
        try:
            await self._flush()
        finally:
            if self._workdir is not None:
                shutil.rmtree(self._workdir, ignore_errors=True)
                self._workdir = self._batch_dir = None
