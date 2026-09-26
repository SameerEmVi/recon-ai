"""
metascan — document & image metadata intelligence.

Reactive: on URL events pointing at documents/images (PDF, Office OOXML, JPEG,
PNG, TIFF), downloads the file (scope-gated, rate-limited, size-capped) and
extracts embedded metadata that commonly leaks internal usernames, software
versions, company names, internal paths and GPS coordinates.

Extraction backend, in order of preference:
  1. `exiftool` if the binary is installed (richest output, parsed from -json)
  2. pure-Python fallback (`recon.metadata`) — works with no binary

Emits:
  ANOMALY            — one `document-metadata` record per file (author/software/…)
  FINDING_CANDIDATE  — `metadata-disclosure` when sensitive fields are present
Feeds the learning system with leaked usernames / software tokens.

Watches:  URL
Produces: ANOMALY, FINDING_CANDIDATE
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from urllib.parse import urlparse

from events.types import AnomalyData, Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register
from recon import metadata, vocabulary

# exiftool tag → our normalized key (subset; the fallback uses the same keys).
_EXIFTOOL_MAP = {
    "Author": "author", "Creator": "creator", "LastModifiedBy": "last_modified_by",
    "Company": "company", "Manager": "manager", "Producer": "producer",
    "Software": "software", "Application": "application", "CreatorTool": "creatortool",
    "Make": "make", "Model": "model", "Artist": "artist", "GPSLatitude": "gps_latitude",
    "GPSLongitude": "gps_longitude", "Title": "title", "CreateDate": "created",
}


@register
class MetaScanModule(BaseModule):
    name = "metascan"
    description = "Document/image metadata analysis (exiftool if present, else pure-Python EXIF/OOXML/PDF)"
    watched_events = ["URL"]
    produced_events = ["ANOMALY", "FINDING_CANDIDATE"]
    flags = ["active", "web", "metadata"]
    expected_value = 8
    options = {
        "timeout": 25,
        "max_body_kb": 8192,     # cap downloaded file size (docs/images can be large)
        "prefer_exiftool": True,
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._seen: set[str] = set()
        self._exiftool: str | None = None

    async def setup(self) -> bool:
        # Pure-Python fallback always works; note whether exiftool is available.
        if self.opt("prefer_exiftool"):
            self._exiftool = shutil.which("exiftool")
        if self._exiftool:
            self._log.info("metascan: using exiftool at %s", self._exiftool)
        else:
            self._log.info("metascan: exiftool not found — using pure-Python extractor")
        return True

    async def handle_event(self, event: Event) -> None:
        url = getattr(event.data, "url", "") or ""
        if not url:
            return
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        if ext not in metadata.META_EXTS:
            return
        if url in self._seen:
            return
        self._seen.add(url)

        data = await self._download(url)
        if not data:
            return

        meta = await self._extract(data, url)
        if not meta:
            return

        host = urlparse(url).hostname or ""
        filename = os.path.basename(urlparse(url).path) or url
        sens = metadata.sensitive(meta)

        # Always record what metadata the file carried.
        compact = "; ".join(f"{k}={v}" for k, v in list(meta.items())[:8])
        if host:
            await self.emit(
                EventType.ANOMALY,
                AnomalyData(host=host,
                            description=f"metadata in {filename}: {compact}",
                            category="document-metadata"),
                source_event=event,
            )

        # Elevate to a finding when it leaks sensitive fields.
        if sens and host:
            await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    title=f"Metadata disclosure in {filename}",
                    description=(
                        f"{filename} exposes document metadata: "
                        + ", ".join(sorted(sens.keys()))
                        + ". Published files can leak internal usernames, software "
                        "versions, company names and GPS location."
                    ),
                    category="metadata-disclosure",
                    evidence={"url": url, **{k: str(v) for k, v in list(sens.items())[:15]}},
                    severity_hint="low",
                ),
                source_event=event,
            )

        await self._feed_learning(meta)
        self._log.info("metascan: %s → %d metadata field(s)%s",
                       filename, len(meta), " [exiftool]" if self._exiftool else "")

    # ── download / extract ─────────────────────────────────────────────────────

    async def _download(self, url: str) -> bytes | None:
        try:
            import httpx
        except ImportError:
            return None
        try:
            async with httpx.AsyncClient(timeout=self.opt("timeout")) as client:
                async with self.guard(f"http:{urlparse(url).hostname or url}"):
                    r = await client.get(url, follow_redirects=True)
                self.inspect_response(r)
                r.raise_for_status()
                if len(r.content) / 1024 > self.opt("max_body_kb"):
                    self._log.debug("metascan: %s too large — skipping", url)
                    return None
                return r.content
        except Exception as exc:
            self._log.debug("metascan: download failed for %s: %s", url, exc)
            return None

    async def _extract(self, data: bytes, url: str) -> dict[str, str]:
        if self._exiftool:
            meta = await self._exiftool_extract(data, url)
            if meta:
                return meta
        # Pure-Python fallback (also the path when exiftool returned nothing).
        return metadata.extract(data, url)

    async def _exiftool_extract(self, data: bytes, url: str) -> dict[str, str]:
        """Run exiftool -json on a temp file; map its tags to our normalized keys."""
        ext = os.path.splitext(urlparse(url).path)[1].lower() or ".bin"
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=ext)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            out = await self.run_proc(
                [self._exiftool, "-json", "-n", tmp],
                timeout=self.opt("timeout"), bucket=f"proc:{self.name}",
            )
            if not out:
                return {}
            parsed = json.loads(out)
            raw = parsed[0] if isinstance(parsed, list) and parsed else {}
            meta: dict[str, str] = {}
            for tag, val in raw.items():
                key = _EXIFTOOL_MAP.get(tag)
                if key and val not in (None, ""):
                    meta[key] = str(val)
            return meta
        except Exception as exc:
            self._log.debug("metascan: exiftool failed for %s: %s", url, exc)
            return {}
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    # ── learning-system feed ────────────────────────────────────────────────────

    async def _feed_learning(self, meta: dict[str, str]) -> None:
        kb = getattr(self._ctrl, "knowledge_base", None)
        if kb is None:
            return
        cands: list[vocabulary.Candidate] = []
        # Single-token author / lastModifiedBy values are often usernames.
        for key in ("author", "last_modified_by", "creator", "artist"):
            v = (meta.get(key) or "").strip()
            if v and " " not in v and 2 <= len(v) <= 64:
                cands.append(vocabulary.Candidate(v, vocabulary.RESOURCE_NAMES,
                                                  meta.get("software") or meta.get("application")))
        if cands:
            await kb.learn_many(cands, scan_domain=self._ctrl.scan_domain,
                                source_scan_id=self._ctrl.scan_id)
