"""
cloud_enum — multi-cloud public asset discovery (initstring/cloud_enum).

Seed module: runs cloud_enum against the target's keywords to find public
AWS S3 / Azure blob / GCP storage assets, emitting each as a FINDING_CANDIDATE
(category "cloud-bucket"). Warn-and-skips without `cloud_enum`.

Note: cloud_enum does not cover Alibaba OSS (matches the cloud_enum migration).

Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

import re
from uuid import UUID

from events.types import EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

_URL_RE = re.compile(r"https?://[^\s'\"]+")
# Lines cloud_enum uses to flag a reachable/public asset.
_HIT = ("open", "public", "found", "exists", "authenticated")


def parse_cloud_enum(text: str) -> list[dict]:
    """Extract public/open cloud assets from cloud_enum output.

    Returns [{"url": str, "line": str}], de-duplicated by url.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        low = line.lower()
        if not any(sig in low for sig in _HIT):
            continue
        m = _URL_RE.search(line)
        if not m:
            continue
        url = m.group(0).rstrip(".,)")
        if url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "line": line.strip()[:256]})
    return out


@register
class CloudEnumModule(BaseModule):
    name = "cloud_enum"
    description = "Multi-cloud public asset discovery via cloud_enum (no Alibaba OSS)"
    watched_events = []  # seed module
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["passive", "cloud", "bucket", "slow"]
    deps_binary = ["cloud_enum"]
    options = {"timeout": 600}

    async def run(self, domain: str, scan_id: UUID) -> None:
        label = domain.split(".")[0]
        keywords = [domain] + ([label] if label and label != domain else [])
        cmd = ["cloud_enum"]
        for k in keywords:
            cmd += ["-k", k]
        out = await self.run_proc(cmd, timeout=self.opt("timeout"))
        if not out:
            return
        count = 0
        for hit in parse_cloud_enum(out):
            await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=domain,
                    title="Public cloud asset",
                    description="cloud_enum reported a reachable/public cloud storage asset. Verify before reporting.",
                    category="cloud-bucket",
                    severity_hint="medium",
                    evidence={"url": hit["url"], "detail": hit["line"]},
                ),
            )
            count += 1
        if count:
            self._log.info("cloud_enum: %d public assets", count)
