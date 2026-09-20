"""
s3scanner — S3 bucket exposure detection (sa7mon/S3Scanner).

Reactive module: on each SUBDOMAIN, probes the hostname as an S3 bucket-name
candidate and emits a FINDING_CANDIDATE (category "cloud-bucket") for any bucket
that exists with permissive ACLs. Warn-and-skips without `s3scanner`.

Watches:  SUBDOMAIN
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

import re

from events.types import Event, EventType, FindingCandidateData
from modules.base import BaseModule
from modules.registry import register

# Signals in s3scanner output that a bucket exists / is exposed.
_EXPOSED = ("allusers", "authusers", "open", "public", "read", "write", "exists")


def parse_s3scanner(text: str) -> list[dict]:
    """Extract exposed-bucket findings from s3scanner output (text or -json-ish).

    Returns [{"bucket": str, "detail": str}], de-duplicated by bucket.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if not any(sig in low for sig in _EXPOSED):
            continue
        # First token that looks like a bucket / host name.
        m = re.search(r"[a-z0-9][a-z0-9.\-]{1,62}", low)
        bucket = m.group(0) if m else line[:64]
        if bucket in seen:
            continue
        seen.add(bucket)
        out.append({"bucket": bucket, "detail": line[:256]})
    return out


@register
class S3ScannerModule(BaseModule):
    name = "s3scanner"
    description = "S3 bucket exposure detection via s3scanner"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "cloud", "bucket", "slow"]
    deps_binary = ["s3scanner"]
    options = {"timeout": 120}

    async def handle_event(self, event: Event) -> None:
        host = event.data.hostname
        if not host:
            return
        out = await self.run_proc(
            ["s3scanner", "scan", "-bucket", host],
            timeout=self.opt("timeout"), bucket=f"cloud:{host}",
        )
        if not out:
            return
        for hit in parse_s3scanner(out):
            await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=host,
                    title=f"Exposed S3 bucket ({hit['bucket']})",
                    description="s3scanner reported an existing/permissive S3 bucket. Verify access before reporting.",
                    category="cloud-bucket",
                    severity_hint="medium",
                    evidence={"bucket": hit["bucket"], "detail": hit["detail"]},
                ),
                source_event=event,
            )
