"""
zonetransfer — DNS zone transfer (AXFR) check via `dig`.

Seed module: once per scan, finds the seed domain's authoritative nameservers
and attempts a full AXFR against each. A successful transfer both discloses
every record (emitted as SUBDOMAIN events) and is itself a misconfiguration
(emitted as a FINDING_CANDIDATE). Warn-and-skips without `dig`.

Produces: SUBDOMAIN, FINDING_CANDIDATE
"""

from __future__ import annotations

from uuid import UUID

from events.types import (
    EventType, FindingCandidateData, SubdomainData,
)
from modules.base import BaseModule
from modules.registry import register


def parse_ns(text: str) -> list[str]:
    """Parse `dig +short NS <domain>` output into nameserver hostnames."""
    out: list[str] = []
    for line in (text or "").splitlines():
        ns = line.strip().rstrip(".").lower()
        if ns and " " not in ns:
            out.append(ns)
    return out


def parse_axfr(text: str, domain: str) -> tuple[list[str], bool]:
    """Parse `dig AXFR` output. Returns (hostnames_in_domain, transfer_succeeded)."""
    domain = domain.strip().rstrip(".").lower()
    names: list[str] = []
    seen: set[str] = set()
    got_records = False
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if "failed" in line.lower() or "transfer" in line.lower() and "failed" in line.lower():
            continue
        parts = line.split()
        # dig record line: "<name>. <ttl> <class> <type> <data...>"
        if len(parts) >= 4 and parts[2].upper() in ("IN", "CH", "HS"):
            got_records = True
            owner = parts[0].rstrip(".").lower()
            if owner and (owner == domain or owner.endswith("." + domain)):
                if owner not in seen:
                    seen.add(owner)
                    names.append(owner)
    return names, got_records


@register
class ZoneTransferModule(BaseModule):
    name = "zonetransfer"
    description = "DNS zone transfer (AXFR) check via dig"
    watched_events = []  # seed module
    produced_events = ["SUBDOMAIN", "FINDING_CANDIDATE"]
    flags = ["active", "dns", "subdomain-enum", "fast"]
    deps_binary = ["dig"]
    options = {"timeout": 30}

    async def run(self, domain: str, scan_id: UUID) -> None:
        ns_out = await self.run_proc(["dig", "+short", "NS", domain], timeout=20)
        if ns_out is None:
            return
        nameservers = parse_ns(ns_out) or [""]  # "" = default resolver fallback

        seen: set[str] = set()
        transferred = False
        for ns in nameservers:
            cmd = ["dig", "AXFR", domain] + ([f"@{ns}"] if ns else [])
            out = await self.run_proc(cmd, timeout=self.opt("timeout"),
                                      bucket=f"axfr:{ns or 'default'}")
            if not out:
                continue
            names, ok = parse_axfr(out, domain)
            if ok and names:
                transferred = True
            for h in names:
                if h in seen:
                    continue
                seen.add(h)
                await self.emit(
                    EventType.SUBDOMAIN,
                    SubdomainData(hostname=h, source="zonetransfer"),
                )

        if transferred:
            self._log.warning("AXFR zone transfer ALLOWED for %s", domain)
            await self.emit(
                EventType.FINDING_CANDIDATE,
                FindingCandidateData(
                    host=domain,
                    title="DNS zone transfer (AXFR) allowed",
                    description=(
                        "An authoritative nameserver allowed a full AXFR zone "
                        "transfer, disclosing internal DNS records."
                    ),
                    category="dns-zone-transfer",
                    severity_hint="high",
                    evidence={"records_disclosed": len(seen)},
                ),
            )
