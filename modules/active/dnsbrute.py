"""
dnsbrute — Active subdomain brute-force via dnsx.

Seed module: resolves a wordlist of common subdomain names against the target
domain with dnsx and emits SUBDOMAIN events for those that resolve. Wildcard
DNS is filtered via `dnsx -wd` so catch-all domains don't flood the scan with
false positives.

Bounded: runs once against the apex domain. Depth beyond the wordlist comes
from the permutations module operating on what this (and passive sources) find.

Produces: SUBDOMAIN
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

_BUNDLED_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "dns_names.txt"


@register
class DnsBruteModule(BaseModule):
    name = "dnsbrute"
    description = "Active subdomain brute-force via dnsx wordlist resolution"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "brute", "slow"]
    options = {
        "wordlist": "",     # absolute path; empty = bundled dns_names.txt
        "timeout": 300,
        "rate_limit": 0,    # dnsx -rl (queries/sec); 0 = dnsx default
    }
    deps_binary = ["dnsx"]

    async def run(self, domain: str, scan_id: UUID) -> None:
        wordlist = self.opt("wordlist") or str(_BUNDLED_WORDLIST)
        if not Path(wordlist).exists():
            self._log.warning("dnsbrute: wordlist not found: %s", wordlist)
            return

        cmd = [
            "dnsx",
            "-silent", "-nc",
            "-d", domain,
            "-w", wordlist,
            "-wd", domain,      # wildcard filtering rooted at the target
        ]
        rate = self.opt("rate_limit")
        if rate and int(rate) > 0:
            cmd += ["-rl", str(rate)]

        self._log.info("dnsbrute: brute-forcing %s (wordlist=%s)", domain, wordlist)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            self._log.warning("dnsbrute timed out after %ds", self.opt("timeout"))
            return
        except FileNotFoundError:
            self._log.warning("dnsx binary not found — dnsbrute disabled")
            return
        except Exception as exc:
            self._log.error("dnsbrute failed: %s", exc)
            return

        seen: set[str] = set()
        count = 0
        for raw in stdout.decode(errors="replace").splitlines():
            host = raw.strip().lower().rstrip(".")
            if not host or host in seen:
                continue
            # dnsx brute mode prints bare resolving FQDNs; keep only ones under
            # the target domain (defensive — never trust tool output blindly).
            if host != domain and not host.endswith("." + domain):
                continue
            seen.add(host)
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=host, source="dnsbrute"),
            ):
                count += 1

        self._log.info("dnsbrute: %d resolved subdomains for %s", count, domain)
