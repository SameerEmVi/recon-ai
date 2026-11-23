"""
dnsbrute — Active subdomain brute-force via dnsx, with wildcard-aware recovery.

Seed module: resolves a wordlist of common subdomain names against the target
with dnsx and emits SUBDOMAIN events for those that resolve.

Two-layer wildcard handling:
  1. DNS layer — the primary pass runs `dnsx -wd <domain>`, so on a catch-all
     domain the names that resolve ONLY to the wildcard IP set are dropped (they
     are indistinguishable from the wildcard and would flood the scan with false
     positives). Names with a distinct IP are emitted directly.
  2. HTTP layer (wildcard recovery) — DNS-layer filtering also discards a *real*
     host that happens to share the wildcard IP but serves different content
     (e.g. a real `api.` behind the same CloudFront as the `*.` catch-all). When
     a wildcard is present, a second pass re-runs dnsx WITHOUT `-wd` to recover
     every wildcard-covered name, then keeps only the ones whose HTTP response
     differs from the wildcard's own baseline response. Identical-content names
     (the pure catch-all) stay dropped — so `smtp/webmail/cpanel` on a CloudFront
     wildcard are correctly NOT emitted, while a content-distinct host is.

All HTTP goes through the shared limiter/cache/WAF-backoff via `BaseModule.fetch`
(capability TARGET_HTTP_REQUEST, like katana), is bounded by `max_http_probes`,
and the whole recovery pass is opt-outable via the `wildcard_http_probe` option.

Produces: SUBDOMAIN
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import string
from pathlib import Path
from uuid import UUID

from events.types import EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register
from policy import CAP_ACTIVE_DISCOVERY, CAP_TARGET_HTTP_REQUEST

_BUNDLED_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "dns_names.txt"


def _rand_label(n: int = 18) -> str:
    """A clearly-non-real DNS label for wildcard probing."""
    return "wc" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def response_signature(status: int | None, body: str | None) -> tuple | None:
    """A comparable fingerprint of one HTTP response: (status, sha1(body)[:16]).

    Pure + unit-tested. Returns None when there is no usable response (a failed
    fetch), so callers never treat a transport error as a 'distinct' host.
    """
    if status is None:
        return None
    digest = hashlib.sha1((body or "").encode("utf-8", "replace")).hexdigest()[:16]
    return (int(status), digest)


def is_distinct(host_sig: tuple | None, baseline_sigs: list, stable: bool) -> bool:
    """Decide whether a wildcard-covered host's response is distinct enough from
    the wildcard baseline to be a real host (pure + unit-tested).

    * No response → not distinct (don't resurrect something we couldn't fetch).
    * Stable wildcard (both baseline probes identical) → distinct iff the host's
      full signature is unseen in the baseline.
    * Dynamic wildcard (baseline probes differ → body hashing is unreliable, e.g.
      per-request nonces) → fall back to STATUS only: distinct iff the host's
      status code is not one the wildcard itself returns. Conservative: avoids
      re-introducing noise when content legitimately varies per request.
    """
    if host_sig is None:
        return False
    baseline = [s for s in baseline_sigs if s is not None]
    if not baseline:
        return False
    if stable:
        return host_sig not in baseline
    baseline_statuses = {s[0] for s in baseline}
    return host_sig[0] not in baseline_statuses


@register
class DnsBruteModule(BaseModule):
    name = "dnsbrute"
    description = "Active subdomain brute-force via dnsx wordlist resolution"
    watched_events = []
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "brute", "slow"]
    # Active enumeration + (for wildcard recovery) direct HTTP to the target —
    # same shape as katana. ACTIVE_DISCOVERY already gates this to active/full,
    # so the added HTTP capability never leaks it into osint/vuln.
    capabilities = frozenset({CAP_ACTIVE_DISCOVERY, CAP_TARGET_HTTP_REQUEST})
    options = {
        "wordlist": "",     # absolute path; empty = bundled dns_names.txt
        "timeout": 300,
        "rate_limit": 0,    # dnsx -rl (queries/sec); 0 = dnsx default
        # Wildcard recovery: HTTP-probe wildcard-covered names and keep the ones
        # whose content differs from the wildcard baseline.
        "wildcard_http_probe": True,
        "max_http_probes": 100,    # cap recovery HTTP requests per scan
    }
    deps_binary = ["dnsx"]

    async def _run_dnsx(self, domain: str, wordlist: str, *, wildcard: bool) -> set[str] | None:
        """Run one dnsx brute pass; return the set of resolving FQDNs under the
        target (None on failure). `wildcard=True` adds `-wd` (DNS-layer filter)."""
        cmd = ["dnsx", "-silent", "-nc", "-d", domain, "-w", wordlist]
        if wildcard:
            cmd += ["-wd", domain]
        rate = self.opt("rate_limit")
        if rate and int(rate) > 0:
            cmd += ["-rl", str(rate)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.opt("timeout"))
        except asyncio.TimeoutError:
            self._log.warning("dnsbrute timed out after %ds", self.opt("timeout"))
            return None
        except FileNotFoundError:
            self._log.warning("dnsx binary not found — dnsbrute disabled")
            return None
        except Exception as exc:
            self._log.error("dnsbrute failed: %s", exc)
            return None

        hosts: set[str] = set()
        for raw in stdout.decode(errors="replace").splitlines():
            host = raw.strip().lower().rstrip(".")
            if not host:
                continue
            # Keep only names under the target (defensive — never trust tool
            # output blindly).
            if host == domain or host.endswith("." + domain):
                hosts.add(host)
        return hosts

    async def _sig(self, host: str) -> tuple | None:
        """HTTP signature of a host: try https then http, through the shared
        fetch (limiter/cache/WAF). follow_redirects=False so a redirecting
        wildcard and a redirecting real host compare on their own responses."""
        for scheme in ("https", "http"):
            r = await self.fetch(
                f"{scheme}://{host}", timeout=12, max_body_kb=256, follow_redirects=False,
            )
            if getattr(r, "ok", False) or getattr(r, "status", None) is not None:
                return response_signature(getattr(r, "status", None), getattr(r, "text", None))
        return None

    async def run(self, domain: str, scan_id: UUID) -> None:
        wordlist = self.opt("wordlist") or str(_BUNDLED_WORDLIST)
        if not Path(wordlist).exists():
            self._log.warning("dnsbrute: wordlist not found: %s", wordlist)
            return

        self._log.info("dnsbrute: brute-forcing %s (wordlist=%s)", domain, wordlist)

        # ── Pass 1: wildcard-filtered — names with a distinct (non-wildcard) IP.
        distinct = await self._run_dnsx(domain, wordlist, wildcard=True)
        if distinct is None:
            return
        emitted = 0
        for host in sorted(distinct):
            if await self.emit(EventType.SUBDOMAIN, SubdomainData(hostname=host, source="dnsbrute")):
                emitted += 1
        self._log.info("dnsbrute: %d distinct-IP subdomains for %s", emitted, domain)

        if not self.opt("wildcard_http_probe"):
            return

        # ── Wildcard present? Resolve a couple of random labels. If they resolve,
        #    the domain is catch-all and real hosts may hide behind it.
        rand_hosts = [f"{_rand_label()}.{domain}" for _ in range(2)]
        wildcard_present = False
        for rh in rand_hosts:
            try:
                await asyncio.get_running_loop().getaddrinfo(rh, None)
                wildcard_present = True
                break
            except Exception:
                continue
        if not wildcard_present:
            return   # no wildcard → nothing was wrongly filtered

        # ── Pass 2: recover wildcard-covered names (no -wd), then HTTP-discriminate.
        all_hosts = await self._run_dnsx(domain, wordlist, wildcard=False)
        if not all_hosts:
            return
        covered = sorted(all_hosts - distinct)
        cap = max(0, int(self.opt("max_http_probes")))
        if cap and len(covered) > cap:
            self._log.info("dnsbrute: %d wildcard-covered names; probing first %d",
                           len(covered), cap)
            covered = covered[:cap]
        if not covered:
            return

        # Baseline: the wildcard's OWN HTTP responses (two random names).
        baseline = [await self._sig(rh) for rh in rand_hosts]
        stable = (
            baseline[0] is not None
            and len(baseline) >= 2
            and baseline[0] == baseline[1]
        )

        recovered = 0
        for host in covered:
            sig = await self._sig(host)
            if is_distinct(sig, baseline, stable):
                if await self.emit(
                    EventType.SUBDOMAIN,
                    SubdomainData(hostname=host, source="dnsbrute-wildcard"),
                ):
                    recovered += 1
        if recovered:
            self._log.info(
                "dnsbrute: recovered %d content-distinct host(s) behind the wildcard", recovered
            )
