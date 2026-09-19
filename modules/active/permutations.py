"""
permutations — Active subdomain permutation/mutation discovery.

Reactive module (bounded): for each originally-discovered in-scope subdomain,
generates dnsgen/altdns-style permutations (affix, numeric, env-word swap,
dash/dot variants), resolves the candidates with dnsx, and emits SUBDOMAIN
events for the ones that resolve.

Bounded to keep recursion finite:
  - never permutes its own output (source_tool == self.name is skipped)
  - each hostname is permuted at most once (per-scan dedup set)
  - candidates per host capped by `max_candidates`

Watches:  SUBDOMAIN
Produces: SUBDOMAIN
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from events.types import Event, EventType, SubdomainData
from modules.base import BaseModule
from modules.registry import register

# Words swapped in/out of environment-labelled hosts (api.dev → api.prod).
_ENV_WORDS = [
    "dev", "development", "staging", "stage", "stg", "test", "testing", "qa",
    "uat", "prod", "production", "demo", "sandbox", "beta", "alpha", "preview",
    "int", "internal", "external", "new", "old", "legacy", "live",
]

# Generic affixes bolted onto the leading label.
_AFFIXES = [
    "dev", "staging", "test", "qa", "uat", "prod", "admin", "api", "internal",
    "new", "old", "beta", "v1", "v2", "1", "2", "01", "02", "backup", "dr", "edge",
]


def generate_permutations(
    hostname: str,
    max_candidates: int = 250,
    words: list[str] | None = None,
    env_words: list[str] | None = None,
) -> list[str]:
    """Return permutation candidate FQDNs for `hostname`.

    Pure function — no network. Operates on the sub-part before the registrable
    root (heuristically the last two labels). Apex / single-label hosts return
    [] since brute-forcing those is the dnsbrute module's job.
    """
    words = words if words is not None else _AFFIXES
    env_words = env_words if env_words is not None else _ENV_WORDS

    host = hostname.strip().lower().rstrip(".")
    labels = host.split(".")
    if len(labels) < 3:
        return []

    root = ".".join(labels[-2:])
    sub = host[: -(len(root) + 1)]          # part before ".root"
    sub_labels = sub.split(".")
    head = sub_labels[0]
    tail = "." + ".".join(sub_labels[1:]) if len(sub_labels) > 1 else ""

    cands: list[str] = []
    seen: set[str] = set()

    def add(new_sub: str) -> None:
        new_sub = new_sub.strip(".-").lower()
        if not new_sub:
            return
        fqdn = f"{new_sub}.{root}"
        if fqdn == host or fqdn in seen:
            return
        seen.add(fqdn)
        cands.append(fqdn)

    # 1) affixes on the sub / leading label
    for w in words:
        add(f"{w}-{sub}")
        add(f"{w}.{sub}")
        add(f"{sub}-{w}")
        add(f"{head}-{w}{tail}")
        add(f"{head}{w}{tail}")

    # 2) numeric neighbours on the leading label
    m = re.match(r"^(.*?)(\d+)$", head)
    if m:
        stem, num = m.group(1), m.group(2)
        width, n = len(num), int(m.group(2))
        for d in (n - 1, n + 1, n + 2):
            if d >= 0:
                add(f"{stem}{str(d).zfill(width)}{tail}")
    else:
        for suf in ("1", "2", "01", "02"):
            add(f"{head}{suf}{tail}")

    # 3) env-word replacement anywhere in the sub labels
    for i, lab in enumerate(sub_labels):
        if lab in env_words:
            for w in env_words:
                if w != lab:
                    swapped = list(sub_labels)
                    swapped[i] = w
                    add(".".join(swapped))

    # 4) dash/dot swaps
    if "-" in sub:
        add(sub.replace("-", "."))
    if "." in sub:
        add(sub.replace(".", "-"))

    return cands[:max_candidates]


@register
class PermutationsModule(BaseModule):
    name = "permutations"
    description = "Active subdomain permutation/mutation discovery via dnsx"
    watched_events = ["SUBDOMAIN"]
    produced_events = ["SUBDOMAIN"]
    flags = ["active", "dns", "subdomain-enum", "permutation", "slow"]
    options = {"timeout": 120, "max_candidates": 250}
    deps_binary = ["dnsx"]

    def __init__(self, controller: Any, config: dict[str, Any] | None = None) -> None:
        super().__init__(controller, config)
        self._permuted: set[str] = set()

    async def handle_event(self, event: Event) -> None:
        # Bounded-recursion guard: our own output must not feed back in.
        if event.source_tool == self.name:
            return

        host = event.data.hostname
        if not host or host in self._permuted:
            return
        self._permuted.add(host)

        candidates = generate_permutations(
            host, max_candidates=int(self.opt("max_candidates"))
        )
        if not candidates:
            return

        resolved = await self._resolve(candidates)
        count = 0
        for hostname in resolved:
            if await self.emit(
                EventType.SUBDOMAIN,
                SubdomainData(hostname=hostname, source="permutations"),
                source_event=event,
            ):
                count += 1
        if count:
            self._log.info("permutations: %d new subdomains from %s", count, host)

    async def _resolve(self, candidates: list[str]) -> list[str]:
        """Resolve candidate FQDNs via dnsx (stdin), filtering wildcards."""
        wildcard_root = ".".join(candidates[0].split(".")[-2:])
        cmd = ["dnsx", "-silent", "-nc", "-wd", wildcard_root]
        payload = ("\n".join(candidates) + "\n").encode()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=payload), timeout=self.opt("timeout")
            )
        except asyncio.TimeoutError:
            self._log.warning("permutations: dnsx resolve timed out")
            return []
        except FileNotFoundError:
            self._log.warning("dnsx binary not found — permutations disabled")
            return []
        except Exception as exc:
            self._log.error("permutations resolve failed: %s", exc)
            return []

        out: list[str] = []
        for raw in stdout.decode(errors="replace").splitlines():
            h = raw.strip().lower().rstrip(".")
            if h:
                out.append(h)
        return out
