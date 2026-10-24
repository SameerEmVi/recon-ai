"""
ffuf wrapper — smart directory/content fuzzing via the ffuf binary.

Two responsibilities, split so the interesting logic is pure and unit-testable:

  1. `derive_calibration()` — the *smart* part. Given a handful of baseline
     probes (random, almost-certainly-nonexistent paths), decide what "noise"
     ffuf should filter so real content stands out. This handles the classic
     scenario where an app answers **301 (or 302/401/403/404) to everything**:
     for a redirect/error catch-all we filter the **status code** — what "filter
     out the 301s and hunt for other codes" means, and robust to body-size drift
     (a CDN/S3 error page whose length wobbles under load still gets filtered,
     where a single size value would leak the drifted responses). Only a **2xx**
     catch-all (a wildcard/SPA that 200s everything) is filtered by **size**,
     since we can't blanket-drop all 2xx. When the baseline is inconsistent we
     defer to ffuf's own `-ac`.

  2. `build_command()` / `parse_ffuf_json()` / `FfufWrapper.run()` — construct
     the ffuf invocation, run it under the shared rate limiter, and parse its
     `-of json` output.

The baseline probing itself happens in `modules/web/ffuf.py` (through the shared
limiter / WAF backoff, like every other HTTP op); this module only reasons about
the results and drives the binary.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import string
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False

# Length of the random token used to probe for a site's wildcard/catch-all baseline.
_RANDOM_TOKEN_LEN = 26


def generate_random_string(length: int = _RANDOM_TOKEN_LEN) -> str:
    """A lowercase-alnum token unlikely to exist as a real path (wildcard probe)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

# Status codes that never indicate a discovered resource, so they must never be
# emitted as a URL even though `-mc all` surfaces them:
#   400 — server rejected a malformed path (traversal/encoding payloads like
#         `/%2e%2e//google.com` or `\..\..\etc\passwd` produce these),
#   404 — not found,
#   429 — throttled,
#   500/502/503/504 — server/transient errors.
# 401/403/405 are deliberately NOT here: they mean "exists but protected / wrong
# method", which is interesting for recon (a catch-all 403 is handled separately
# by calibration's -fc).
NOISE_STATUS: frozenset[int] = frozenset({400, 404, 429, 500, 502, 503, 504})

# Back-compat alias (was the lone default-noise status).
_DEFAULT_NOISE_STATUS = 404


def is_real_find(status: int, length: int) -> bool:
    """True only if a ffuf row is a genuinely discovered resource.

    Drops noise statuses (see NOISE_STATUS) and empty-bodied 2xx responses — a
    `200 len=0` on a CDN/S3 host is a catch-all stub (e.g. CloudFront answering
    `/soap/servlet/Spy` with an empty 200), not real content, whereas a real file
    carries a body.
    """
    try:
        st, ln = int(status), int(length)
    except (TypeError, ValueError):
        return False
    if st <= 0 or st in NOISE_STATUS:
        return False
    if 200 <= st < 300 and ln == 0:
        return False
    return True


@dataclass
class FfufResult:
    url: str
    status: int
    length: int
    words: int = 0
    lines: int = 0
    fuzz: str = ""
    redirect: str = ""


@dataclass
class Calibration:
    """The filters ffuf should apply, plus a human-readable why (explainability)."""
    filter_codes: list[int] = field(default_factory=list)
    filter_sizes: list[int] = field(default_factory=list)
    auto_calibrate: bool = False   # fall back to ffuf's own -ac when we can't decide
    reason: str = ""


def derive_calibration(probes: list[tuple[int | None, int]]) -> Calibration:
    """Decide noise filters from baseline probes.

    `probes` is a list of (status, length) tuples from random non-existent
    paths. Returns a Calibration describing what to filter and why.
    """
    valid = [(s, ln) for (s, ln) in probes if s is not None]
    if not valid:
        # Couldn't learn a baseline (all probes failed) — let ffuf self-calibrate.
        return Calibration(
            auto_calibrate=True,
            reason="no baseline learned — enabling ffuf auto-calibration (-ac)",
        )

    statuses = {s for s, _ in valid}
    sizes = {ln for _, ln in valid}

    if len(statuses) == 1:
        st = next(iter(statuses))
        # A 2xx catch-all (SPA / wildcard that answers 200 for everything) can't
        # be filtered by status — we'd drop every real find too. Distinguish it
        # by response size instead.
        if 200 <= st < 300:
            if len(sizes) == 1:
                size = next(iter(sizes))
                return Calibration(
                    filter_sizes=[size],
                    reason=f"2xx catch-all at {size} bytes on random paths — "
                    f"filtering size {size} (keeps real 2xx of a different size)",
                )
            return Calibration(
                auto_calibrate=True,
                reason="2xx catch-all with varying size — enabling ffuf "
                "auto-calibration (-ac)",
            )
        # A redirect/error catch-all (the app 301/302/401/403/404s *everything*):
        # filter the STATUS CODE. This is what "filter out the 301s and hunt for
        # other codes" means, and it's robust to body-size drift — a CDN/S3 403
        # page whose length wobbles under load (263→243B) still gets filtered,
        # where a single -fs value would leak the drifted responses.
        return Calibration(
            filter_codes=[st],
            reason=f"catch-all status {st} on random paths — filtering code {st} "
            f"(robust to body-size drift on CDN/error pages)",
        )

    # Multiple statuses among random paths. If they at least share one size,
    # that shared size is the wildcard body; otherwise defer to ffuf's -ac.
    if len(sizes) == 1:
        size = next(iter(sizes))
        return Calibration(
            filter_sizes=[size],
            reason=f"mixed statuses but constant {size}-byte body on random "
            f"paths — filtering size {size}",
        )
    return Calibration(
        auto_calibrate=True,
        reason="inconsistent baseline (varied status and size) — enabling "
        "ffuf auto-calibration (-ac)",
    )


def build_command(
    *,
    target_url: str,
    wordlist: str,
    output_file: str,
    extensions: list[str] | None = None,
    filter_codes: list[int] | None = None,
    filter_sizes: list[int] | None = None,
    match_codes: str = "all",
    auto_calibrate: bool = False,
    threads: int = 40,
    rate: int = 0,
    timeout: int = 10,
    max_time: int = 0,
    user_agent: str = "recon-ai/ffuf",
    recursion: bool = False,
    recursion_depth: int = 0,
    proxy: str | None = None,
    binary: str = "ffuf",
) -> list[str]:
    """Build a fully-formed ffuf argv. Pure — no side effects (unit-tested).

    ``max_time`` (seconds, 0 = unbounded) maps to ffuf ``-maxtime``: ffuf stops
    fuzzing when it elapses and **still writes its JSON output** with whatever it
    found so far. This is what keeps a big wordlist × low rate from producing
    *nothing* — without it, the subprocess timeout kills ffuf before it writes.
    """
    if "FUZZ" not in target_url:
        target_url = target_url.rstrip("/") + "/FUZZ"

    cmd: list[str] = [
        binary,
        "-u", target_url,
        "-w", wordlist,
        "-mc", match_codes,
        "-t", str(threads),
        "-rate", str(rate),
        "-timeout", str(timeout),
        "-H", f"User-Agent: {user_agent}",
        *(["-maxtime", str(max_time)] if max_time and max_time > 0 else []),
        "-o", output_file,
        "-of", "json",
        "-s",                # silent: no live progress on stdout
        "-noninteractive",   # never prompt
        *(["-x", proxy] if proxy else []),   # ffuf's proxy flag → route via Burp
    ]

    exts = [e for e in (extensions or []) if e]
    if exts:
        # ffuf wants dot-prefixed extensions, comma-joined.
        cmd += ["-e", ",".join(e if e.startswith(".") else f".{e}" for e in exts)]

    if filter_codes:
        cmd += ["-fc", ",".join(str(c) for c in sorted(set(filter_codes)))]
    if filter_sizes:
        cmd += ["-fs", ",".join(str(s) for s in sorted(set(filter_sizes)))]
    if auto_calibrate:
        cmd += ["-ac"]
    if recursion and recursion_depth > 0:
        cmd += ["-recursion", "-recursion-depth", str(recursion_depth)]

    return cmd


def parse_ffuf_json(text: str) -> list[FfufResult]:
    """Parse ffuf `-of json` output into FfufResult rows. Tolerant of junk."""
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []

    out: list[FfufResult] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url", "") or "")
        if not url:
            continue
        try:
            status = int(r.get("status", 0) or 0)
            length = int(r.get("length", 0) or 0)
            words = int(r.get("words", 0) or 0)
            lines = int(r.get("lines", 0) or 0)
        except (ValueError, TypeError):
            continue
        fuzz = ""
        inp = r.get("input")
        if isinstance(inp, dict):
            fuzz = str(inp.get("FUZZ", "") or "")
        out.append(
            FfufResult(
                url=url,
                status=status,
                length=length,
                words=words,
                lines=lines,
                fuzz=fuzz,
                redirect=str(r.get("redirectlocation", "") or ""),
            )
        )
    return out


class FfufWrapper:
    """Runs the ffuf binary under the shared rate limiter."""

    def __init__(self, timeout: int = 600, limiter=None) -> None:
        self._timeout = timeout
        from ratelimit import NOOP
        self._limiter = limiter if limiter is not None else NOOP

    async def run(self, cmd: list[str], *, bucket: str = "ffuf") -> bool:
        """Execute ffuf (which writes JSON to its -o file). Returns True on a
        clean completion, False on missing binary / timeout / launch error."""
        global _NOT_FOUND_WARNED
        log.debug("[ffuf] %s", " ".join(cmd))
        async with self._limiter.guard(bucket):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                if not _NOT_FOUND_WARNED:
                    log.warning("[ffuf] binary not found — skipping smart fuzzing")
                    _NOT_FOUND_WARNED = True
                return False
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                log.warning("[ffuf] timed out after %ds", self._timeout)
                return False
        if proc.returncode not in (0, None):
            log.debug("[ffuf] exit %s: %s", proc.returncode,
                      (stderr or b"").decode("utf-8", "replace")[:200])
        return True
