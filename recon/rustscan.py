"""
RustScan wrapper — fast open-port discovery.

The discovery half of a "RustScan finds, nmap identifies" combo that mirrors the
existing "naabu finds, nmap identifies" pairing: RustScan finds open ports fast;
the separate (independently capability-gated) nmap module reacts to the emitted
OPEN_PORT events and runs `-sV` for service/version detection. RustScan is run
in **greppable mode** (`-g`) with `--scripts none`, so it only prints ports and
never spawns nmap or any script as a side effect of port discovery — service
detection stays an explicit, separately-gated follow-up.

Upstream: https://github.com/bee-san/RustScan  (RustScan/RustScan)
CLI verified against src/input.rs (master): greppable output is one line per
host, `IP -> [p1,p2,...]`, ports comma-separated with no spaces.

Safe by construction:
  * single target per invocation (`-a <ip>`) — the caller never passes a CIDR,
    so port discovery can never expand the authorized target range;
  * greppable + `--scripts none` — no nmap, no NSE, no exploitation;
  * conservative batch size / timeout defaults, below RustScan's own aggressive
    defaults (batch 4500), tunable by the caller;
  * runs under the shared RateLimiter like every other outbound tool;
  * fail-soft: a missing binary, timeout, bad exit, or malformed output yields an
    empty result and the scan continues. `asyncio.CancelledError` propagates.

`build_command` and `parse_greppable` are pure and unit-tested directly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re

log = logging.getLogger(__name__)

_NOT_FOUND_WARNED = False

# Conservative defaults (RustScan's own are more aggressive — batch 4500).
DEFAULT_BATCH_SIZE = 1500
# 3000 ms (above RustScan's own 1500): a short per-port timeout silently drops a
# slow-responding open port on a remote target (a false negative is worse for
# recon than a slightly slower scan). Tunable down for fast/local targets.
DEFAULT_TIMEOUT_MS = 3000
DEFAULT_TRIES = 1
DEFAULT_SCAN_ORDER = "serial"

_GREP_RE = re.compile(r"^\s*(\S+)\s*->\s*\[(.*)\]\s*$")


class RustScanError(ValueError):
    """Invalid arguments for a RustScan invocation (fail closed, never scan)."""


def _valid_scan_order(order: str) -> str:
    o = (order or "").strip().lower()
    if o not in ("serial", "random"):
        raise RustScanError(f"invalid scan_order {order!r} (serial|random)")
    return o


def _port_list(ports) -> list[int]:
    """Normalize a ports spec into a sorted list of unique 1..65535 ints.

    Accepts an int, a comma string ("80,443"), or an iterable of ints/strings.
    Raises RustScanError on anything out of range or unparseable — we never
    silently drop a requested port or pass junk to the binary.
    """
    if ports is None:
        return []
    if isinstance(ports, int):
        raw = [ports]
    elif isinstance(ports, str):
        raw = [p for p in re.split(r"[,\s]+", ports.strip()) if p]
    else:
        raw = list(ports)
    out: set[int] = set()
    for p in raw:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise RustScanError(f"invalid port {p!r}")
        if not (1 <= n <= 65535):
            raise RustScanError(f"port out of range: {n}")
        out.add(n)
    return sorted(out)


def build_command(
    target: str,
    *,
    ports=None,
    top: bool = True,
    batch_size: int = DEFAULT_BATCH_SIZE,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    tries: int = DEFAULT_TRIES,
    ulimit: int | None = None,
    exclude_ports=None,
    scan_order: str = DEFAULT_SCAN_ORDER,
    binary: str = "rustscan",
) -> list[str]:
    """Build the RustScan argument vector for a single target. Pure.

    Always greppable + `--scripts none` + `--no-banner` so the run only prints
    ports and never launches nmap/scripts. `top` uses RustScan's top-1000 list;
    explicit `ports` override it (and disable `top`). Raises RustScanError on an
    empty / flag-like target or an out-of-range port (arg-injection + range
    guard — a target starting with '-' must never reach the binary).
    """
    t = (target or "").strip()
    if not t:
        raise RustScanError("empty target")
    if t.startswith("-"):
        raise RustScanError(f"refusing flag-like target {target!r}")

    bs = int(batch_size)
    if bs < 1:
        raise RustScanError(f"batch_size must be >= 1, got {batch_size}")
    tmo = int(timeout_ms)
    if tmo < 1:
        raise RustScanError(f"timeout_ms must be >= 1, got {timeout_ms}")
    tr = int(tries)
    if tr < 1:
        raise RustScanError(f"tries must be >= 1, got {tries}")
    order = _valid_scan_order(scan_order)

    cmd = [
        binary,
        "-a", t,
        "-g",                 # greppable: only ports, no nmap
        "--scripts", "none",  # belt-and-suspenders: never run any script
        "--no-banner",
        "-b", str(bs),
        "-t", str(tmo),
        "--tries", str(tr),
        "--scan-order", order,
    ]
    if ulimit is not None:
        cmd += ["-u", str(int(ulimit))]

    explicit = _port_list(ports)
    if explicit:
        cmd += ["-p", ",".join(str(p) for p in explicit)]
    elif top:
        cmd += ["--top"]
    # else: neither → RustScan scans the full range (caller opted out of top).

    excl = _port_list(exclude_ports)
    if excl:
        cmd += ["--exclude-ports", ",".join(str(p) for p in excl)]

    return cmd


def parse_greppable(text: str) -> dict[str, list[int]]:
    """Parse RustScan greppable output (`IP -> [p1,p2,...]`) into {ip: [ports]}.

    Tolerant of blank lines, banner/noise lines that don't match, empty port
    lists (`[]`), IPv6 addresses, and junk port tokens (skipped individually).
    Never raises.
    """
    results: dict[str, list[int]] = {}
    for line in (text or "").splitlines():
        m = _GREP_RE.match(line)
        if not m:
            continue
        host = m.group(1).strip()
        if not host:
            continue
        ports: list[int] = []
        for tok in m.group(2).split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                n = int(tok)
            except ValueError:
                continue
            if 1 <= n <= 65535 and n not in ports:
                ports.append(n)
        if ports:
            results.setdefault(host, [])
            for p in ports:
                if p not in results[host]:
                    results[host].append(p)
    return {h: sorted(ps) for h, ps in results.items()}


def is_ip(value: str) -> bool:
    """True if `value` is a literal IPv4/IPv6 address (not a hostname/CIDR)."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


class RustScanWrapper:
    """Async wrapper around the `rustscan` binary, run under the shared limiter."""

    binary = "rustscan"

    def __init__(
        self,
        *,
        limiter=None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        tries: int = DEFAULT_TRIES,
        ulimit: int | None = None,
        scan_order: str = DEFAULT_SCAN_ORDER,
        run_timeout: int = 300,
    ) -> None:
        from ratelimit import NOOP
        self._limiter = limiter if limiter is not None else NOOP
        self._batch_size = batch_size
        self._timeout_ms = timeout_ms
        self._tries = tries
        self._ulimit = ulimit
        self._scan_order = scan_order
        self._run_timeout = run_timeout

    async def scan(
        self,
        target: str,
        *,
        ports=None,
        top: bool = True,
        exclude_ports=None,
    ) -> dict[str, list[int]]:
        """Scan a single authorized `target` (IP or hostname). Returns {ip: [ports]}.

        Fail-soft: returns {} on a missing binary, bad args, timeout, or a
        non-zero exit with no parseable output. Propagates CancelledError so an
        interrupted scan actually stops.
        """
        global _NOT_FOUND_WARNED

        try:
            cmd = build_command(
                target,
                ports=ports,
                top=top,
                batch_size=self._batch_size,
                timeout_ms=self._timeout_ms,
                tries=self._tries,
                ulimit=self._ulimit,
                exclude_ports=exclude_ports,
                scan_order=self._scan_order,
                binary=self.binary,
            )
        except RustScanError as exc:
            log.warning("[rustscan] refusing to run: %s", exc)
            return {}

        log.debug("[rustscan] exec: %s", " ".join(cmd))

        async with self._limiter.guard(f"rustscan:{target}"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                if not _NOT_FOUND_WARNED:
                    log.warning(
                        "[rustscan] binary not found — port discovery skipped "
                        "(install RustScan or add it to PATH)"
                    )
                    _NOT_FOUND_WARNED = True
                return {}
            except Exception as exc:  # pragma: no cover - exec edge cases
                log.error("[rustscan] failed to start: %s", exc)
                return {}

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._run_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:  # pragma: no cover
                    pass
                log.warning("[rustscan] timed out after %ds on %s",
                            self._run_timeout, target)
                return {}
            except asyncio.CancelledError:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:  # pragma: no cover
                    pass
                raise

        rc = proc.returncode
        if stderr:
            # Truncate — never dump uncontrolled subprocess output into logs.
            log.debug("[rustscan] stderr: %s", stderr.decode(errors="replace")[:512])
        out = stdout.decode(errors="replace") if stdout else ""
        results = parse_greppable(out)
        if rc not in (0, None) and not results:
            # Non-zero exit with nothing parseable — report the code, not the body.
            log.debug("[rustscan] exit code %s on %s, no ports parsed", rc, target)
        return results
