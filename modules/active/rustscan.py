"""
rustscan — fast open-port discovery via the RustScan binary.

Reactive module in the "RustScan discovers, nmap identifies" combo (the
RustScan counterpart to the naabu module): fires on each in-scope IP event,
runs RustScan in greppable mode, and emits OPEN_PORT events. The existing nmap
module — if loaded and permitted by the mode — reacts to those OPEN_PORT events
and performs `-sV` service/version detection, so service detection is an
explicit, independently capability-gated follow-up rather than a side effect of
port discovery.

It is an **alternative** to naabu, not an addition: it is not in the default
FULL set (so a single scan does not port-scan every IP twice). Select it
explicitly with `-m rustscan` or the `port-scan` flag.

Safety:
  * capability re-check at call time (PORT_SCANNING must be permitted by the
    mode) on top of the module-load filter;
  * the target IP is re-evaluated against the scope engine before scanning, and
    every IP in RustScan's output is scope-checked before its ports are emitted
    — the authorized range is never expanded by a discovered/co-resolved IP;
  * all OPEN_PORT emission goes through emit → stamp_and_publish → ScopeEngine,
    so the scope gate applies unconditionally regardless of the local checks;
  * runs under the shared RateLimiter; conservative batch/timeout defaults.

Watches:  IP
Produces: OPEN_PORT
Requires: rustscan on PATH (warn-and-skip otherwise)
"""

from __future__ import annotations

from events.types import Event, EventType, OpenPortData
from modules.base import BaseModule
from modules.registry import register
from scope.engine import ScopeEngine


@register
class RustScanModule(BaseModule):
    name = "rustscan"
    description = "Fast open-port discovery via RustScan (alternative to naabu)"
    watched_events = ["IP"]
    produced_events = ["OPEN_PORT"]
    flags = ["active", "port-scan", "slow"]
    deps_binary = ["rustscan"]
    # Behaviour-audited capability (also in policy.MODULE_CAPABILITIES). Declared
    # here too so the mode ceiling is unambiguous for this module.
    capabilities = ["PORT_SCANNING"]
    estimated_cost = 5
    # Port discovery is high-value recon; without an explicit value the planner
    # scores cost(5) against the default value(3) → -2 and skips it (the same
    # bug that silently disabled naabu). HIGH value → score 3, runs by default.
    expected_value = 8
    options = {
        "ports": "top-1000",       # "top-1000" | "full" | "80,443,8080"
        "batch_size": 1500,        # conservative (RustScan default is 4500)
        "timeout_ms": 3000,        # per-port connect timeout (higher = fewer missed ports)
        "tries": 1,
        "ulimit": None,            # pass-through to RustScan -u (None = leave to OS)
        "scan_order": "serial",    # serial | random
        "exclude_ports": None,     # e.g. "22,3389"
        "timeout": 300,            # overall subprocess timeout (seconds)
    }

    def _scope_ok(self, ip: str) -> bool:
        """Re-evaluate an IP against the real scope engine (defence in depth).

        The triggering IP event already passed the gate at publish time, and
        every emitted OPEN_PORT is gated again; this is an early, explicit
        refusal. Under a mock controller (unit tests) there is no real
        ScopeEngine, so we defer to the unconditional emit-time gate.
        """
        engine = getattr(self._ctrl, "scope_engine", None)
        if not isinstance(engine, ScopeEngine):
            return True
        from scope.types import ScopeStatus
        return engine.evaluate(ip).status is ScopeStatus.IN

    def _ports_spec(self):
        """Translate the `ports` option into (ports, top) for the wrapper."""
        spec = str(self.opt("ports") or "").strip().lower()
        if spec in ("", "top-1000", "top1000", "top"):
            return None, True
        if spec == "full":
            return None, False   # neither -p nor --top → full range
        return spec, False

    async def handle_event(self, event: Event) -> None:
        from policy import CAP_PORT_SCANNING
        if not self.capability_ok(CAP_PORT_SCANNING, action="rustscan port scan"):
            return

        ip = getattr(event.data, "address", "") or ""
        if not ip:
            return

        # Enforce scope on the target BEFORE scanning — never scan an IP that is
        # not explicitly in scope, and never expand to its network.
        if not self._scope_ok(ip):
            self._log.warning("[rustscan] target %s not in scope — skipping", ip)
            return

        from recon.rustscan import RustScanWrapper

        ports, top = self._ports_spec()
        wrapper = RustScanWrapper(
            limiter=self.rate_limiter,
            batch_size=int(self.opt("batch_size")),
            timeout_ms=int(self.opt("timeout_ms")),
            tries=int(self.opt("tries")),
            ulimit=self.opt("ulimit"),
            scan_order=str(self.opt("scan_order")),
            run_timeout=int(self.opt("timeout")),
        )
        results = await wrapper.scan(
            ip, ports=ports, top=top, exclude_ports=self.opt("exclude_ports")
        )

        count = 0
        for found_ip, found_ports in results.items():
            # A co-resolved / unexpected IP in the output must still be in scope
            # before we touch its ports (the emit-time gate enforces this too).
            if not self._scope_ok(found_ip):
                self._log.warning(
                    "[rustscan] dropping out-of-scope result IP %s", found_ip)
                continue
            for port in found_ports:
                if await self.emit(
                    EventType.OPEN_PORT,
                    OpenPortData(host=found_ip, port=port, protocol="tcp"),
                    source_event=event,
                ):
                    count += 1

        self._log.info("rustscan: %d open port(s) on %s", count, ip)
