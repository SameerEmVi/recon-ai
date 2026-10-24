"""
RustScan wrapper + module tests.

Pure-function coverage (command construction, greppable parsing) plus wrapper
behaviour (missing binary, timeout, non-zero exit, cancellation) and module
behaviour (event emission, scope enforcement, capability gating, nmap-follow-up
wiring) — all with mocks/fixtures. No live network scanning.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from events.types import EventType, IpData, OpenPortData
from modules.registry import ModuleRegistry
from recon.rustscan import (
    RustScanError,
    RustScanWrapper,
    build_command,
    is_ip,
    parse_greppable,
)


# ── build_command (pure) ──────────────────────────────────────────────────────

def test_build_command_defaults_are_safe():
    cmd = build_command("10.0.0.5")
    assert cmd[0] == "rustscan"
    assert "-a" in cmd and "10.0.0.5" in cmd
    # greppable + no-script guarantees: never spawns nmap / scripts.
    assert "-g" in cmd
    assert cmd[cmd.index("--scripts") + 1] == "none"
    assert "--no-banner" in cmd
    assert "--top" in cmd                      # default port set
    assert "-p" not in cmd
    # conservative defaults
    assert cmd[cmd.index("-b") + 1] == "1500"
    assert cmd[cmd.index("-t") + 1] == "3000"


def test_build_command_explicit_ports_override_top():
    cmd = build_command("example.com", ports="443,80,443")
    assert "--top" not in cmd
    # normalized: sorted + de-duped
    assert cmd[cmd.index("-p") + 1] == "80,443"


def test_build_command_full_range_when_top_false_and_no_ports():
    cmd = build_command("10.0.0.5", top=False)
    assert "--top" not in cmd and "-p" not in cmd


def test_build_command_exclude_ports():
    cmd = build_command("10.0.0.5", exclude_ports="22,3389")
    assert cmd[cmd.index("--exclude-ports") + 1] == "22,3389"


def test_build_command_passes_ulimit():
    cmd = build_command("10.0.0.5", ulimit=5000)
    assert cmd[cmd.index("-u") + 1] == "5000"


@pytest.mark.parametrize("bad", ["-oN/tmp/x", "-a", "--top", ""])
def test_build_command_refuses_flag_like_or_empty_target(bad):
    with pytest.raises(RustScanError):
        build_command(bad)


@pytest.mark.parametrize("bad_ports", ["0", "70000", "abc", "-1"])
def test_build_command_rejects_bad_ports(bad_ports):
    with pytest.raises(RustScanError):
        build_command("10.0.0.5", ports=bad_ports)


def test_build_command_rejects_bad_scan_order():
    with pytest.raises(RustScanError):
        build_command("10.0.0.5", scan_order="stealthy")


def test_build_command_rejects_nonpositive_tuning():
    with pytest.raises(RustScanError):
        build_command("10.0.0.5", batch_size=0)
    with pytest.raises(RustScanError):
        build_command("10.0.0.5", timeout_ms=0)
    with pytest.raises(RustScanError):
        build_command("10.0.0.5", tries=0)


# ── parse_greppable (pure) ────────────────────────────────────────────────────

def test_parse_greppable_single_host():
    out = parse_greppable("10.0.0.5 -> [22,80,443]")
    assert out == {"10.0.0.5": [22, 80, 443]}


def test_parse_greppable_multiple_hosts_and_noise():
    text = (
        "Banner line that should be ignored\n"
        "\n"
        "10.0.0.5 -> [80,443]\n"
        "10.0.0.6 -> [8080]\n"
        "garbage -> not-a-list\n"
    )
    assert parse_greppable(text) == {"10.0.0.5": [80, 443], "10.0.0.6": [8080]}


def test_parse_greppable_ipv6():
    out = parse_greppable("2001:db8::1 -> [443]")
    assert out == {"2001:db8::1": [443]}


def test_parse_greppable_empty_list_and_junk_ports():
    assert parse_greppable("10.0.0.5 -> []") == {}
    assert parse_greppable("10.0.0.5 -> [80, x, 70000, 443]") == {"10.0.0.5": [80, 443]}


def test_parse_greppable_empty_and_none():
    assert parse_greppable("") == {}
    assert parse_greppable(None) == {}


def test_is_ip():
    assert is_ip("10.0.0.5") and is_ip("2001:db8::1")
    assert not is_ip("example.com") and not is_ip("10.0.0.0/24")


# ── wrapper (subprocess mocked) ───────────────────────────────────────────────

def _fake_proc(stdout=b"", stderr=b"", returncode=0, *, hang=False, cancel=False):
    proc = MagicMock()
    proc.returncode = returncode
    if hang:
        proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    elif cancel:
        proc.communicate = AsyncMock(side_effect=asyncio.CancelledError())
    else:
        proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=None)
    return proc


async def test_wrapper_parses_open_ports():
    proc = _fake_proc(stdout=b"10.0.0.5 -> [22,443]\n")
    with patch("recon.rustscan.asyncio.create_subprocess_exec",
               AsyncMock(return_value=proc)):
        res = await RustScanWrapper().scan("10.0.0.5")
    assert res == {"10.0.0.5": [22, 443]}


async def test_wrapper_missing_binary_returns_empty():
    import recon.rustscan as rs
    rs._NOT_FOUND_WARNED = False
    with patch("recon.rustscan.asyncio.create_subprocess_exec",
               AsyncMock(side_effect=FileNotFoundError())):
        res = await RustScanWrapper().scan("10.0.0.5")
    assert res == {}


async def test_wrapper_timeout_returns_empty_and_kills():
    proc = _fake_proc(hang=True)
    with patch("recon.rustscan.asyncio.create_subprocess_exec",
               AsyncMock(return_value=proc)):
        res = await RustScanWrapper(run_timeout=1).scan("10.0.0.5")
    assert res == {}
    proc.kill.assert_called_once()


async def test_wrapper_cancellation_propagates():
    proc = _fake_proc(cancel=True)
    with patch("recon.rustscan.asyncio.create_subprocess_exec",
               AsyncMock(return_value=proc)):
        with pytest.raises(asyncio.CancelledError):
            await RustScanWrapper().scan("10.0.0.5")
    proc.kill.assert_called_once()


async def test_wrapper_nonzero_exit_no_output_is_empty():
    proc = _fake_proc(stdout=b"", stderr=b"boom", returncode=1)
    with patch("recon.rustscan.asyncio.create_subprocess_exec",
               AsyncMock(return_value=proc)):
        res = await RustScanWrapper().scan("10.0.0.5")
    assert res == {}


async def test_wrapper_bad_target_never_execs():
    exec_mock = AsyncMock()
    with patch("recon.rustscan.asyncio.create_subprocess_exec", exec_mock):
        res = await RustScanWrapper().scan("-oN/tmp/x")
    assert res == {}
    exec_mock.assert_not_called()


# ── module ────────────────────────────────────────────────────────────────────

def _controller(*, scope=None, policy=None):
    from ratelimit import NOOP
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.rate_limiter = NOOP
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    # Real scope engine when provided (for scope-enforcement tests); otherwise a
    # MagicMock, which _scope_ok treats as "no real engine → defer to emit gate".
    if scope is not None:
        from scope.engine import ScopeEngine
        ctrl.scope_engine = ScopeEngine(scope)
    if policy is not None:
        ctrl.policy = policy
    return ctrl


def _ip_event(addr="10.0.0.5"):
    ev = MagicMock()
    ev.data = IpData(address=addr)
    ev.id = uuid.uuid4()
    ev.distance = 2
    ev.type = EventType.IP
    return ev


def _load(ctrl):
    ModuleRegistry.discover()
    return ModuleRegistry.load(names=["rustscan"], controller=ctrl)[0]


async def test_module_emits_open_ports():
    ctrl = _controller()
    m = _load(ctrl)
    with patch("recon.rustscan.RustScanWrapper.scan",
               AsyncMock(return_value={"10.0.0.5": [22, 443]})):
        await m.handle_event(_ip_event("10.0.0.5"))
    # two OPEN_PORT emissions through the scope gate
    assert ctrl.stamp_and_publish.await_count == 2
    emitted = {c.args[0].data.port for c in ctrl.stamp_and_publish.await_args_list}
    assert emitted == {22, 443}
    ev0 = ctrl.stamp_and_publish.await_args_list[0].args[0]
    assert ev0.type is EventType.OPEN_PORT
    assert isinstance(ev0.data, OpenPortData) and ev0.data.host == "10.0.0.5"


async def test_module_refuses_out_of_scope_target():
    from scope.types import Scope
    ctrl = _controller(scope=Scope.from_strings(in_scope=["10.0.0.0/24"]))
    m = _load(ctrl)
    scan = AsyncMock(return_value={})
    with patch("recon.rustscan.RustScanWrapper.scan", scan):
        await m.handle_event(_ip_event("192.168.1.9"))   # outside 10.0.0.0/24
    scan.assert_not_called()                              # never scanned
    ctrl.stamp_and_publish.assert_not_awaited()


async def test_module_drops_out_of_scope_result_ip():
    from scope.types import Scope
    ctrl = _controller(scope=Scope.from_strings(in_scope=["10.0.0.0/24"]))
    m = _load(ctrl)
    # RustScan returns the scanned IP plus a co-resolved out-of-scope one.
    ret = {"10.0.0.5": [443], "8.8.8.8": [53]}
    with patch("recon.rustscan.RustScanWrapper.scan", AsyncMock(return_value=ret)):
        await m.handle_event(_ip_event("10.0.0.5"))
    hosts = {c.args[0].data.host for c in ctrl.stamp_and_publish.await_args_list}
    assert hosts == {"10.0.0.5"}                          # 8.8.8.8 dropped


async def test_module_blocked_when_capability_denied():
    from policy import CapabilityPolicy
    ctrl = _controller(policy=CapabilityPolicy("osint"))   # no PORT_SCANNING
    m = _load(ctrl)
    scan = AsyncMock(return_value={})
    with patch("recon.rustscan.RustScanWrapper.scan", scan):
        await m.handle_event(_ip_event("10.0.0.5"))
    scan.assert_not_called()


async def test_module_setup_skips_without_binary():
    ctrl = _controller()
    m = _load(ctrl)
    with patch("shutil.which", return_value=None):
        assert await m.setup() is False


async def test_module_setup_enabled_with_binary():
    ctrl = _controller()
    m = _load(ctrl)
    with patch("shutil.which", return_value="/usr/bin/rustscan"):
        assert await m.setup() is True


def test_nmap_followup_wiring():
    # The "RustScan discovers, nmap identifies" combo is pure event wiring:
    # rustscan produces OPEN_PORT, nmap watches OPEN_PORT. No live scan needed.
    ModuleRegistry.discover()
    rs = ModuleRegistry.get("rustscan")
    nmap = ModuleRegistry.get("nmap")
    assert "OPEN_PORT" in rs.produced_events
    assert "OPEN_PORT" in nmap.watched_events


def test_rustscan_not_in_default_full_set():
    # It is an alternative to naabu, opt-in only, so a full scan does not
    # port-scan every IP twice.
    from modules.registry import FULL_MODULES
    assert "rustscan" not in FULL_MODULES
    assert "naabu" in FULL_MODULES


def test_rustscan_classified_port_scanning():
    from policy.policy import MODULE_CAPABILITIES
    assert MODULE_CAPABILITIES["rustscan"] == frozenset({"PORT_SCANNING"})
