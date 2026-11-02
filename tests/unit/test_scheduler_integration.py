"""
Tests for the hybrid engine's controller integration (scheduler.integration) and
the CLI surface: module-spec derivation (valid DAG), target-file loading, the
subdomain runner, the end-to-end controller --hybrid path (scope per target,
dedup, report), and CLI flag validation + scan-status.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scheduler.engine import HybridScheduler
from scheduler.integration import build_subdomain_runner, derive_module_specs, load_targets_file


# ── module-spec derivation ─────────────────────────────────────────────────────

def _fake_module(name, watched, produced, flags=()):
    m = MagicMock()
    m.name = name
    m.watched_events = list(watched)
    m.produced_events = list(produced)
    m.flags = list(flags)
    return m


def test_derive_specs_producer_to_watcher_dependency():
    mods = [
        _fake_module("httpx_probe", watched=["SUBDOMAIN"], produced=["HTTP_SERVICE"]),
        _fake_module("fingerprint", watched=["HTTP_SERVICE"], produced=["TECHNOLOGY"]),
        _fake_module("subfinder", watched=[], produced=["SUBDOMAIN"], flags=["passive"]),
    ]
    specs = {s.name: s for s in derive_module_specs(mods)}
    assert "httpx_probe" in specs["fingerprint"].requires       # watches HTTP_SERVICE it produces
    assert "subfinder" in specs["httpx_probe"].requires          # produces SUBDOMAIN
    assert specs["subfinder"].passive and specs["subfinder"].priority < specs["httpx_probe"].priority


def test_derive_specs_is_always_a_valid_dag_even_with_cycles():
    # two modules that both watch AND produce URL would cycle; derivation must
    # break it so HybridScheduler (which rejects cycles) accepts the result.
    mods = [
        _fake_module("a", watched=["URL"], produced=["URL"]),
        _fake_module("b", watched=["URL"], produced=["URL"]),
    ]
    specs = derive_module_specs(mods)
    # must construct without raising (DAG valid)
    HybridScheduler(
        scan_id=uuid.uuid4(), scope_engine=MagicMock(), module_specs=specs,
        module_runner=AsyncMock(return_value=True),
    )


# ── targets file ──────────────────────────────────────────────────────────────

def test_load_targets_file_parses_dedups_comments(tmp_path):
    p = tmp_path / "subs.txt"
    p.write_text("# authorized\nAPI.ex.com\napi.ex.com.\n\n  b.ex.com  # note\n", encoding="utf-8")
    assert load_targets_file(str(p)) == ["api.ex.com", "b.ex.com"]


# ── subdomain runner ────────────────────────────────────────────────────────────

async def test_subdomain_runner_seeds_target_via_chokepoint():
    ctrl = MagicMock()
    ctrl.scan_id = uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    runner = build_subdomain_runner(ctrl)
    ok = await runner("a.ex.com", "pipeline")
    assert ok is True
    ctrl.stamp_and_publish.assert_awaited_once()
    seeded = ctrl.stamp_and_publish.await_args.args[0]
    assert seeded.data.hostname == "a.ex.com"
    from scope.types import ScopeStatus
    assert seeded.scope_status is ScopeStatus.IN        # pre-stamped (scheduler already validated)


# ── end-to-end controller --hybrid path (no network) ────────────────────────────

async def test_controller_hybrid_seeds_each_in_scope_target():
    from controller.controller import ScanController
    from events.types import EventType
    from scope.types import Scope

    ctrl = ScanController(
        Scope.from_strings(in_scope=["*.ex.com", "ex.com"]),
        results_enabled=False, hybrid=True,
        hybrid_targets=["a.ex.com", "b.ex.com", "evil.com"],   # evil.com is out of scope
    )
    seen: list[str] = []

    async def handler(event):
        seen.append(event.data.hostname)

    async def fake_load():
        ctrl._bus.subscribe(EventType.SUBDOMAIN, handler)       # one fake reactive module
        ctrl._loaded_modules = []
        return ([], [])

    with patch.object(ctrl, "_load_and_setup_modules", new=fake_load):
        await ctrl._do_run_hybrid("ex.com")

    assert set(seen) == {"a.ex.com", "b.ex.com"}                # out-of-scope never seeded
    rep = ctrl.scheduler_report
    assert rep.targets_total == 3
    assert rep.targets_out_of_scope == 1
    assert rep.targets_completed == 2


# ── CLI validation ──────────────────────────────────────────────────────────────

def test_cli_targets_file_missing_fails():
    from typer.testing import CliRunner
    from cli.main import app
    r = CliRunner().invoke(app, ["scan", "ex.com", "--hybrid", "--targets-file", "/no/such/file.txt"])
    assert r.exit_code == 1
    assert "targets-file not found" in r.output


def test_cli_scan_status_rejects_bad_uuid():
    from typer.testing import CliRunner
    from cli.main import app
    r = CliRunner().invoke(app, ["scan-status", "not-a-uuid", "--db-url", "sqlite+aiosqlite://"])
    assert r.exit_code == 1
    assert "not a valid scan id" in r.output
