"""
Increment 8 — diagnostics reader tests.

Run discovery + stream reads off a fabricated results dir (written by the real
DiagnosticsLogger, so the on-disk layout is exactly what the engine produces),
module filtering, path confinement to results_dir, and the proxy-check contract.
"""

from __future__ import annotations

import os

import httpx

from api.app import create_app
from api.config import Settings
from api.diagnostics import list_runs, proxy_check, read_run
from api.scans import ScanManager

TOKEN = "t"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _write_run(results_dir: str, domain: str, run_id: str) -> None:
    """Produce a real diagnostics dir via the engine's own DiagnosticsLogger."""
    from diagnostics.logger import DiagnosticsLogger

    base = os.path.join(results_dir, domain, f"run-{run_id}")
    os.makedirs(base, exist_ok=True)
    d = DiagnosticsLogger(run_id, base, proxy="off", debug=True)
    d.event("INFO", "scan_started", module="controller")
    d.http(module="httpx_probe", operation="probe", method="GET",
           url="https://www.ex.com", status=200, duration_ms=12.3, response_bytes=1024, verify=True)
    d.http(module="ffuf", operation="fuzz", method="GET", url="https://www.ex.com/x",
           error={"error_type": "ConnectTimeout", "message": "timed out"})
    d.summary()
    d.close()


async def test_list_and_read_run(tmp_path):
    rd = str(tmp_path)
    _write_run(rd, "ex.com", "aaaa1111")

    runs = list_runs(rd)
    assert len(runs) == 1
    r = runs[0]
    assert r["domain"] == "ex.com" and r["run_id"] == "aaaa1111"
    assert r["total_errors"] == 1 and "ConnectTimeout" in r["errors_by_category"]
    assert "dir" not in r                                    # absolute path not leaked

    # events stream
    ev = read_run(rd, stream="events")
    assert ev["run"]["run_id"] == "aaaa1111"
    assert any(x["event"] == "scan_started" for x in ev["records"])

    # http stream + module filter
    http = read_run(rd, stream="http", module="ffuf")
    assert len(http["records"]) == 1 and http["records"][0]["error_type"] == "ConnectTimeout"

    # errors stream
    errs = read_run(rd, stream="errors")
    assert all(x.get("level") in ("ERROR", "CRITICAL") for x in errs["records"])


async def test_read_run_confined_and_empty(tmp_path):
    rd = str(tmp_path)
    _write_run(rd, "ex.com", "bbbb2222")
    # A bogus domain/run filter never escapes results_dir — just yields no run.
    out = read_run(rd, domain="../../etc", run_id="nope")
    assert out["run"] is None and out["records"] == []
    # available_runs still enumerated from results_dir only.
    assert out["available_runs"] and out["available_runs"][0]["domain"] == "ex.com"


async def test_route_auth_and_runs(tmp_path):
    rd = str(tmp_path)
    _write_run(rd, "ex.com", "cccc3333")
    app = create_app(Settings(token=TOKEN, db_url=None, results_dir=rd), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/diagnostics/runs")).status_code == 401
        runs = (await c.get("/api/diagnostics/runs", headers=AUTH)).json()
        assert runs["runs"][0]["run_id"] == "cccc3333"
        body = (await c.get("/api/diagnostics?stream=http", headers=AUTH)).json()
        assert body["stream"] == "http" and len(body["records"]) == 2


async def test_proxy_check_unreachable():
    # A port nothing listens on → ok False, with a message (no exception).
    out = await proxy_check("http://127.0.0.1:1")
    assert out["ok"] is False and out["message"] and "127.0.0.1:1" in out["target"]
