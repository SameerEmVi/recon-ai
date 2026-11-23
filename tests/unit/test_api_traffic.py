"""Unit tests for the Traffic assembler (api/traffic.py)."""

from __future__ import annotations

import json
import os

from api.traffic import build_traffic, list_runs

_RECS = [
    {"timestamp": "2026-01-01T00:00:01+00:00", "module": "secretfinder",
     "operation": "fetch", "method": "GET", "target": "https://a.example.com/x",
     "status": 200, "response_bytes": 1500, "duration_ms": 120.0, "tls_verify": True},
    {"timestamp": "2026-01-01T00:00:02+00:00", "module": "apifinder",
     "operation": "fetch", "method": "GET", "target": "https://b.example.com/api/docs",
     "status": 404, "response_bytes": 80, "duration_ms": 30.0, "tls_verify": True},
    {"timestamp": "2026-01-01T00:00:03+00:00", "module": "secretfinder",
     "operation": "fetch", "method": "POST", "target": "https://a.example.com/submit",
     "status": 500, "response_bytes": 200, "duration_ms": 90.0, "tls_verify": True},
    {"timestamp": "2026-01-01T00:00:04+00:00", "module": "secretfinder",
     "operation": "fetch", "method": "GET", "target": "https://a.example.com/dead",
     "status": None, "response_bytes": None, "duration_ms": 1000.0, "tls_verify": True,
     "error_type": "TLSVerificationError", "error_message": "cert mismatch"},
]


def _seed(tmp_path, scan_id="11111111-2222-3333-4444-555555555555", domain="example.com"):
    diag = tmp_path / domain / f"run-{scan_id}" / "diagnostics"
    diag.mkdir(parents=True)
    with open(diag / "http.jsonl", "w", encoding="utf-8") as fh:
        for r in _RECS:
            fh.write(json.dumps(r) + "\n")
    return scan_id


def test_list_runs_finds_http_stream(tmp_path):
    sid = _seed(tmp_path)
    runs = list_runs(str(tmp_path))
    assert len(runs) == 1
    assert runs[0]["run_id"] == sid
    assert runs[0]["domain"] == "example.com"
    assert "file" not in runs[0]            # absolute path must not leak


def test_build_traffic_basic_and_pagination(tmp_path):
    sid = _seed(tmp_path)
    out = build_traffic(str(tmp_path), scan_id=sid, page=1, page_size=2)
    assert out["total"] == 4
    assert out["pages"] == 2
    assert len(out["flows"]) == 2
    # Newest first.
    assert out["flows"][0]["time"] == "2026-01-01T00:00:04+00:00"
    assert set(out["facets"]["methods"]) == {"GET", "POST"}
    assert 200 in out["facets"]["statuses"] and 500 in out["facets"]["statuses"]


def test_filters(tmp_path):
    sid = _seed(tmp_path)
    assert build_traffic(str(tmp_path), scan_id=sid, host="a.example")["total"] == 3
    assert build_traffic(str(tmp_path), scan_id=sid, method="POST")["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, status="4xx")["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, status="error")["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, q="/api/")["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, errors_only=True)["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, size_min=1000)["total"] == 1
    assert build_traffic(str(tmp_path), scan_id=sid, module="apifinder")["total"] == 1


def test_error_flow_shape(tmp_path):
    sid = _seed(tmp_path)
    out = build_traffic(str(tmp_path), scan_id=sid, errors_only=True)
    f = out["flows"][0]
    assert f["ok"] is False
    assert f["error_type"] == "TLSVerificationError"
    assert f["status"] is None


def test_missing_run_degrades(tmp_path):
    _seed(tmp_path)
    out = build_traffic(str(tmp_path), scan_id="does-not-exist")
    assert out["run"] is None
    assert out["flows"] == []
    assert out["total"] == 0


def test_no_results_dir(tmp_path):
    out = build_traffic(str(tmp_path / "nope"), scan_id="x")
    assert out["run"] is None and out["total"] == 0
