"""
Increment 9 — read-only config view tests.

Auth gate, non-sensitive fields only (never the token or the DB URL), DB-dialect
extraction without credentials, and loopback detection.
"""

from __future__ import annotations

import httpx

from api.app import create_app
from api.config import Settings
from api.scans import ScanManager
from api.sysinfo import build_config

TOKEN = "supersecret-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_build_config_hides_secrets_and_reports_dialect():
    st = Settings(
        host="127.0.0.1", port=8787, token=TOKEN, token_generated=True,
        db_url="postgresql+asyncpg://user:pass@db.internal:5432/recon",
        results_dir="results",
    )
    cfg = build_config(st, "1.2.3")

    # No secret anywhere in the payload.
    import json
    blob = json.dumps(cfg)
    assert TOKEN not in blob
    assert "pass" not in blob and "db.internal" not in blob and "asyncpg" not in blob

    assert cfg["database"] == {"configured": True, "dialect": "postgresql"}
    assert cfg["auth"] == {"token_set": True, "token_source": "generated"}
    assert cfg["server"]["loopback"] is True
    assert cfg["defaults"]["worker_ceiling"] >= cfg["defaults"]["workers"]
    assert "osint" in cfg["modes"] and "chrome-windows" in cfg["browser_profiles"]


def test_build_config_non_loopback_and_env_token():
    st = Settings(host="0.0.0.0", port=9000, token=TOKEN, token_generated=False, db_url=None)
    cfg = build_config(st, "0")
    assert cfg["server"]["loopback"] is False
    assert cfg["auth"]["token_source"] == "env"
    assert cfg["database"] == {"configured": False, "dialect": None}


async def test_config_route_requires_token():
    app = create_app(Settings(token=TOKEN, db_url=None), ScanManager())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/config")).status_code == 401
        r = await c.get("/api/config", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["auth"]["token_set"] is True and TOKEN not in str(body)
