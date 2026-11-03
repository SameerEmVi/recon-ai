"""
Settings for the Recon-AI web API.

Everything is resolved from the environment with safe, localhost-first defaults.
The auth token is the single security gate for the whole API (routes + the
WebSocket): if RECON_AI_WEB_TOKEN is unset, a random one is generated at startup
and printed ONCE to stderr so the local operator can copy it — it is never
exposed through any endpoint.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _split_env(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [p.strip() for p in raw.split(",") if p.strip()]


@dataclass(frozen=True)
class Settings:
    #: Bind address — localhost by default; a non-loopback bind is an explicit
    #: operator choice (and the token auth then actually matters).
    host: str = field(default_factory=lambda: os.environ.get("RECON_AI_WEB_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("RECON_AI_WEB_PORT", "8787")))
    #: Single bearer token. Generated (and printed once) if not provided.
    token: str = field(default_factory=lambda: os.environ.get("RECON_AI_WEB_TOKEN", ""))
    token_generated: bool = False
    #: Database URL for result reads (reuses the existing env the CLI/MCP use).
    db_url: str | None = field(default_factory=lambda: os.environ.get("RECON_AI_DB_URL"))
    #: CORS allow-list — the Vite dev origin by default. Strict: no "*".
    cors_origins: list[str] = field(
        default_factory=lambda: _split_env(
            "RECON_AI_WEB_CORS", ["http://localhost:5173", "http://127.0.0.1:5173"]
        )
    )
    #: Where results/diagnostics live (confines export/file reads).
    results_dir: str = field(default_factory=lambda: os.environ.get("RECON_AI_RESULTS_DIR", "results"))

    @classmethod
    def load(cls) -> "Settings":
        token = os.environ.get("RECON_AI_WEB_TOKEN", "")
        generated = False
        if not token:
            token = secrets.token_urlsafe(32)
            generated = True
        return cls(token=token, token_generated=generated)
