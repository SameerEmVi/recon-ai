"""
Read-only system/config view for the Settings page.

Reports the effective, NON-SENSITIVE configuration: the bind address, whether a
DB / proxy env is configured (bool + DB dialect only — never the URL or any
credential), the CORS allow-list, the results directory, the token's source
(env vs generated — never the token itself), and the engine defaults the scan
form should reflect (worker default/ceiling, max-distance, browser profiles,
modes). Nothing here is a secret and nothing mutates state.
"""

from __future__ import annotations


def _db_dialect(db_url: str | None) -> str | None:
    """The backend name only (e.g. 'sqlite', 'postgresql') — never host/creds."""
    if not db_url:
        return None
    scheme = db_url.split("://", 1)[0]
    return scheme.split("+", 1)[0] or None


def build_config(settings, version: str) -> dict:
    import os

    from net.headers import available as browser_profiles
    from policy import MODES
    from scheduler.pool import WorkerPool

    host = settings.host
    loopback = host in ("127.0.0.1", "::1", "localhost")

    return {
        "version": version,
        "server": {"host": host, "port": settings.port, "loopback": loopback},
        "auth": {
            "token_set": bool(settings.token),
            "token_source": "generated" if settings.token_generated else "env",
        },
        "database": {
            "configured": bool(settings.db_url),
            "dialect": _db_dialect(settings.db_url),
        },
        "proxy": {"env_configured": bool(os.environ.get("RECON_AI_PROXY"))},
        "cors_origins": list(settings.cors_origins),
        "results_dir": settings.results_dir,
        "defaults": {
            "max_distance": 5,
            "workers": WorkerPool.DEFAULT_MAX_WORKERS,
            "worker_ceiling": WorkerPool.SAFETY_CEILING,
            "browser_profile": "chrome-windows",
        },
        "modes": list(MODES),
        "browser_profiles": browser_profiles(),
    }
