"""
FastAPI application factory + entry point for the Recon-AI web GUI.

`create_app()` wires settings, the ScanManager, strict CORS, auth-gated routers,
and (when a built frontend exists) serves it as static files. `main()` loads
settings, prints the local token once, and runs uvicorn bound to localhost.

Nothing here reimplements scanning — routers delegate to the existing engine via
the ScanManager (api/scans.py).
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import Settings
from api.scans import ScanManager

log = logging.getLogger("api")

_VERSION = "0.1.0"


class _SPAStaticFiles:
    """StaticFiles that falls back to index.html for unmatched paths.

    The frontend is a single-page app with client-side routing, so a hard
    refresh (or a bookmarked deep link) on a route like /skills must return the
    app shell rather than 404 — the browser then lets React Router render the
    page. Real asset requests (/assets/*.js, favicon, …) are served normally;
    only paths with no matching file fall through to index.html.

    Implemented as a lazy factory so fastapi.staticfiles is imported only when a
    built frontend is actually present.
    """

    @staticmethod
    def build(directory: str):
        from fastapi.staticfiles import StaticFiles
        from starlette.exceptions import HTTPException as StarletteHTTPException

        class SPAStaticFiles(StaticFiles):
            async def get_response(self, path: str, scope):
                try:
                    return await super().get_response(path, scope)
                except StarletteHTTPException as exc:
                    if exc.status_code == 404:
                        # Unknown path → serve the SPA shell so the client router
                        # can handle it (deep-link refresh fix).
                        return await super().get_response("index.html", scope)
                    raise

        return SPAStaticFiles(directory=directory, html=True)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    # Cancel any running scans cleanly on server shutdown.
    await app.state.scan_manager.shutdown()


def create_app(settings: Settings | None = None,
               scan_manager: ScanManager | None = None) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(title="Recon-AI", version=_VERSION, lifespan=_lifespan)
    app.state.settings = settings
    from api.ws import LiveHub, live_ws
    app.state.hub = LiveHub()
    app.state.scan_manager = scan_manager or ScanManager(db_url=settings.db_url, hub=app.state.hub)
    app.add_api_websocket_route("/ws/live", live_ws)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,     # strict allow-list, never "*"
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    from api.routes import (
        assets, catalog, config, diagnostics, evidence, execmap, exploration,
        findings, graph, health, overview, plan, scans, skills, traffic, vulns,
    )
    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(overview.router)
    app.include_router(catalog.router)
    app.include_router(assets.router)
    app.include_router(graph.router)
    app.include_router(plan.router)
    app.include_router(vulns.router)
    app.include_router(findings.router)
    app.include_router(diagnostics.router)
    app.include_router(traffic.router)
    app.include_router(skills.router)
    app.include_router(execmap.router)
    app.include_router(exploration.router)
    app.include_router(evidence.router)
    app.include_router(config.router)

    # Serve the built frontend if present (added AFTER API routers so /api/* wins).
    import os
    dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
    if os.path.isdir(dist):
        # SPA-aware: unknown non-API paths fall back to index.html so a hard
        # refresh on a client route (e.g. /skills) renders the app, not a 404.
        app.mount("/", _SPAStaticFiles.build(dist), name="frontend")

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s  %(message)s")
    settings = Settings.load()
    if settings.token_generated:
        # Printed ONCE to stderr so the local operator can copy it; never exposed
        # through any endpoint.
        print(f"\n  Recon-AI web token (set RECON_AI_WEB_TOKEN to persist it):\n"
              f"    {settings.token}\n", file=sys.stderr)
    app = create_app(settings)
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
