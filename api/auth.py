"""
Token authentication for the web API.

A single bearer token (api.config.Settings.token) gates every sensitive route
and the WebSocket. Comparison is constant-time (secrets.compare_digest) to avoid
a timing oracle. The token is read from the `Authorization: Bearer <token>`
header for HTTP, or a `token` query parameter for the WebSocket handshake (which
cannot carry custom headers from a browser).
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


def _token_ok(presented: str | None, expected: str) -> bool:
    if not presented or not expected:
        return False
    # constant-time compare; both sides must be str of equal handling
    return secrets.compare_digest(presented, expected)


async def require_token(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """FastAPI dependency: 401 unless a valid bearer token is presented."""
    expected = request.app.state.settings.token
    presented = creds.credentials if creds else None
    if not _token_ok(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def websocket_token_ok(expected: str, presented: str | None) -> bool:
    """Validate a WebSocket handshake token (passed as ?token=…)."""
    return _token_ok(presented, expected)
