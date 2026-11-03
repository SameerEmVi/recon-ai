"""
api — FastAPI presentation/control layer over the existing Recon-AI engine.

This package is a *sibling* of `mcpserver/`: like the MCP server, it drives the
EXISTING ScanController / scheduler / repositories and never reimplements
scanning. Route handlers validate input, re-check scope on the backend, persist
jobs, and delegate execution to the engine — they never run modules directly.

Entry point: `recon-ai-web = api.app:main` (serves on 127.0.0.1 by default).
"""
