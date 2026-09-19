# Recon-AI

AI-assisted bug bounty **reconnaissance** platform. Python 3.12.

> [!WARNING]
> **Authorized targets only.** This tool performs active reconnaissance against
> hosts and web services. Only run it against domains you own or are explicitly
> authorized to test (e.g. an in-scope bug bounty program). You are responsible
> for your own use.

## What it does

Root domain + authorized scope → enumerate subdomains → resolve/probe live hosts
→ fingerprint → content discovery / fuzzing → (optional) LLM triage → structured
results → historical scan diff.

## Core design principle — deterministic vs. LLM

Deterministic code owns everything security-relevant: **scope enforcement**,
enumeration, probing, parsing, rate limiting, dedup, execution. The LLM only
*reasons* (triage, prioritization, correlation, strategy) and can **propose**
targets but **never decides scope**. MCP is the standardized external interface.

Non-negotiable invariants:

- **Scope is decided by code, never the LLM.** `scope/engine.py::ScopeEngine.evaluate()`
  is the single gate. Deny-first order (normalize → DENY → DISTANCE → ALLOW →
  default OUT). Fail closed.
- **One scope chokepoint.** Every event passes through the controller's
  `stamp_and_publish()`; the EventBus drops any event whose `scope_status != IN`.
- **Target output is hostile input.** All target-controlled strings are sanitized
  (control-char strip + length cap) by Pydantic validators at event construction.
- **All AI is opt-in** (`--ai` / `--agent`). Everything works fully without an API key.

## Architecture

Event-driven (BBOT-style). An `Event` (11 types: SUBDOMAIN, DNS_RECORD, IP,
OPEN_PORT, HTTP_SERVICE, TECHNOLOGY, URL, ENDPOINT, PARAMETER, ANOMALY,
FINDING_CANDIDATE) is the atom. Modules emit events; the `EventBus` fans out to
handlers and dedups.

- **Seed modules** run once in parallel at scan start (subfinder, crt_sh, …).
- **Reactive modules** subscribe to the bus and fire on matching events
  (dnsx: SUBDOMAIN→IP; httpx_probe: SUBDOMAIN/IP/OPEN_PORT→HTTP_SERVICE; …).

Two-layer tools: `recon/` = low-level subprocess wrappers around the real
binaries (subfinder, dnsx, httpx, nuclei, …); `modules/` = the event-driven
layer that wraps them plus pure-Python passive sources.

Throttling is centralized in `ratelimit/` — one `RateLimiter` per scan (rps
spacing, concurrency cap, and adaptive WAF backoff that automatically slows the
scan when the target starts blocking).

| Path | Role |
|---|---|
| `scope/` | Scope engine + types — the deterministic gate |
| `events/` | Event model, pub/sub bus, dedup |
| `recon/` | Subprocess wrappers around external binaries |
| `modules/` | Event-driven modules: `passive/`, `active/`, `web/` |
| `controller/` | Scan lifecycle |
| `database/` | SQLModel models, repositories, persister, diff |
| `ai/` | LLM triage (forced-schema calls) |
| `agent/` | Constrained agent loop |
| `mcpserver/` | FastMCP server (8 tools) |
| `ratelimit/` | RateLimiter + adaptive WAF backoff |
| `cli/main.py` | Typer CLI (entry: `recon-ai`) |
| `tests/` | Security (scope engine) + unit tests |

## Install

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -e ".[sqlite,ai,mcp,dev]"
```

External binaries are optional per module (modules warn-and-skip if a binary is
missing). Commonly used: subfinder, dnsx, httpx (ProjectDiscovery), naabu,
katana, ffuf, nuclei. See `CLAUDE.md` for toolchain notes.

## Usage

```bash
python -m cli.main scan example.com                 # deterministic, no AI/DB
python -m cli.main scan example.com --passive       # + passive modules
python -m cli.main scan example.com --full          # all modules
python -m cli.main scan example.com -p fast         # a profile
python -m cli.main scan example.com -m crt_sh -m dnsx    # explicit modules
python -m cli.main scan example.com -r 5 -c 20      # 5 req/s per bucket, 20 concurrent
python -m cli.main modules [--profiles]             # list modules / profiles

# With persistence + AI (needs ANTHROPIC_API_KEY):
python -m cli.main scan example.com --ai    --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main scan example.com --agent --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main history example.com --db-url ...
python -m cli.main diff <scan_a> <scan_b> --db-url ...
python -m cli.main triage <scan_id> --db-url ...
```

Scope defaults to `[*.domain, domain]` if `--in-scope` is omitted; `--out-scope`
deny always wins; `--max-distance` default 5. Resolved IPs are OUT under a
domain-only scope (deny-first) — add `--in-scope <ip/CIDR>` to probe a host.

### MCP server

```bash
recon-ai-mcp    # FastMCP server exposing 8 tools (start_scan, get_scan_status,
                # list_scans, list_hosts, list_findings, list_assessments,
                # compute_diff, run_triage)
```

## Testing

```bash
pytest          # config in pyproject.toml; asyncio_mode=auto
```

## Status

All core phases complete (scope engine → events/DB/recon → AI triage → agent
loop → module system + MCP). 291 tests passing.
