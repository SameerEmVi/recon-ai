# Recon-AI — Project Context

AI-assisted bug bounty **reconnaissance** platform. **Authorized targets only.**
Python 3.12. Package name `recon-ai` (pyproject.toml). Not a git repo yet.

Workflow: root domain + authorized scope → enumerate subdomains → resolve/probe
live hosts → fingerprint → content discovery/fuzzing → (optional) LLM triage →
structured results → historical scan diff.

## Core principle — deterministic vs. LLM split

Deterministic code owns everything security-relevant: scope enforcement,
enumeration, probing, parsing, rate limiting, dedup, execution. The LLM only
*reasons* (triage, prioritization, correlation, strategy) and can **propose**
targets but **never decides** scope. MCP is the standardized external interface.

## Non-negotiable invariants

- **Scope is decided by code, never the LLM.** `scope/engine.py::ScopeEngine.evaluate()`
  is the single gate. Deny-first order is a security property: normalize →
  DENY → DISTANCE (recursion bound) → ALLOW → default OUT. Fail closed.
- **One scope chokepoint.** Every event goes through the controller's
  `stamp_and_publish()`. No module, tool, or agent can bypass it. The EventBus
  drops any event whose `scope_status != IN`.
- **Target output is hostile input.** All target-controlled strings are
  sanitized (control-char strip + length cap, `_MAX_STR=2048`) by Pydantic
  validators in `events/types.py` at event construction. Raw tool output never
  travels past that module and never reaches the LLM as instructions.
- **All AI is opt-in** via `--ai/--no-ai`. Everything works fully without an API key.
- Never design to bypass scope, rate limits, auth, or security controls.

## Rate limiting & adaptive WAF backoff

The `ratelimit/` package (`RateLimiter` + `ratelimit/waf.py`) is the single
throttling chokepoint. One `RateLimiter` is created per scan (owned by
`ScanController`, exposed as `controller.rate_limiter`) and shared by every
module, recon wrapper, and agent tool via one `guard()` context manager:

- **rps spacing** — min-interval between op starts, per bucket (host/tool)
- **concurrency cap** — a global semaphore over in-flight ops
- **adaptive WAF backoff** — `observe_http(status, headers, body)` detects WAF
  fingerprints / block statuses (403/406/429/503) / block pages; on a block it
  multiplies the spacing (×2 per block, capped ×32) and recovers slowly on clean
  responses. If no static rate was set, a detected block self-imposes a 1s/op
  baseline so the scan *automatically slows down* against a WAF.

Wiring: `BaseModule.guard()` / `BaseModule.inspect_response()` for HTTP modules;
`BaseReconTool._run` and the `GauWrapper`/`NucleiWrapper` subprocess wrappers take
the limiter; `httpx_probe` feeds the target's own responses into WAF detection.
User controls: CLI `--rate-limit/-r` (req/s) and `--max-concurrency/-c`, mirrored
in the MCP `start_scan` tool. Unset = unlimited static rate, but adaptive WAF
backoff still applies.

Test-safety: `get_limiter(obj)` returns the shared **inert** `NOOP` limiter unless
`obj.rate_limiter` is a real `RateLimiter` (MagicMock controllers fall through).
`NOOP` is `frozen=True` and must never throttle/adapt — a non-frozen shared
fallback silently slowed the whole test suite once (WAF signals mutated it).

## Architecture (BBOT-style, event-driven)

`Event` (11 types in `events/types.py`: SUBDOMAIN, DNS_RECORD, IP, OPEN_PORT,
HTTP_SERVICE, TECHNOLOGY, URL, ENDPOINT, PARAMETER, ANOMALY, FINDING_CANDIDATE)
is the atom. Modules emit events; the `EventBus` (`events/bus.py`) fans out to
handlers and dedups by `dedup_key` (bounds recursion / graph cycles).

Two module kinds (`modules/base.py::BaseModule`):
- **Seed** (`watched_events=[]`): run once in parallel at scan start (subfinder, crt_sh, …).
- **Reactive** (`watched_events=[...]`): subscribed to the bus, fire on matching
  events (dnsx: SUBDOMAIN→IP/DNS_RECORD; httpx_probe: IP/OPEN_PORT→HTTP_SERVICE; …).

`ScanController` (`controller/controller.py`) owns the lifecycle and wires
scope + bus + modules + (optional) AI/agent.

**Vhost-aware probing:** `httpx_probe` watches `SUBDOMAIN` (not just `IP`/`OPEN_PORT`), so `HTTP_SERVICE` is keyed on the **hostname** and the whole web chain (ffuf/nuclei/fingerprint/katana/corscanner/bypass403/secretfinder) hits the real name-based vhost with the correct Host header — and works on domain-only scope without adding the resolved IP. (Fuzzing the bare IP hit the empty default vhost and found nothing.)

### Two-layer tool design (important)
- `recon/` = low-level **subprocess wrappers** that execute the actual binaries
  (subfinder, dnsx, httpx, gau, nuclei, bbot). This is the execution layer.
- `modules/` = the **event-driven module layer** that wraps those recon wrappers
  (and pure-Python passive sources) into the BBOT-style system.
  `modules/active/dnsx.py` etc. delegate to `recon/dnsx.py`. `recon/` is not
  legacy — `modules/` depends on it.

Module registry (`modules/registry.py`): auto-discovery via `@register` +
`pkgutil`. Load by name, by flag (`passive|active|web|dns|slow|fast`), or defaults.
- `DEFAULT_MODULES = [subfinder, dnsx, httpx_probe]`
- `PASSIVE_MODULES = [crt_sh, certspotter, hackertarget, wayback]` (pure-Python, no binaries)
- Groups: `EXTRA_PASSIVE`, `DEEP_DNS`, `WEB`, `CRAWL`, `DISCOVERY`, `FULL`
- Secret scanning: **secretfinder** (`modules/web/secretfinder.py` + `recon/secrets.py`) watches `HTTP_SERVICE`+`URL`, fetches bodies/JS/maps, regex+entropy detects exposed keys/tokens → `FINDING_CANDIDATE` (category `exposed-secret`). Secrets are **redacted** before hitting any event (never stored/logged/sent to LLM).
- Parameter discovery: **paramfinder** (`modules/web/paramfinder.py`) watches `URL`+`ENDPOINT`, extracts query-string params and endpoint parameter names (pure Python, no network) → `PARAMETER` events. It is the producer for the `PARAMETER` type (the dedup key + `ParameterData` already existed). `sample_value` is sanitized/capped by the `ParameterData` validator like every other target string. In the `DISCOVERY` group / `--full`.
- Port scanning combo: **naabu** discovers open ports fast → **nmap** (`modules/active/nmap.py` + `recon/nmap.py`) watches `OPEN_PORT` and runs `-sV` for service/version → `TECHNOLOGY` events. nmap is `-sV -Pn -n` only (no NSE/OS-detect) unless opted in.
- Profiles: `fast` (passive only) · `default` · `full` · `paranoid`

## Directory map

| Path | Role |
|---|---|
| `scope/` | Scope engine + types — the deterministic gate. The heart of the system. |
| `events/` | Event model (`types.py`), pub/sub `bus.py`, `dedup.py` |
| `recon/` | Subprocess wrappers around external binaries |
| `modules/` | Event-driven modules: `passive/`, `active/`, `web/` + `base.py`, `registry.py` |
| `controller/` | `controller.py` (scan lifecycle), `reflexes.py` |
| `database/` | SQLModel models, repositories, persister, session, diff (asyncpg/aiosqlite) |
| `ai/` | `assessor.py` (forced-schema LLM call), `triage.py` (post-scan), `prompts/` |
| `agent/` | Phase-4 agent loop: `loop.py`, `approval.py`, `stopping.py`, `tools.py` |
| `mcpserver/` | FastMCP server exposing 8 tools; `context.py` in-process scan registry |
| `ratelimit/` | `RateLimiter` + `waf.py` — throttling & adaptive WAF backoff (used everywhere) |
| `normalize/` | Output parsers |
| `cli/main.py` | Typer CLI (entry: `recon-ai`) |
| `alembic/` | DB migrations |
| `tests/` | `security/` (scope engine) + `unit/` (291 tests, all passing) |
| `wordlists/` | `common.txt`, `dns_names.txt` |

Entry points (pyproject): `recon-ai = cli.main:app`, `recon-ai-mcp = mcpserver.server:main`.

Stray duplicates at repo root — **safe to delete, do not edit**: `types.py`
(identical to `scope/types.py`), `test_scope_engine.py` (dup of
`tests/security/`), and root `__init__.py`/`engine.py` shadowing the `scope/`
package. The canonical files live under `scope/` and `tests/`.

## Running it

```bash
python -m cli.main scan example.com                 # deterministic, no AI/DB
python -m cli.main scan example.com --passive       # + passive modules
python -m cli.main scan example.com --full          # all modules
python -m cli.main scan example.com -p fast         # a profile
python -m cli.main scan example.com -m crt_sh -m dnsx   # explicit modules (replaces defaults)
python -m cli.main scan example.com -r 5 -c 20      # 5 req/s per bucket, max 20 concurrent ops
python -m cli.main modules [--profiles]             # list modules / profiles
python -m cli.main scan example.com --ai   --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main scan example.com --agent --db-url "sqlite+aiosqlite:///recon.db"
python -m cli.main history example.com --db-url ...
python -m cli.main diff <scan_a> <scan_b> --db-url ...
python -m cli.main triage <scan_id> --db-url ...
```
`--ai`/`--agent` need `ANTHROPIC_API_KEY` + `--db-url`. Default AI model string
in code is `claude-sonnet-4-6`. Scope defaults to `[*.domain, domain]` if
`--in-scope` omitted; `--out-scope` deny always wins; `--max-distance` default 5.

Every scan prints a readable end-of-scan **SCAN SUMMARY** (subdomains, ports, HTTP services, technologies, findings) via `ScanController.print_summary()`; per-event logging is DEBUG-only (`-v` to see it).

Tests: `pytest` (config in pyproject; `asyncio_mode=auto`).

## Windows toolchain gotchas (this machine)

- **Prepend Go bins first:** `export PATH="/c/Users/samee/go/bin:$PATH"` — else
  ProjectDiscovery `httpx` is shadowed by Python's `httpx` CLI and silently
  produces no HTTP_SERVICE events.
- `nuclei` won't `go install` here (32-bit MinGW / CGO) — use the prebuilt release.
- `naabu` SYN scans need Npcap.
- Built & working in go/bin: subfinder, dnsx, httpx(PD), naabu, katana, ffuf.
  Missing/optional (modules warn-and-skip): gau, gowitness, amass, assetfinder, findomain.
- **Scope note:** resolved IPs are OUT under a domain-only scope (deny-first).
  Add `--in-scope <ip/CIDR>` to let httpx_probe/naabu touch a host.

## Status

All 5 phases complete (scope engine → events/DB/recon → AI triage → agent loop →
module system + MCP). 291 tests passing. See persistent memory
`project-recon-ai` and `reference-toolchain-env` for the fuller record.
