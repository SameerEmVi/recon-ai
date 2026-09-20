# Installation Guide

Setup instructions for **Recon-AI**. Covers the Python package, the optional
external recon binaries, database, and AI configuration.

> [!WARNING]
> **Authorized targets only.** Recon-AI performs active reconnaissance. Only run
> it against domains you own or are explicitly authorized to test.

---

## 1. Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| **Python ≥ 3.12** | everything | `python --version` |
| **git** | cloning | |
| **Go ≥ 1.21** | building the recon binaries | only if you want active recon (subfinder, dnsx, httpx, …) |
| **Npcap** (Windows) | `naabu` SYN port scans | [npcap.com](https://npcap.com) — optional |
| **ANTHROPIC_API_KEY** | `--ai` / `--agent` | optional; everything works without it |

Recon-AI runs fully in **deterministic mode with zero external binaries** — the
passive modules (`crt_sh`, `certspotter`, `hackertarget`, `wayback`) are pure
Python. Binaries only add active enumeration/probing, and every module that
needs one **warns and skips** if it's missing.

---

## 2. Get the code

```bash
git clone https://github.com/SameerEmVi/recon-ai.git
cd recon-ai
```

---

## 3. Python environment

Create a virtualenv and install the package with the extras you need.

**Linux / macOS (bash / zsh)**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[sqlite,ai,mcp,dev]"
```

**fish shell** (e.g. default on Kali) — the plain `activate` script is bash-only
and will error with `"case" builtin not inside of switch block`; use the fish
activator instead:
```fish
python -m venv .venv
source .venv/bin/activate.fish        # csh/tcsh: source .venv/bin/activate.csh
pip install -e ".[sqlite,ai,mcp,dev]"
```

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[sqlite,ai,mcp,dev]"
```

Deactivate any of these with `deactivate`.

### Extras

| Extra | Pulls in | When you need it |
|---|---|---|
| `sqlite` | `aiosqlite` | local persistence (`--db-url sqlite+aiosqlite:///…`) |
| `postgres` | `asyncpg` | Postgres persistence |
| `ai` | `anthropic` | `--ai` triage / `--agent` loop |
| `mcp` | `mcp` | running the MCP server |
| `dev` | `pytest`, `pytest-asyncio`, `aiosqlite` | running the test suite |

Minimal deterministic-only install: `pip install -e .`

This also installs two console scripts: **`recon-ai`** (CLI) and
**`recon-ai-mcp`** (MCP server). You can equally run the CLI as
`python -m cli.main`.

---

## 4. External recon binaries (optional)

Active modules shell out to standard recon tools. Install the ones you want.

### ProjectDiscovery + Go tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
```

Go installs land in `$(go env GOPATH)/bin` (default `~/go/bin`). Make sure that
directory is on your `PATH`.

### nuclei

`nuclei` may fail to `go install` on some Windows toolchains (32-bit MinGW /
CGO). Use the **prebuilt release** from
[github.com/projectdiscovery/nuclei/releases](https://github.com/projectdiscovery/nuclei/releases)
and drop the binary on your `PATH`.

### Optional extras

`gau`, `gowitness`, `amass`, `assetfinder`, `findomain` — install if you want
those modules; otherwise they warn-and-skip.

### ⚠ Windows PATH gotcha (important)

Python's `httpx` package ships a CLI named `httpx` that will **shadow**
ProjectDiscovery's `httpx` and silently produce no HTTP_SERVICE events. Put your
Go bin **first** on PATH:

```bash
export PATH="$HOME/go/bin:$PATH"          # Git Bash
```
```powershell
$env:PATH = "$env:USERPROFILE\go\bin;$env:PATH"   # PowerShell
```

Verify you got the right one:
```bash
httpx -version    # should print ProjectDiscovery's version, not Python usage
```

---

## 5. Database (optional — needed for AI, history, diff)

Deterministic scans print results and need **no database**. Persistence unlocks
`--ai`, `--agent`, `history`, `diff`, and `triage`.

- **SQLite (simplest):**
  `--db-url "sqlite+aiosqlite:///recon.db"`
- **Postgres:**
  `--db-url "postgresql+asyncpg://user:pass@host/dbname"`

The schema is **created automatically** on first use (SQLModel `create_all`), so
a fresh SQLite file just works — no migration step required.

For evolving an existing/production schema, Alembic is included:
```bash
alembic upgrade head
```

---

## 6. AI configuration (optional)

`--ai` and `--agent` require an Anthropic API key:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."          # bash
$env:ANTHROPIC_API_KEY = "sk-ant-..."          # PowerShell
```

Default model in code is `claude-sonnet-4-6` (override with `--ai-model`).

---

## 7. Verify the install

```bash
# List all modules and profiles (proves the package imports & registry works):
python -m cli.main modules --profiles

# Run the test suite (needs the [dev] extra):
pytest            # expect: 291 passed
```

---

## 8. First scan

```bash
# Deterministic, passive-only (no binaries, no DB, no API key):
python -m cli.main scan example.com --passive

# Full active scan (needs the recon binaries on PATH):
python -m cli.main scan example.com --full -r 5 -c 20

# With persistence + AI triage:
export ANTHROPIC_API_KEY="sk-ant-..."
python -m cli.main scan example.com --ai --db-url "sqlite+aiosqlite:///recon.db"
```

Remember: resolved IPs are **out of scope** under a domain-only scope
(deny-first). Add `--in-scope <ip/CIDR>` to let `httpx_probe` / `naabu` touch a
specific host.

---

## 9. MCP server

```bash
recon-ai-mcp      # or: python -m mcpserver.server
```

Exposes 8 tools: `start_scan`, `get_scan_status`, `list_scans`, `list_hosts`,
`list_findings`, `list_assessments`, `compute_diff`, `run_triage`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| No `HTTP_SERVICE` events on a live site | Python's `httpx` CLI is shadowing PD's — put `~/go/bin` first on PATH (§4). |
| `nuclei` won't `go install` (Windows) | Use the prebuilt release binary (§4). |
| `naabu` finds no ports / needs raw sockets | Install Npcap (Windows); or naabu falls back to CONNECT scan. |
| A module logs "binary not found — module disabled" | That tool isn't installed; install it or ignore (module is skipped). |
| `--ai` / `--agent` "skipped" warning | Set `ANTHROPIC_API_KEY` **and** pass `--db-url`. |
| Active modules find nothing on a bare domain | IPs are OOS by default; add `--in-scope <ip/CIDR>`. |

See [`CLAUDE.md`](CLAUDE.md) for the full architecture and machine-specific
toolchain notes.
