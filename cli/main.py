"""
recon-ai CLI.

Deterministic (default — no AI, no DB required):
    python -m cli.main scan example.com

With persistence:
    python -m cli.main scan example.com --db-url "postgresql+asyncpg://localhost/recon_ai"
    python -m cli.main scan example.com --db-url "sqlite+aiosqlite:///recon.db"

AI-assisted + persistence:
    python -m cli.main scan example.com --ai --db-url "postgresql+asyncpg://localhost/recon_ai"

Scan history / diff (requires --db-url):
    python -m cli.main history example.com --db-url "sqlite+aiosqlite:///recon.db"
    python -m cli.main diff <scan_a_uuid> <scan_b_uuid> --db-url "sqlite+aiosqlite:///recon.db"
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid

import typer

from scope.types import Scope

app = typer.Typer(
    name="recon-ai",
    help="AI-assisted bug bounty reconnaissance. Authorized targets only.",
    no_args_is_help=True,
)


def _silence_proactor_pipe_warnings() -> None:
    """Suppress the noisy 'I/O operation on closed pipe' spam that Windows'
    ProactorEventLoop emits from transport __del__ during interpreter shutdown.

    Two transport classes raise it at GC time (pipe transports and the
    subprocess transport that wraps dnsx/naabu/nmap/...), so we harden both.
    Harmless GC-time noise; not a scan failure."""
    if sys.platform != "win32":
        return
    import functools

    def _harden(cls) -> None:
        orig = getattr(cls, "__del__", None)
        if orig is None:
            return

        @functools.wraps(orig)
        def _quiet_del(self, *a, **k):
            try:
                orig(self, *a, **k)
            except (RuntimeError, ValueError):
                pass

        cls.__del__ = _quiet_del

    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        _harden(_ProactorBasePipeTransport)
    except Exception:
        pass
    try:
        from asyncio.base_subprocess import BaseSubprocessTransport
        _harden(BaseSubprocessTransport)
    except Exception:
        pass


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)-8s %(name)s  %(message)s",
        stream=sys.stderr,
    )
    # Quiet chatty third-party loggers unless -v; keeps the default output readable.
    if not verbose:
        for noisy in ("httpx", "httpcore", "hpack", "asyncio", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
    _silence_proactor_pipe_warnings()


# ── scan ──────────────────────────────────────────────────────────────────────

@app.command()
def scan(
    domain: str = typer.Argument(..., help="Root domain to scan."),
    in_scope: list[str] = typer.Option(
        [], "--in-scope", "-i",
        help="Scope rule (repeatable): exact domain, *.wildcard, or CIDR. "
             "Defaults to [*.domain, domain] if omitted.",
    ),
    out_scope: list[str] = typer.Option(
        [], "--out-scope", "-o",
        help="Out-of-scope rule (repeatable). Deny wins over any allow. An "
             "exact host (e.g. x.abc.com) also excludes its whole subtree "
             "(*.x.abc.com); use a bare host to carve out a domain and "
             "everything under it.",
    ),
    max_distance: int = typer.Option(5, "--max-distance"),
    wildcard_apex: bool = typer.Option(
        False, "--wildcard-apex/--no-wildcard-apex",
        help="Let *.example.com also match the apex example.com.",
    ),
    # ── module selection ──────────────────────────────────────────────────────
    profile: str | None = typer.Option(
        None, "--profile", "-p",
        help=(
            "Scan profile: fast | default | full | paranoid. "
            "fast = passive only; default = subfinder+dns+http; "
            "full = everything; paranoid = full + deeper scanning. "
            "Takes precedence over -m / --passive / --full."
        ),
    ),
    module: list[str] = typer.Option(
        [], "-m", "--module",
        help=(
            "Enable a specific module by name (repeatable). "
            "When set, REPLACES the default module set entirely. "
            "Run 'recon-ai modules' to see available modules."
        ),
    ),
    passive: bool = typer.Option(
        False, "--passive",
        help="Add all passive modules (crt_sh, certspotter, hackertarget, wayback) "
             "on top of the default set.",
    ),
    full: bool = typer.Option(
        False, "--full",
        help="Enable ALL modules: default + passive + web + crawl + discovery.",
    ),
    # ── AI / agent ────────────────────────────────────────────────────────────
    ai: bool = typer.Option(
        False, "--ai/--no-ai",
        help=(
            "Enable AI-assisted Mode B. Runs enumeration then LLM triage. "
            "Requires ANTHROPIC_API_KEY env var and --db-url."
        ),
    ),
    agent: bool = typer.Option(
        False, "--agent/--no-agent",
        help="Enable constrained agent loop after triage. Implies --ai.",
    ),
    max_iterations: int = typer.Option(
        20, "--max-iterations",
        help="Maximum agent iterations (default: 20). Only used with --agent.",
    ),
    # ── rate limiting ─────────────────────────────────────────────────────────
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", "-r",
        help="Max requests/sec per bucket (host/tool). Omit = unlimited. "
             "Adaptive WAF backoff applies regardless of this value.",
    ),
    max_concurrency: int | None = typer.Option(
        None, "--max-concurrency", "-c",
        help="Max simultaneous recon operations (HTTP requests + subprocesses). "
             "Omit = unlimited.",
    ),
    ai_model: str = typer.Option(
        "claude-sonnet-4-6", "--ai-model",
        help="Anthropic model for triage and agent.",
    ),
    # ── persistence ───────────────────────────────────────────────────────────
    db_url: str | None = typer.Option(
        None, "--db-url",
        help=(
            "Database URL. "
            "PostgreSQL: 'postgresql+asyncpg://user:pass@host/db'  "
            "SQLite:     'sqlite+aiosqlite:///recon.db'"
        ),
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a reconnaissance scan against an authorized domain."""
    _setup_logging(verbose)

    resolved_in = list(in_scope) or [f"*.{domain}", domain]
    resolved_out = list(out_scope)

    try:
        scope = Scope.from_strings(
            in_scope=resolved_in,
            out_scope=resolved_out,
            max_distance=max_distance,
            wildcard_includes_apex=wildcard_apex,
        )
    except ValueError as exc:
        typer.echo(f"[error] invalid scope rule: {exc}", err=True)
        raise typer.Exit(code=1)

    ai_effective = ai or agent

    # Resolve module selection — profiles take precedence.
    from modules.registry import FULL_MODULES, PASSIVE_MODULES, SCAN_PROFILES
    profile_config: dict = {}

    if profile is not None:
        if profile not in SCAN_PROFILES:
            typer.echo(
                f"[error] unknown profile {profile!r}. "
                f"Available: {', '.join(SCAN_PROFILES)}",
                err=True,
            )
            raise typer.Exit(code=1)
        p = SCAN_PROFILES[profile]
        enabled_modules: list[str] | None = p["modules"]
        enabled_flags: list[str] | None = None
        profile_config = p.get("module_config", {})
        typer.echo(f"[recon-ai] profile   : {profile} — {p['description']}")
    elif list(module):
        # Explicit -m flags override everything.
        enabled_modules = list(module)
        enabled_flags = None
    elif full:
        enabled_modules = list(FULL_MODULES)
        enabled_flags = None
    else:
        # Default set + optional passive extras.
        enabled_modules = None
        enabled_flags = ["passive"] if passive else None

    typer.echo(f"[recon-ai] in-scope  : {resolved_in}")
    typer.echo(f"[recon-ai] out-scope : {resolved_out or '(none)'}")
    mode_label = "A — deterministic"
    if agent:
        mode_label = "B+agent — AI triage + agent loop"
    elif ai_effective:
        mode_label = "B — AI-assisted"
    typer.echo(f"[recon-ai] mode      : {mode_label}")
    typer.echo(f"[recon-ai] db        : {db_url or '(none — in-memory only)'}")
    if enabled_modules:
        typer.echo(f"[recon-ai] modules   : {enabled_modules}")
    elif passive:
        typer.echo(f"[recon-ai] modules   : defaults + passive")
    elif full:
        typer.echo(f"[recon-ai] modules   : full")
    if ai_effective:
        typer.echo(f"[recon-ai] ai-model  : {ai_model}")
    if agent:
        typer.echo(f"[recon-ai] max-iter  : {max_iterations}")

    api_key = os.environ.get("ANTHROPIC_API_KEY") if ai_effective else None
    if ai_effective and not api_key:
        typer.echo("[warn] ANTHROPIC_API_KEY not set — triage will be skipped", err=True)

    from controller.controller import ScanController
    controller = ScanController(
        scope,
        ai_enabled=ai_effective,
        agent_enabled=agent,
        enabled_modules=enabled_modules,
        enabled_flags=enabled_flags,
        module_config=profile_config or None,
        db_url=db_url,
        anthropic_api_key=api_key,
        ai_model=ai_model,
        max_agent_iterations=max_iterations,
        rate_limit=rate_limit,
        max_concurrency=max_concurrency,
    )

    try:
        asyncio.run(controller.run(domain))
    except KeyboardInterrupt:
        typer.echo("\n[recon-ai] interrupted", err=True)
        raise typer.Exit(code=130)


# ── modules ───────────────────────────────────────────────────────────────────

@app.command(name="modules")
def list_modules(
    show_profiles: bool = typer.Option(False, "--profiles", help="Show scan profiles instead."),
) -> None:
    """List all available recon modules (or scan profiles with --profiles)."""
    if show_profiles:
        from modules.registry import SCAN_PROFILES
        typer.echo(f"{'PROFILE':<12}  DESCRIPTION")
        typer.echo("-" * 70)
        for name, p in SCAN_PROFILES.items():
            typer.echo(f"{name:<12}  {p['description']}")
        typer.echo("\nUse: recon-ai scan <domain> --profile <name>")
        return

    from modules.registry import ModuleRegistry
    rows = ModuleRegistry.info()
    if not rows:
        typer.echo("No modules found.")
        return
    typer.echo(f"{'NAME':<20}  {'FLAGS':<36}  DESCRIPTION")
    typer.echo("-" * 88)
    for r in rows:
        flags = ", ".join(r["flags"]) or "-"
        typer.echo(f"{r['name']:<20}  {flags:<36}  {r['description']}")


# ── triage ────────────────────────────────────────────────────────────────────

@app.command()
def triage(
    scan_id: str = typer.Argument(..., help="Scan UUID to triage."),
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
    ai_model: str = typer.Option("claude-sonnet-4-6", "--ai-model"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run LLM triage over a completed scan (post-hoc). Requires ANTHROPIC_API_KEY."""
    _setup_logging(verbose)
    try:
        uid = uuid.UUID(scan_id)
    except ValueError as exc:
        typer.echo(f"[error] invalid UUID: {exc}", err=True)
        raise typer.Exit(code=1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        typer.echo("[error] ANTHROPIC_API_KEY not set", err=True)
        raise typer.Exit(code=1)

    asyncio.run(_triage(uid, db_url, api_key, ai_model))


async def _triage(
    scan_id: uuid.UUID, db_url: str, api_key: str, model: str
) -> None:
    from ai.triage import Triage
    from database.repository import AiAssessmentRepository, FindingRepository, HostRepository, ScanRepository
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    async with make_session_factory(engine)() as session:
        scan = await ScanRepository(session).get(scan_id)
        if scan is None:
            typer.echo(f"[error] scan {scan_id} not found", err=True)
            return
        t = Triage(
            api_key=api_key,
            host_repo=HostRepository(session),
            finding_repo=FindingRepository(session),
            assessment_repo=AiAssessmentRepository(session),
            model=model,
        )
        report = await t.assess_scan(scan_id, scan.target_domain)
        typer.echo(report.print_summary())


# ── history ────────────────────────────────────────────────────────────────────

@app.command()
def history(
    domain: str = typer.Argument(..., help="Domain to look up scan history for."),
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
    limit: int = typer.Option(10, "--limit", "-n"),
) -> None:
    """List past scans for a domain."""
    asyncio.run(_history(domain, db_url, limit))


async def _history(domain: str, db_url: str, limit: int) -> None:
    from database.session import init_db, make_engine, make_session_factory
    from database.repository import ScanRepository
    engine = make_engine(db_url)
    await init_db(engine)
    async with make_session_factory(engine)() as session:
        scans = await ScanRepository(session).recent(domain, limit=limit)
    if not scans:
        typer.echo(f"no scans found for {domain}")
        return
    typer.echo(f"{'ID':<38}  {'STATUS':<10}  {'MODE'}  {'EVENTS':>7}  STARTED")
    for s in scans:
        typer.echo(
            f"{str(s.id):<38}  {s.status:<10}  {s.mode:<5}  {s.event_count:>7}  {s.created_at}"
        )


# ── diff ───────────────────────────────────────────────────────────────────────

@app.command()
def diff(
    scan_a: str = typer.Argument(..., help="Baseline scan UUID."),
    scan_b: str = typer.Argument(..., help="Current scan UUID."),
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
) -> None:
    """Show what changed between two scans."""
    try:
        uuid_a = uuid.UUID(scan_a)
        uuid_b = uuid.UUID(scan_b)
    except ValueError as exc:
        typer.echo(f"[error] invalid UUID: {exc}", err=True)
        raise typer.Exit(code=1)

    asyncio.run(_diff(uuid_a, uuid_b, db_url))


async def _diff(scan_a: uuid.UUID, scan_b: uuid.UUID, db_url: str) -> None:
    from database.diff import compute_diff
    from database.repository import EventRepository
    from database.session import make_engine, make_session_factory
    engine = make_engine(db_url)
    async with make_session_factory(engine)() as session:
        result = await compute_diff(EventRepository(session), scan_a, scan_b)
    typer.echo(result.summary())


if __name__ == "__main__":
    app()
