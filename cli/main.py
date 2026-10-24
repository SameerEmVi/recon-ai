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

from scope.types import Scope, ScopeStatus

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
        help="Enable ALL modules: default + passive + web + crawl + discovery. "
             "(Legacy; prefer --mode full. Equivalent to --mode full when no --mode given.)",
    ),
    mode: str | None = typer.Option(
        None, "--mode",
        help=(
            "Execution mode — the central capability ceiling AND default module set:\n"
            "osint = passive external intel only (NO target probing/fuzzing/scanning); "
            "vuln = minimal discovery + vulnerability assessment; "
            "active = passive + full active recon + non-intrusive vuln checks; "
            "full = complete authorized pipeline. "
            "Enforced throughout execution (incl. the AI agent). Omit = legacy behaviour "
            "(active ceiling + your -m/--profile/--full selection)."
        ),
    ),
    intrusive: bool = typer.Option(
        False, "--intrusive",
        help="Authorize the INTRUSIVE check tier (active/full modes only). Off by "
             "default; requires explicit opt-in. Never enables destructive payloads.",
    ),
    # ── related (sibling) root domains ────────────────────────────────────────
    related: bool = typer.Option(
        False, "--related",
        help="Also discover sibling ROOT domains owned by the same org (e.g. "
             "brand.com, brandliving.nz). Reported for review, never scanned.",
    ),
    related_http: bool = typer.Option(
        False, "--related-http",
        help="Confirm related domains by one GET / each and check it redirects to "
             "the target. Contacts hosts OUTSIDE scope — only if your program allows. "
             "Implies --related.",
    ),
    brand: list[str] = typer.Option(
        [], "--brand",
        help="Extra brand stem for related-domain guessing (repeatable), e.g. --brand oceania.",
    ),
    org: str | None = typer.Option(
        None, "--org",
        help="Registrant organisation for reverse-WHOIS related-domain lookup "
             "(needs WHOISXML_API_KEY; not useful for .nz, whose WHOIS hides registrants).",
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
    # ── adaptive planner ──────────────────────────────────────────────────────
    plan_mode: str = typer.Option(
        "default", "--plan-mode",
        help="Adaptive planner mode: passive-first | default | aggressive. "
             "passive-first runs only passive modules; aggressive raises budgets "
             "and per-host caps. Default preserves normal behaviour.",
    ),
    budget: int = typer.Option(
        0, "--budget",
        help="Max total module executions the planner will allow (0 = unlimited). "
             "Useful to cap cost on large scopes.",
    ),
    # ── result output ─────────────────────────────────────────────────────────
    out_dir: str = typer.Option(
        "results", "--out-dir",
        help="Directory for categorized result files (results/<domain>/latest/…).",
    ),
    no_results: bool = typer.Option(
        False, "--no-results",
        help="Disable writing the categorized result directory on scan completion.",
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
    proxy: str | None = typer.Option(
        None, "--proxy",
        help="Route outbound HTTP(S) through a proxy, e.g. Burp: http://127.0.0.1:8080 "
             "(or set RECON_AI_PROXY). TLS verification stays ON.",
    ),
    proxy_ca: str | None = typer.Option(
        None, "--proxy-ca",
        help="Path to the proxy's CA bundle (PEM) for HTTPS interception, e.g. Burp's "
             "exported CA (or set RECON_AI_PROXY_CA). Explicit opt-in; never disables TLS.",
    ),
    proxy_insecure: bool = typer.Option(
        False, "--proxy-insecure",
        help="Disable TLS verification for proxied traffic (local Burp testing only, "
             "e.g. when Burp's CA lacks the keyUsage extension). Explicit + logged, "
             "never silent. Prefer --proxy-ca with a valid CA.",
    ),
    debug: bool = typer.Option(
        False, "--debug",
        help="Write verbose structured diagnostics (events/errors/http JSONL) under "
             "results/<domain>/run-<id>/diagnostics/.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress the live per-event stream (the end-of-scan summary still prints).",
    ),
    color: bool | None = typer.Option(
        None, "--color/--no-color",
        help="Force colour on/off. Default: auto (colour on a TTY, off when piped).",
    ),
) -> None:
    """Run a reconnaissance scan against an authorized domain."""
    _setup_logging(verbose)

    from cli import ui
    if color is not None:
        ui.set_color(color)
    print(ui.banner())

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

    # Fail closed before any setup: the seed gets the same deny-first gate as
    # every other target (the controller re-checks this in run()).
    from scope.engine import ScopeEngine
    seed_decision = ScopeEngine(scope).evaluate(domain)
    if seed_decision.status is not ScopeStatus.IN:
        typer.echo(f"[error] seed {domain!r} is not in scope: {seed_decision.reason}", err=True)
        raise typer.Exit(code=1)

    # Outbound proxy (Burp) config: CLI > env (> config file, future). Fail closed
    # on a bad proxy URL / missing CA — never silently disable TLS.
    from net.errors import ConfigurationError
    from net.proxy import ProxyConfig
    try:
        proxy_cfg = ProxyConfig.from_sources(
            cli_proxy=proxy, cli_ca=proxy_ca,
            cli_verify=False if proxy_insecure else None, diagnostic=debug)
    except ConfigurationError as exc:
        typer.echo(f"[error] proxy configuration: {exc}", err=True)
        raise typer.Exit(code=1)
    if proxy_cfg.active and not proxy_cfg.verify and not proxy_cfg.ca_bundle:
        typer.echo(ui.warn("TLS verification DISABLED for proxied traffic "
                           "(--proxy-insecure) — local testing only"))

    ai_effective = ai or agent

    from planner import MODES
    if plan_mode not in MODES:
        typer.echo(f"[error] unknown --plan-mode {plan_mode!r}. Available: {', '.join(MODES)}", err=True)
        raise typer.Exit(code=1)

    # Execution mode = the central capability ceiling. Fail-closed on an invalid
    # value; default "active" preserves legacy behaviour when --mode is omitted.
    from policy import MODES as EXEC_MODES
    if mode is not None and mode not in EXEC_MODES:
        typer.echo(f"[error] unknown --mode {mode!r}. Available: {', '.join(EXEC_MODES)}", err=True)
        raise typer.Exit(code=1)
    exec_mode = mode or "active"
    if intrusive and exec_mode not in ("active", "full"):
        typer.echo(ui.warn(f"--intrusive ignored in '{exec_mode}' mode (only active/full)"))
    user_selected = profile is not None or bool(list(module)) or full or passive

    # Resolve module selection — profiles take precedence.
    from modules.registry import DEFAULT_MODULES, FULL_MODULES, PASSIVE_MODULES, SCAN_PROFILES
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
        typer.echo(ui.kv("profile", f"{profile} — {p['description']}"))
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

    # --mode drives the DEFAULT module set when the user gave no explicit
    # selection; otherwise it is purely the capability ceiling (the controller
    # filters whatever was selected). Either way the controller enforces it.
    if mode is not None:
        if not user_selected:
            from modules.registry import ModuleRegistry
            from policy import CapabilityPolicy
            _pol = CapabilityPolicy(exec_mode, intrusive_authorized=intrusive)
            enabled_modules = _pol.default_module_names(ModuleRegistry.get)
            enabled_flags = None
        else:
            typer.echo(ui.kv("note", f"--mode {exec_mode} ceiling applied to your module selection"))

    # --related adds the module to whatever set was chosen above. With --passive
    # it is already included (it carries the "passive" flag).
    related = related or related_http or bool(brand) or bool(org)
    if related and enabled_flags is None:
        base = enabled_modules if enabled_modules is not None else DEFAULT_MODULES
        if "related_domains" not in base:
            enabled_modules = list(base) + ["related_domains"]
    rel_cfg = {k: v for k, v in (
        ("http_check", related_http or None), ("brands", list(brand) or None), ("org", org),
    ) if v}
    if rel_cfg:
        profile_config = {**profile_config,
                          "related_domains": {**profile_config.get("related_domains", {}), **rel_cfg}}

    typer.echo(ui.kv("in-scope", resolved_in))
    typer.echo(ui.kv("out-scope", resolved_out or "(none)"))
    typer.echo(ui.kv("exec-mode", exec_mode + ("  +intrusive" if (intrusive and exec_mode in ('active', 'full')) else "")))
    ai_label = "A — deterministic"
    if agent:
        ai_label = "B+agent — AI triage + agent loop"
    elif ai_effective:
        ai_label = "B — AI-assisted"
    typer.echo(ui.kv("ai-mode", ai_label))
    if plan_mode != "default" or budget:
        typer.echo(ui.kv("planner", f"{plan_mode}" + (f" (budget {budget})" if budget else "")))
    typer.echo(ui.kv("db", db_url or "(none — in-memory only)"))
    if enabled_modules:
        typer.echo(ui.kv("modules", ", ".join(enabled_modules)))
    elif passive:
        typer.echo(ui.kv("modules", "defaults + passive"))
    elif full:
        typer.echo(ui.kv("modules", "full"))
    else:
        typer.echo(ui.kv("modules", "defaults"))
    if ai_effective:
        typer.echo(ui.kv("ai-model", ai_model))
    if agent:
        typer.echo(ui.kv("max-iter", max_iterations))

    api_key = os.environ.get("ANTHROPIC_API_KEY") if ai_effective else None
    if ai_effective and not api_key:
        typer.echo(ui.warn("ANTHROPIC_API_KEY not set — triage will be skipped"), err=True)

    # Unlock the vulnassess intrusive tier only when authorized in an active/full mode.
    intrusive_ok = intrusive and exec_mode in ("active", "full")
    if intrusive_ok:
        profile_config = {**(profile_config or {}),
                          "vulnassess": {**(profile_config or {}).get("vulnassess", {}),
                                         "intrusive": True, "authorized_intrusive": True}}

    from controller.controller import ScanController
    controller = ScanController(
        scope,
        ai_enabled=ai_effective,
        agent_enabled=agent,
        mode=exec_mode,
        intrusive_authorized=intrusive_ok,
        enabled_modules=enabled_modules,
        enabled_flags=enabled_flags,
        module_config=profile_config or None,
        db_url=db_url,
        anthropic_api_key=api_key,
        ai_model=ai_model,
        max_agent_iterations=max_iterations,
        rate_limit=rate_limit,
        max_concurrency=max_concurrency,
        plan_mode=plan_mode,
        plan_budget=budget,
        results_enabled=not no_results,
        out_dir=out_dir,
        live=not quiet,
        proxy=proxy_cfg,
        debug=debug,
    )

    try:
        asyncio.run(controller.run(domain))
    except KeyboardInterrupt:
        typer.echo(ui.warn("interrupted"), err=True)
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


# ── report ───────────────────────────────────────────────────────────────────

@app.command()
def report(
    target: str = typer.Argument(..., help="Scan UUID, or a domain (uses its most recent scan)."),
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
    json_out: bool = typer.Option(False, "--json", help="Emit structured JSON instead of text."),
    output: str | None = typer.Option(None, "-O", "--output", help="Write to a file instead of stdout."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Render the evidence-based vulnerability report for a scan (text or JSON).

    Reads persisted findings — run a scan with --db-url --full first.
    """
    _setup_logging(verbose)
    asyncio.run(_report(target, db_url, json_out, output))


async def _report(target: str, db_url: str, json_out: bool, output: str | None) -> None:
    from database.repository import FindingRepository, ScanRepository
    from database.session import init_db, make_engine, make_session_factory
    from vulnscan.report import build_report, render_json, render_text, result_from_finding

    engine = make_engine(db_url)
    await init_db(engine)
    async with make_session_factory(engine)() as session:
        scan_repo = ScanRepository(session)
        scan = None
        try:
            scan = await scan_repo.get(uuid.UUID(target))
            domain = scan.target_domain if scan else target
        except ValueError:
            recent = await scan_repo.recent(target, limit=1)
            scan = recent[0] if recent else None
            domain = target
        if scan is None:
            typer.echo(f"[error] no scan found for {target!r}", err=True)
            raise typer.Exit(code=1)

        findings = await FindingRepository(session).list_for_scan(scan.id)

    results = [r for r in (result_from_finding(f) for f in findings) if r is not None]
    rep = build_report(domain, results, scan_id=scan.id)
    text = render_json(rep) if json_out else "\n".join(render_text(rep))

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        typer.echo(f"report written → {output}  ({len(results)} finding(s))")
    else:
        typer.echo(text)


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


# ── wordlist (persistent reconnaissance learning system) ─────────────────────────

wordlist_app = typer.Typer(
    name="wordlist",
    help="Inspect and export the persistent recon-vocabulary knowledge base.",
    no_args_is_help=True,
)
app.add_typer(wordlist_app, name="wordlist")


@wordlist_app.command("stats")
def wordlist_stats(
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
    scope: str | None = typer.Option(
        None, "--scope",
        help="Filter to a scope type: global | technology | target | organization.",
    ),
    scope_key: str | None = typer.Option(
        None, "--scope-key", help="Filter to a scope key (e.g. a tech name or domain)."
    ),
) -> None:
    """Show knowledge-base size per category and per scope."""
    asyncio.run(_wordlist_stats(db_url, scope, scope_key))


async def _wordlist_stats(db_url: str, scope: str | None, scope_key: str | None) -> None:
    from database.knowledge_base import KnowledgeBase
    from database.session import init_db, make_engine, make_session_factory

    engine = make_engine(db_url)
    await init_db(engine)
    async with make_session_factory(engine)() as session:
        stats = await KnowledgeBase(session).stats(scope, scope_key)
    typer.echo(f"knowledge base: {stats['total']} vocabulary items")
    if stats.get("by_scope"):
        typer.echo("by scope:")
        for s, n in sorted(stats["by_scope"].items()):
            typer.echo(f"  {s:<14}{n}")
    typer.echo("by category:")
    for cat, n in sorted(stats["by_category"].items()):
        typer.echo(f"  {cat:<16}{n}")
    if not stats["by_category"]:
        typer.echo("  (empty — run a scan with --db-url and --full to populate it)")


@wordlist_app.command("export")
def wordlist_export(
    category: str = typer.Argument(..., help="Category (see recon.vocabulary.CATEGORIES)."),
    db_url: str = typer.Option(..., "--db-url", help="Database URL."),
    scope: str = typer.Option(
        "global", "--scope",
        help="Knowledge scope: global | technology | target | organization.",
    ),
    scope_key: str = typer.Option(
        "", "--scope-key",
        help="Scope key (required for technology/target/organization scopes).",
    ),
    out: str | None = typer.Option(
        None, "--out", "-O", help="Write to this file instead of stdout."
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-n", help="Cap the number of words emitted."
    ),
    min_targets: int = typer.Option(
        1, "--min-targets", help="Only words seen on at least this many targets."
    ),
    min_occurrence: int = typer.Option(
        1, "--min-occurrence", help="Only words seen at least this many times."
    ),
    min_confidence: float = typer.Option(
        0.0, "--min-confidence", help="Only words with at least this confidence (0..1)."
    ),
) -> None:
    """Generate a ranked wordlist for one category+scope (broadest/most-confident first).

    The output file can be fed straight to content discovery, e.g. the ffuf
    module's wordlist=<path> option. Learned words are candidates for probing,
    never assertions that any of them exist.
    """
    from recon.vocabulary import CATEGORIES, SCOPES

    if category not in CATEGORIES:
        typer.echo(f"[error] unknown category {category!r}. Available: {', '.join(CATEGORIES)}", err=True)
        raise typer.Exit(code=1)
    if scope not in SCOPES:
        typer.echo(f"[error] unknown scope {scope!r}. Available: {', '.join(SCOPES)}", err=True)
        raise typer.Exit(code=1)
    asyncio.run(_wordlist_export(
        db_url, category, scope, scope_key, out, limit, min_targets, min_occurrence, min_confidence
    ))


async def _wordlist_export(
    db_url: str, category: str, scope: str, scope_key: str, out: str | None,
    limit: int | None, min_targets: int, min_occurrence: int, min_confidence: float,
) -> None:
    from database.knowledge_base import KnowledgeBase
    from database.session import init_db, make_engine, make_session_factory

    engine = make_engine(db_url)
    await init_db(engine)
    async with make_session_factory(engine)() as session:
        kb = KnowledgeBase(session)
        kw = dict(
            scope_type=scope, scope_key=scope_key, min_target_count=min_targets,
            min_occurrence=min_occurrence, min_confidence=min_confidence, limit=limit,
        )
        if out:
            n = await kb.export_to_file(category, out, **kw)
            typer.echo(f"wrote {n} words to {out}")
        else:
            for w in await kb.generate_wordlist(category, **kw):
                typer.echo(w)


@app.command()
def diagnostics(
    domain: str | None = typer.Argument(
        None, help="Target domain whose run diagnostics to inspect. Omit to use the "
                   "most recent run across all targets."),
    run_id: str | None = typer.Option(None, "--run-id", help="Inspect a specific run id."),
    errors_only: bool = typer.Option(False, "--errors-only", help="Show only error records."),
    module: str | None = typer.Option(None, "--module", help="Filter records to one module."),
    export: bool = typer.Option(False, "--export", help="Write a sanitized .zip bundle of the run's diagnostics and print its path."),
    proxy_check: str | None = typer.Option(
        None, "--proxy-check", help="Test connectivity to a proxy URL (no scan) and exit."),
    out_dir: str = typer.Option("results", "--out-dir"),
    limit: int = typer.Option(30, "--limit", help="Max records to print."),
) -> None:
    """Inspect a finished scan's structured diagnostics (no scanning is performed)."""
    import glob
    import json as _json
    from cli import ui

    # --proxy-check is a standalone connectivity probe (no target traffic).
    if proxy_check is not None:
        from net.errors import ConfigurationError
        from net.proxy import ProxyConfig
        try:
            cfg = ProxyConfig.from_sources(cli_proxy=proxy_check)
        except ConfigurationError as exc:
            typer.echo(f"[error] {exc}", err=True)
            raise typer.Exit(code=1)
        ok, msg = asyncio.run(cfg.probe())
        typer.echo((ui.ok if ok else ui.warn)(f"{cfg.describe()} → {msg}"))
        raise typer.Exit(code=0 if ok else 2)

    # Locate run directories: results/<domain>/run-<id>/diagnostics/
    pattern = os.path.join(out_dir, domain or "*", "run-*", "diagnostics")
    dirs = [d for d in glob.glob(pattern) if os.path.isdir(d)]
    if run_id:
        dirs = [d for d in dirs if f"run-{run_id}" in d]
    if not dirs:
        typer.echo("no diagnostics found (run a scan with --debug or --proxy)", err=True)
        raise typer.Exit(code=1)
    diag_dir = max(dirs, key=os.path.getmtime)   # most recent
    run_dir = os.path.dirname(diag_dir)

    if export:
        import zipfile
        bundle = run_dir + "-diagnostics.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
            for fn in os.listdir(diag_dir):
                zf.write(os.path.join(diag_dir, fn), arcname=fn)
        typer.echo(ui.ok(f"sanitized diagnostics bundle → {bundle}"))
        raise typer.Exit(code=0)

    summary_path = os.path.join(diag_dir, "summary.json")
    if os.path.isfile(summary_path):
        s = _json.loads(open(summary_path, encoding="utf-8").read())
        print(ui.section("Diagnostics", os.path.basename(run_dir)))
        print(ui.kv("run-id", s.get("run_id")))
        print(ui.kv("errors", s.get("total_errors", 0)))
        for cat, n in (s.get("errors_by_category") or {}).items():
            print(ui.bullet(f"{ui.paint(str(n), 'byellow')}  {cat}"))
        for mod, n in (s.get("errors_by_module") or {}).items():
            print(ui.bullet(f"{ui.paint(str(n), 'bred')}  module {mod}", "grey"))

    stream = "errors" if errors_only else "events"
    path = os.path.join(diag_dir, f"{stream}.jsonl")
    if not os.path.isfile(path):
        return
    print("\n" + ui.section(stream))
    shown = 0
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = _json.loads(line)
        except ValueError:
            continue
        if module and rec.get("module") != module:
            continue
        ts = (rec.get("timestamp") or "")[11:19]
        lvl = rec.get("level", "")
        fg = "bred" if lvl in ("ERROR", "CRITICAL") else "grey"
        extra = rec.get("error_type") or rec.get("status") or ""
        print(ui.bullet(f"{ts} {ui.paint(lvl, fg)} {rec.get('event')} "
                        f"{rec.get('module') or ''} {extra}"))
        shown += 1
        if shown >= limit:
            break
    print(ui.info(f"diagnostics dir → {diag_dir}"))


if __name__ == "__main__":
    app()
