"""
Evidence-aware vulnerability report builder (docs §5).

Assembles the report dict from persisted findings **plus the captured
request/response evidence** bound to each one, so the output is a shareable
deliverable — not just a list of claims. Shared by the `recon-ai report` CLI and
the `/api/report` route. Bodies are decrypted only when the server holds
`RECON_AI_EVIDENCE_KEY` (else metadata-only, never ciphertext).

Pure assembly over existing repositories; no schema change.
"""

from __future__ import annotations

from uuid import UUID


async def build_scan_report(db_url: str | None, target: str,
                            *, with_evidence: bool = True) -> tuple[dict | None, object | None]:
    """Return (report_dict, scan) for a scan UUID or a domain's most recent scan,
    or (None, None) when not found. The report's findings carry
    `evidence_exchanges` (display views of the exchanges that prove them)."""
    if not db_url:
        return None, None

    from database.repository import (
        FindingRepository, HttpExchangeRepository, ScanRepository,
    )
    from database.session import make_engine, make_session_factory
    from evidence.capture import exchange_for_display
    from evidence.crypto import EvidenceCipher
    from vulnscan.report import build_report, result_from_finding

    cipher = EvidenceCipher.from_env()
    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            scan_repo = ScanRepository(s)
            scan = None
            domain = target
            try:
                scan = await scan_repo.get(UUID(target))
                domain = scan.target_domain if scan else target
            except ValueError:
                try:
                    recent = await scan_repo.recent(target, limit=1)
                    scan = recent[0] if recent else None
                except Exception:
                    scan = None
            except Exception:
                scan = None                     # missing/old table, bad DB
            if scan is None:
                return None, None

            findings = await FindingRepository(s).list_for_scan(scan.id)
            results = []
            evidence: dict[str, list] = {}
            ex_repo = HttpExchangeRepository(s)
            for f in findings:
                r = result_from_finding(f)
                if r is None:
                    continue
                results.append(r)
                if with_evidence:
                    try:
                        rows = await ex_repo.list_for_finding(f.id)
                    except Exception:
                        rows = []
                    if rows:
                        evidence[r.dedup_key] = [exchange_for_display(e, cipher) for e in rows]

            report = build_report(domain, results, scan_id=scan.id, evidence=evidence)
            return report, scan
    finally:
        await engine.dispose()


def render_report(report: dict, fmt: str) -> str:
    from vulnscan.report import render_html, render_json, render_markdown, render_text
    if fmt == "json":
        return render_json(report)
    if fmt in ("md", "markdown"):
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    return "\n".join(render_text(report))
