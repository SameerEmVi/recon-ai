"""
Evidence read API — the captured request/response proof behind pentest findings
(docs/pentest-section-design.md §6), surfaced for the operator-facing console.

Read-only. Reads `HttpExchange` rows through the existing repository and returns
the **redacted, operator-safe display view** (`evidence.exchange_for_display`):
URL + headers are already redacted at capture; bodies are decrypted only when the
server process holds the evidence key (`RECON_AI_EVIDENCE_KEY`), else the view
shows metadata with `bodies_available=false` — never ciphertext, never the LLM
path. Degrades to an empty payload with no DB.

The evidence table may predate this feature on an existing DB, so a read that hits
a missing table just returns nothing rather than erroring.
"""

from __future__ import annotations

from uuid import UUID

_MAX = 500


async def build_evidence(
    db_url: str | None,
    *,
    scan_id: str | None = None,
    finding_id: str | None = None,
    limit: int = _MAX,
) -> dict:
    """List captured exchanges for a scan (optionally one finding), as display
    views. `key_available` tells the UI whether bodies can be shown."""
    from evidence.crypto import EvidenceCipher

    cipher = EvidenceCipher.from_env()
    out: dict = {"exchanges": [], "count": 0, "key_available": cipher.enabled}
    if not db_url:
        return out

    from database.repository import HttpExchangeRepository
    from database.session import make_engine, make_session_factory
    from evidence.capture import exchange_for_display

    limit = max(1, min(int(limit or _MAX), _MAX))
    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            repo = HttpExchangeRepository(s)
            try:
                if finding_id:
                    rows = await repo.list_for_finding(UUID(finding_id))
                elif scan_id:
                    rows = await repo.list_for_scan(UUID(scan_id), limit=limit)
                else:
                    rows = []
            except Exception:
                rows = []                       # missing table / bad id → nothing
            out["exchanges"] = [exchange_for_display(r, cipher) for r in rows[:limit]]
            out["count"] = len(out["exchanges"])
    except Exception:
        pass
    finally:
        await engine.dispose()
    return out


async def evidence_summary(db_url: str | None, scan_id: str | None = None) -> dict:
    """Counts for the pentest section header: exchanges stored, how many are bound
    to a finding, and whether bodies are readable here."""
    data = await build_evidence(db_url, scan_id=scan_id)
    linked = sum(1 for e in data["exchanges"] if e.get("finding_id"))
    return {
        "exchanges": data["count"],
        "linked_to_findings": linked,
        "key_available": data["key_available"],
    }
