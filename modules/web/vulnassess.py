"""
vulnassess — evidence-based vulnerability assessment module.

The integration point for the `vulnscan` layer. It is a normal reactive module
(registered in the existing module registry, runs in `--full`) that:

  1. observes recon events during the scan (TECHNOLOGY / HTTP_SERVICE / URL /
     ENDPOINT / PARAMETER / ANOMALY / FINDING_CANDIDATE) into a pure
     `AssessmentState` — no network, no scope logic;
  2. at `finish()` (full fingerprint known), builds one `CheckContext` per host,
     runs the `AssessmentEngine` (technology-aware check selection, one
     low-impact GET per service for header/cookie checks through the shared
     limiter/cache, per-check isolation), de-dups results, and emits each
     emittable result as a `FINDING_CANDIDATE` (category `vuln:<check_id>`);
  3. builds the JSON + human-readable vulnerability report and attaches it to the
     result aggregator's single writer.

Because emission is `self.emit → stamp_and_publish → ScopeEngine`, every result
is scope-checked, dedup'd and persisted like any other finding, and the existing
AI triage pass annotates each one. Deterministic code owns the verification
`status`; the LLM never promotes a result to CONFIRMED.

Tiers (requirement #1): passive + low-impact active run by default; the intrusive
tier is disabled unless BOTH `intrusive=True` and `authorized_intrusive=True`.

Watches:  TECHNOLOGY, HTTP_SERVICE, URL, ENDPOINT, PARAMETER, ANOMALY, FINDING_CANDIDATE
Produces: FINDING_CANDIDATE
"""

from __future__ import annotations

from events.types import Event, EventType
from modules.base import BaseModule
from modules.registry import register
from vulnscan.engine import AssessmentEngine, AssessmentState
from vulnscan.report import build_report, render_json, render_text, summary_sections


@register
class VulnAssessModule(BaseModule):
    name = "vulnassess"
    description = "Evidence-based vulnerability assessment over recon intelligence (native checks)"
    watched_events = [
        "TECHNOLOGY", "HTTP_SERVICE", "URL", "ENDPOINT",
        "PARAMETER", "ANOMALY", "FINDING_CANDIDATE",
    ]
    produced_events = ["FINDING_CANDIDATE"]
    flags = ["active", "web", "vuln", "assessment"]
    estimated_cost = 5
    expected_value = 9
    options = {
        "active_checks": True,          # low-impact active tier (header/cookie/reflection probes)
        "intrusive": False,             # intrusive tier — OFF by default
        "authorized_intrusive": False,  # must ALSO be True for the intrusive tier to run
        "timeout": 15,
        "max_body_kb": 512,
    }

    def __init__(self, controller, config=None) -> None:
        super().__init__(controller, config)
        self._state = AssessmentState()

    async def setup(self) -> bool:
        return True  # pure Python; active checks reuse BaseModule.fetch

    async def handle_event(self, event: Event) -> None:
        # Never re-observe our own assessment findings (avoids feedback).
        etype = getattr(event.type, "value", event.type)
        if etype == EventType.FINDING_CANDIDATE.value:
            cat = getattr(event.data, "category", "") or ""
            if cat.startswith("vuln:") or getattr(event, "source_tool", "") == self.name:
                return
        self._state.observe(event)

    async def _probe(self, url: str):
        """Shared-limiter, cached GET used by active checks (header/reflection)."""
        return await self.fetch(
            url,
            timeout=int(self.opt("timeout")),
            max_body_kb=int(self.opt("max_body_kb")),
            follow_redirects=True,
        )

    async def finish(self) -> None:
        active = bool(self.opt("active_checks"))
        want_intrusive = bool(self.opt("intrusive"))
        authorized = bool(self.opt("authorized_intrusive"))
        intrusive = want_intrusive and authorized
        if want_intrusive and not authorized:
            self._log.warning(
                "vulnassess: intrusive tier requested but authorized_intrusive=False — "
                "skipping intrusive checks (explicit authorization required)"
            )

        contexts = self._state.build_contexts(
            fetch=self._probe, active=active, intrusive=intrusive
        )
        if not contexts:
            return

        engine = AssessmentEngine(active=active, intrusive=intrusive)
        outcome = await engine.assess(contexts)

        emitted = 0
        for r in outcome.emitted:
            if await self.emit(EventType.FINDING_CANDIDATE, r.to_finding_data()):
                emitted += 1

        self._log.info(
            "vulnassess: %d result(s) (%d emitted, %d report-only) · checks ran=%d skipped=%d failed=%d",
            len(outcome.results), emitted, len(outcome.results) - len(outcome.emitted),
            len(outcome.executed), len(outcome.skipped), len(outcome.failed),
        )

        self._attach_report(outcome)

    def _attach_report(self, outcome) -> None:
        agg = getattr(self._ctrl, "aggregator", None)
        if agg is None or not hasattr(agg, "attach_vuln_report"):
            return
        try:
            report = build_report(
                self._ctrl.scan_domain or "",
                outcome.results,
                outcome=outcome,
                scan_id=getattr(self._ctrl, "scan_id", None),
            )
            agg.attach_vuln_report(
                render_text(report), render_json(report), summary_sections(report)
            )
        except Exception as exc:
            self._log.debug("vulnassess: report attach failed: %s", exc)
