"""
Triage — post-scan LLM annotation of structured recon records.

Phase 3 design:
  - Runs AFTER enumeration completes, not during. It reads from the DB.
  - Two LLM calls: one batch for all hosts, one per finding.
  - Writes results to ai_assessments table.
  - Never reads raw tool output or HTTP bodies — only sanitized DB records.
  - Failures are logged but never fatal: the scan result is complete regardless.

What the AI can do in Phase 3:
  ✅ Rank hosts by importance / environment guess
  ✅ Note interesting indicators (unusual ports, known-risky techs)
  ✅ Assess whether a finding candidate is worth investigating
  ✅ Suggest investigation angles for the human analyst

What the AI cannot do in Phase 3:
  ❌ Trigger any recon action (that's Phase 4)
  ❌ Override scope decisions
  ❌ See raw HTTP responses, cookies, or auth tokens
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from uuid import UUID

import anthropic

from ai.assessor import Assessor
from ai.prompts.finding import FINDING_ASSESSMENT_TOOL, build_finding_prompt
from ai.prompts.host import HOST_ASSESSMENT_TOOL, build_host_list_prompt
from database.models import AiAssessment, Finding, Host
from database.repository import (
    AiAssessmentRepository,
    FindingRepository,
    HostRepository,
)

log = logging.getLogger(__name__)


# ── result types ──────────────────────────────────────────────────────────────

@dataclass
class HostAssessment:
    host: Host
    importance: str          # low / medium / high / critical
    environment: str         # prod / staging / dev / internal / unknown
    attack_surface_notes: str
    interesting_indicators: list[str] = field(default_factory=list)
    db_record: AiAssessment | None = None


@dataclass
class FindingAssessment:
    finding: Finding
    confirmed_interesting: bool
    severity: str            # info / low / medium / high / critical
    reasoning: str
    investigation_notes: str
    db_record: AiAssessment | None = None


@dataclass
class TriageReport:
    scan_id: UUID
    host_assessments: list[HostAssessment] = field(default_factory=list)
    finding_assessments: list[FindingAssessment] = field(default_factory=list)

    def print_summary(self) -> str:
        lines = [f"\n{'─'*60}", f"  TRIAGE REPORT  scan={self.scan_id}", f"{'─'*60}"]

        if self.host_assessments:
            lines.append(f"\nHOSTS ({len(self.host_assessments)} assessed, by priority):")
            for ha in self.host_assessments:
                badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(
                    ha.importance, "  "
                )
                lines.append(f"  {badge} [{ha.importance.upper():<8}] {ha.host.hostname}")
                lines.append(f"       env={ha.environment}")
                if ha.attack_surface_notes:
                    lines.append(f"       {ha.attack_surface_notes[:120]}")
                for ind in ha.interesting_indicators[:3]:
                    lines.append(f"       → {ind[:100]}")
        else:
            lines.append("\nNo hosts assessed (empty scan or DB unavailable).")

        if self.finding_assessments:
            lines.append(f"\nFINDINGS ({len(self.finding_assessments)} assessed):")
            for fa in self.finding_assessments:
                flag = "✓" if fa.confirmed_interesting else "✗"
                lines.append(
                    f"  [{flag}] [{fa.severity.upper():<8}] {fa.finding.title[:80]}"
                    f"  ({fa.finding.host})"
                )
                if fa.confirmed_interesting and fa.investigation_notes:
                    lines.append(f"       → {fa.investigation_notes[:120]}")
        else:
            lines.append("\nNo findings to assess.")

        lines.append(f"{'─'*60}\n")
        return "\n".join(lines)


# ── Triage ────────────────────────────────────────────────────────────────────

class Triage:
    def __init__(
        self,
        api_key: str,
        host_repo: HostRepository,
        finding_repo: FindingRepository,
        assessment_repo: AiAssessmentRepository,
        model: str = "claude-sonnet-4-6",
    ) -> None:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        self._assessor = Assessor(client, model)
        self._host_repo = host_repo
        self._finding_repo = finding_repo
        self._assessment_repo = assessment_repo
        self._model = model

    async def assess_scan(self, scan_id: UUID, target_domain: str = "") -> TriageReport:
        """Run triage over all hosts and findings for a completed scan."""
        log.info("triage: starting for scan %s", scan_id)
        report = TriageReport(scan_id=scan_id)

        hosts = await self._host_repo.list_for_scan(scan_id)
        if hosts:
            report.host_assessments = await self._assess_hosts(scan_id, hosts, target_domain)
        else:
            log.info("triage: no hosts to assess")

        findings = await self._finding_repo.list_for_scan(scan_id)
        for finding in findings:
            fa = await self._assess_finding(scan_id, finding)
            report.finding_assessments.append(fa)

        log.info(
            "triage: complete — %d hosts, %d findings",
            len(report.host_assessments),
            len(report.finding_assessments),
        )
        return report

    # ── host batch assessment ─────────────────────────────────────────────────

    async def _assess_hosts(
        self, scan_id: UUID, hosts: list[Host], target_domain: str
    ) -> list[HostAssessment]:
        prompt = build_host_list_prompt(target_domain, hosts)
        raw = await self._assessor.call(prompt, HOST_ASSESSMENT_TOOL)

        if not raw or "assessments" not in raw:
            log.warning("triage: host assessment returned no data")
            return []

        # Build a hostname → Host lookup for O(1) matching.
        host_map = {h.hostname: h for h in hosts}
        results: list[HostAssessment] = []

        for item in raw.get("assessments", []):
            hostname = item.get("hostname", "")
            host = host_map.get(hostname)
            if host is None:
                log.debug("triage: LLM mentioned unknown host %r — skipping", hostname)
                continue

            ha = HostAssessment(
                host=host,
                importance=item.get("importance", "low"),
                environment=item.get("environment", "unknown"),
                attack_surface_notes=str(item.get("attack_surface_notes", ""))[:512],
                interesting_indicators=[
                    str(ind)[:200] for ind in item.get("interesting_indicators", [])[:10]
                ],
            )
            ha.db_record = await self._save_host_assessment(scan_id, host, ha)
            results.append(ha)

        # Hosts the LLM didn't mention get a default low-importance record.
        assessed_names = {ha.host.hostname for ha in results}
        for host in hosts:
            if host.hostname not in assessed_names:
                ha = HostAssessment(
                    host=host,
                    importance="low",
                    environment="unknown",
                    attack_surface_notes="Not assessed (not returned by model).",
                )
                ha.db_record = await self._save_host_assessment(scan_id, host, ha)
                results.append(ha)

        # Sort: critical → high → medium → low
        _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: _rank.get(x.importance, 4))
        return results

    async def _save_host_assessment(
        self, scan_id: UUID, host: Host, ha: HostAssessment
    ) -> AiAssessment:
        record = AiAssessment(
            scan_job_id=scan_id,
            target_type="host",
            target_id=host.id,
            importance=ha.importance,
            environment_guess=ha.environment,
            attack_surface_notes=ha.attack_surface_notes,
            assessment={
                "interesting_indicators": ha.interesting_indicators,
                "model": self._model,
            },
            model_used=self._model,
        )
        return await self._assessment_repo.save(record)

    # ── finding assessment ────────────────────────────────────────────────────

    async def _assess_finding(self, scan_id: UUID, finding: Finding) -> FindingAssessment:
        prompt = build_finding_prompt(finding)
        raw = await self._assessor.call(prompt, FINDING_ASSESSMENT_TOOL)

        fa = FindingAssessment(
            finding=finding,
            confirmed_interesting=bool(raw.get("confirmed_interesting", False)),
            severity=raw.get("severity", "info"),
            reasoning=str(raw.get("reasoning", ""))[:512],
            investigation_notes=str(raw.get("investigation_notes", ""))[:512],
        )

        record = AiAssessment(
            scan_job_id=scan_id,
            target_type="finding",
            target_id=finding.id,
            importance=fa.severity,
            attack_surface_notes=fa.reasoning,
            assessment={
                "confirmed_interesting": fa.confirmed_interesting,
                "investigation_notes": fa.investigation_notes,
                "model": self._model,
            },
            model_used=self._model,
        )
        fa.db_record = await self._assessment_repo.save(record)
        return fa
