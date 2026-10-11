"""
vulnscan result schema — the structured, evidence-bearing vulnerability record.

Every check produces zero or more `VulnResult`s. A VulnResult carries everything
requirement #4 demands: asset + affected URL, category + check id, evidence +
detection method, confidence, severity + rationale, verification status,
remediation, source module + timestamp.

A VulnResult is projected onto the existing `FINDING_CANDIDATE` event (see
`to_finding_data`) so it flows through the unchanged scope gate, dedup,
persistence, aggregator and AI-triage pipeline. All the structured fields are
folded into the finding's `evidence` dict, so they persist in the existing
`findings.evidence` JSON column with no database migration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


# ── verification status ─────────────────────────────────────────────────────
# Deterministic code owns this field; the LLM may annotate importance but never
# promotes a result to CONFIRMED.
class Status:
    OBSERVED = "OBSERVED"        # a factual condition we directly observed (e.g. header missing)
    POTENTIAL = "POTENTIAL"      # likely, but manual verification required
    UNCONFIRMED = "UNCONFIRMED"  # ambiguous / low-certainty evidence (fuzzy fingerprint, backport)
    CONFIRMED = "CONFIRMED"      # we verified the condition's content non-destructively


STATUSES = (Status.OBSERVED, Status.POTENTIAL, Status.UNCONFIRMED, Status.CONFIRMED)


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITIES = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # info=0 … critical=4 (highest)

# Check tiers (requirement #1): passive · low-impact active · intrusive.
TIER_PASSIVE = "passive"
TIER_ACTIVE = "active"
TIER_INTRUSIVE = "intrusive"
TIERS = (TIER_PASSIVE, TIER_ACTIVE, TIER_INTRUSIVE)

CONFIDENCE_LABELS = ((0.85, "high"), (0.5, "medium"), (0.0, "low"))


def confidence_label(confidence: float) -> str:
    for threshold, label in CONFIDENCE_LABELS:
        if confidence >= threshold:
            return label
    return "low"


def severity_rank(severity: str) -> int:
    return _SEV_RANK.get((severity or "info").lower(), 0)


@dataclass
class VulnResult:
    """One structured, evidence-backed vulnerability assessment result."""

    asset: str                              # host the result is about
    check_id: str
    check_name: str
    category: str                           # human category, e.g. "security-headers"
    status: str                             # one of STATUSES — set by deterministic code
    severity: str                           # one of SEVERITIES
    confidence: float                       # 0..1
    detection_method: str                   # how it was found (passive-correlation, header-probe, …)
    severity_rationale: str = ""            # why this severity
    remediation: str = ""
    url: str | None = None                  # affected URL, where applicable
    evidence: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)   # CVE / CWE / links
    tier: str = TIER_PASSIVE
    # When False, the result is a *normalization* of a finding another module
    # already emitted — included in the report for a unified view, but NOT
    # re-emitted as a new event (avoids duplicating cross-check findings).
    emit: bool = True
    source_module: str = "vulnassess"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # dedup identity: same (asset, check, affected url) is the same result across
    # checks and scans. Mirrors the finding dedup key (host:title:category).
    @property
    def dedup_key(self) -> str:
        return f"{self.asset.lower()}|{self.check_id}|{(self.url or '').lower()}"

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"invalid status {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if not self.evidence:
            # Requirement #4: every result must carry evidence. A check that
            # cannot substantiate a result must not produce one.
            raise ValueError(f"{self.check_id}: a VulnResult must carry evidence")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    # ── projection onto the existing FINDING_CANDIDATE event ──────────────────
    def title(self) -> str:
        where = self.url or self.asset
        return f"{self.check_name}: {where}"

    def description(self) -> str:
        bits = [
            f"[{self.status}] {self.check_name} on {self.url or self.asset}.",
            self.severity_rationale.strip(),
        ]
        if self.status != Status.CONFIRMED:
            bits.append("This is an assessment candidate — verify before reporting.")
        if self.remediation:
            bits.append(f"Remediation: {self.remediation}")
        return " ".join(b for b in bits if b)

    def to_finding_data(self):
        """Build a FindingCandidateData (sanitized/capped by its own validators).

        All structured fields are folded into `evidence` so they persist in the
        existing findings.evidence JSON — no schema change. Evidence is kept to
        well under the 20-entry cap the validator enforces.
        """
        from events.types import FindingCandidateData

        ev: dict = {
            "check_id": self.check_id,
            "status": self.status,
            "confidence": round(self.confidence, 3),
            "confidence_label": confidence_label(self.confidence),
            "detection_method": self.detection_method,
            "tier": self.tier,
            "source_module": self.source_module,
            "timestamp": self.timestamp,
        }
        if self.url:
            ev["url"] = self.url[:512]
        if self.references:
            ev["references"] = ", ".join(self.references)[:512]
        if self.remediation:
            ev["remediation"] = self.remediation[:512]
        # Fold in up to a handful of check-specific evidence keys (stay <20 total).
        for i, (k, v) in enumerate(self.evidence.items()):
            if i >= 8:
                break
            ev[f"ev_{k}"] = v
        return FindingCandidateData(
            host=self.asset,
            title=self.title(),
            description=self.description(),
            category=f"vuln:{self.check_id}",
            severity_hint=self.severity,
            evidence=ev,
        )
