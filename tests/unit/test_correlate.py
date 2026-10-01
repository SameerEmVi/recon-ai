"""Unit tests for the LLM correlation & intelligence layer (deterministic parts
+ guardrail + a mocked-LLM analyze)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from ai.correlate import (
    IntelligenceAnalyst,
    build_evidence,
    render_intelligence_txt,
    render_summary_sections,
    verify,
)
from events.types import (
    Event,
    EventType,
    HttpServiceData,
    SubdomainData,
    TechnologyData,
    UrlData,
)

SID = uuid.uuid4()


def _mk(etype, data, tool="test"):
    return Event.create(etype, data, scan_job_id=SID, source_tool=tool)


def _aggregator_with_evidence():
    """A real aggregator populated to mirror the spec's example."""
    from output.aggregator import ResultAggregator
    agg = ResultAggregator(out_dir="/tmp/does-not-matter")
    agg.observe(_mk(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="t")))
    agg.observe(_mk(EventType.HTTP_SERVICE, HttpServiceData(
        url="https://api.example.com/", status_code=200, server="nginx")))
    agg.observe(_mk(EventType.TECHNOLOGY, TechnologyData(host="api.example.com", name="GraphQL")))
    agg.observe(_mk(EventType.TECHNOLOGY, TechnologyData(host="api.example.com", name="Node.js")))
    agg.observe(_mk(EventType.URL, UrlData(url="https://api.example.com/api/v2/export"), tool="httpx_probe"))
    agg.observe(_mk(EventType.URL, UrlData(url="https://api.example.com/graphql"), tool="apifinder"))
    # historical version from wayback (source matters for _urls_by_source)
    agg.observe(_mk(EventType.URL, UrlData(url="https://api.example.com/api/v1/export"), tool="wayback"))
    return agg


# ── evidence packaging ────────────────────────────────────────────────────────

def test_build_evidence_bundles_counts_and_samples():
    agg = _aggregator_with_evidence()
    bundle, known = build_evidence(agg)

    assert bundle["counts"]["subdomains"] >= 1
    assert "GraphQL" in bundle["technologies"] and "Node.js" in bundle["technologies"]
    assert any("/api/v2/export" in u for u in bundle["subdomains_sample"] + [str(x) for x in bundle["wayback_sample"]] + list(map(str, bundle.get("endpoints_sample", []))) + [str(x) for x in bundle["sources"]]) or \
        any("/api/v2/export" in t for t in known)
    # wayback (historical) URL is captured under its own sample
    assert any("v1/export" in u for u in bundle["wayback_sample"])
    # known token set is usable by the guardrail
    assert any("/api/v2/export" in t for t in known)


def test_build_evidence_known_contains_paths_and_tech():
    agg = _aggregator_with_evidence()
    _, known = build_evidence(agg)
    assert any("graphql" in t for t in known)
    assert any("api.example.com" in t for t in known)


# ── guardrail: verify() drops unverifiable claims ─────────────────────────────

def test_verify_keeps_grounded_finding_drops_hallucination():
    _, known = build_evidence(_aggregator_with_evidence())
    raw = {
        "findings": [
            {   # grounded: cites a real endpoint
                "title": "Export endpoint across API versions",
                "interest": "HIGH", "confidence": "MEDIUM", "status": "OBSERVED",
                "category": "API",
                "evidence": ["https://api.example.com/api/v2/export",
                             "https://api.example.com/api/v1/export"],
                "reason": "Export exists in current and historical API versions.",
                "next_action": "apifinder",
            },
            {   # hallucinated: cites nothing in the bundle
                "title": "SQL injection in /totally/made/up",
                "interest": "HIGH", "confidence": "HIGH", "status": "CONFIRMED",
                "category": "OTHER",
                "evidence": ["/totally/made/up?id=1' OR 1=1"],
                "reason": "invented",
            },
        ],
    }
    report = verify(raw, known, {"apifinder", "js_intel"}, "example.com", "test-model")
    titles = [f.title for f in report.findings]
    assert "Export endpoint across API versions" in titles
    assert all("made/up" not in t for t in titles)
    assert report.dropped == 1


def test_verify_drops_recommendation_for_unknown_module():
    _, known = build_evidence(_aggregator_with_evidence())
    raw = {
        "findings": [],
        "recommended_next": [
            {"module": "apifinder", "reason": "parse the API surface", "evidence": []},
            {"module": "definitely_not_a_module", "reason": "x", "evidence": []},
        ],
    }
    report = verify(raw, known, {"apifinder", "js_intel"}, "example.com", "m")
    mods = [n.module for n in report.recommended_next]
    assert mods == ["apifinder"]


def test_verify_url_classification_requires_known_url():
    _, known = build_evidence(_aggregator_with_evidence())
    raw = {"findings": [], "url_classifications": [
        {"url": "https://api.example.com/graphql", "category": "GRAPHQL",
         "confidence": "HIGH", "evidence": ["GraphQL"]},
        {"url": "https://api.example.com/ghost-endpoint", "category": "API",
         "confidence": "HIGH", "evidence": []},
    ]}
    report = verify(raw, known, set(), "example.com", "m")
    urls = [u.url for u in report.url_classifications]
    assert "https://api.example.com/graphql" in urls
    assert "https://api.example.com/ghost-endpoint" not in urls


# ── rendering ──────────────────────────────────────────────────────────────────

def test_render_intelligence_txt_and_summary_sections():
    _, known = build_evidence(_aggregator_with_evidence())
    raw = {"findings": [{
        "title": "Export endpoint across API versions", "interest": "HIGH",
        "confidence": "MEDIUM", "status": "OBSERVED", "category": "API",
        "evidence": ["https://api.example.com/api/v2/export"],
        "reason": "current + historical", "next_action": "apifinder",
    }], "recommended_next": [
        {"module": "apifinder", "reason": "parse API spec", "evidence": []}]}
    report = verify(raw, known, {"apifinder"}, "example.com", "m")

    txt = "\n".join(render_intelligence_txt(report))
    assert "INTERESTING FINDINGS" in txt
    assert "Export endpoint across API versions" in txt
    assert "RECOMMENDED NEXT RECON" in txt

    summ = "\n".join(render_summary_sections(report))
    assert "Interesting Findings" in summ
    assert "Recommended Next Recon" in summ
    assert "apifinder" in summ


# ── analyst orchestration with a mocked LLM ───────────────────────────────────

async def test_analyst_analyze_verifies_mocked_output():
    agg = _aggregator_with_evidence()
    fake_raw = {
        "findings": [{
            "title": "GraphQL present alongside REST export",
            "interest": "MEDIUM", "confidence": "MEDIUM", "status": "OBSERVED",
            "category": "GRAPHQL",
            "evidence": ["https://api.example.com/graphql",
                         "https://api.example.com/api/v2/export"],
            "reason": "Both a GraphQL endpoint and a REST export endpoint exist.",
            "next_action": "apifinder",
        }],
        "recommended_next": [{"module": "js_intel", "reason": "mine JS", "evidence": []}],
        "overall_notes": "Small API surface.",
    }
    with patch("ai.assessor.Assessor.call", new=AsyncMock(return_value=fake_raw)):
        analyst = IntelligenceAnalyst(api_key="test-key", model="test-model",
                                      allowed_modules=["apifinder", "js_intel"])
        report = await analyst.analyze(agg, target="example.com")

    assert not report.is_empty
    assert report.findings[0].category == "GRAPHQL"
    assert report.recommended_next[0].module == "js_intel"
