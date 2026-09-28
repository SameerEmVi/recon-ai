"""
Tests for the Central Result Aggregator (output.aggregator.ResultAggregator):
cross-source deduplication, normalization, categorization, provenance retention,
and the results/<domain>/{latest,scans/<ts>,diff} directory layout.
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

from events.types import (
    DnsRecordData,
    EndpointData,
    Event,
    EventType,
    FindingCandidateData,
    HttpServiceData,
    IpData,
    OpenPortData,
    ParameterData,
    SubdomainData,
    TechnologyData,
    UrlData,
)
from output.aggregator import ResultAggregator, classify_api

SCAN = uuid.uuid4()


def ev(t, data, tool):
    e = Event.create(t, data, scan_job_id=SCAN, source_tool=tool)
    return e


def _agg_with_multisource():
    a = ResultAggregator(out_dir="unused")
    # Same subdomain discovered by THREE different modules → must dedup to one.
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="subfinder"), "subfinder"))
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="crt_sh"), "crt_sh"))
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="API.example.com", source="hackertarget"), "hackertarget"))
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="www.example.com", source="subfinder"), "subfinder"))
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="admin.example.com", source="permutations"), "permutations"))
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="dev.example.com", source="dnsbrute"), "dnsbrute"))
    # DNS → IP correlation
    a.observe(ev(EventType.DNS_RECORD, DnsRecordData(hostname="api.example.com", record_type="A", value="1.2.3.5"), "dnsx"))
    a.observe(ev(EventType.IP, IpData(address="1.2.3.4", resolved_from="example.com"), "dnsx"))
    # ports
    a.observe(ev(EventType.OPEN_PORT, OpenPortData(host="1.2.3.4", port=443, protocol="tcp"), "naabu"))
    a.observe(ev(EventType.OPEN_PORT, OpenPortData(host="1.2.3.4", port=22, protocol="tcp"), "naabu"))
    # live services + tech
    a.observe(ev(EventType.HTTP_SERVICE, HttpServiceData(url="https://example.com", status_code=200, title="Home", server="nginx", technologies=["React", "Cloudflare"]), "httpx_probe"))
    a.observe(ev(EventType.HTTP_SERVICE, HttpServiceData(url="https://admin.example.com/login", status_code=200, title="Sign in to Admin", server="Apache"), "httpx_probe"))
    a.observe(ev(EventType.TECHNOLOGY, TechnologyData(host="example.com", name="nginx", source="fingerprint"), "fingerprint"))
    a.observe(ev(EventType.TECHNOLOGY, TechnologyData(host="example.com", name="WordPress", version="6.1", source="fingerprint"), "fingerprint"))
    # Same URL from FOUR sources → dedup to one
    for tool in ("katana", "wayback", "js_intel", "apifinder"):
        a.observe(ev(EventType.URL, UrlData(url="https://example.com/search?q=x", found_via=tool), tool))
    # endpoints (API + graphql)
    a.observe(ev(EventType.ENDPOINT, EndpointData(url="https://api.example.com/api/v1/users", method="GET"), "apifinder"))
    a.observe(ev(EventType.ENDPOINT, EndpointData(url="https://api.example.com/graphql", method="POST"), "js_intel"))
    # params
    a.observe(ev(EventType.PARAMETER, ParameterData(url="https://example.com/download", name="file", location="query"), "paramfinder"))
    a.observe(ev(EventType.PARAMETER, ParameterData(url="https://example.com/download", name="type", location="query"), "paramfinder"))
    # finding
    a.observe(ev(EventType.FINDING_CANDIDATE, FindingCandidateData(host="example.com", title="Exposed secret", description="key", category="exposed-secret", evidence={}, severity_hint="high"), "secretfinder"))
    return a


# ── dedup / normalization ─────────────────────────────────────────────────────

def test_domains_deduped_across_sources():
    a = _agg_with_multisource()
    assert "api.example.com" in a.domains
    # api.example.com seen 3x (incl. mixed case) → exactly one entry
    assert sorted(a.domains).count("api.example.com") == 1
    # provenance retains all three discovery sources
    srcs = {r["source"] for r in a._provenance if r["value"] == "api.example.com"}
    assert {"subfinder", "crt_sh", "hackertarget"} <= srcs


def test_urls_deduped_across_four_sources():
    a = _agg_with_multisource()
    matches = [u for u in a.urls if u == "https://example.com/search?q=x"]
    assert len(matches) == 1
    prov_sources = {r["source"] for r in a._provenance if "search?q=x" in str(r["value"])}
    assert {"katana", "wayback", "js_intel", "apifinder"} <= prov_sources


# ── categorization ────────────────────────────────────────────────────────────

def test_technologies_grouped_per_host():
    a = _agg_with_multisource()
    lines = a._tech_lines()
    host_line = [l for l in lines if l.startswith("https://example.com\t")][0]
    assert "nginx" in host_line and "WordPress 6.1" in host_line and "React" in host_line


def test_ip_domain_correlation():
    a = _agg_with_multisource()
    lines = a._ip_lines()
    assert any(l.startswith("1.2.3.4\t") and "example.com" in l for l in lines)


def test_ports():
    a = _agg_with_multisource()
    lines = a._port_lines()
    assert "1.2.3.4:443\ttcp" in lines and "1.2.3.4:22\ttcp" in lines


def test_api_endpoints_typed():
    a = _agg_with_multisource()
    rows = a._api_endpoints()
    assert "https://api.example.com/graphql\tGraphQL" in rows
    assert any(r.startswith("https://api.example.com/api/v1/users\t") and "REST" in r for r in rows)


def test_login_pages_by_path_and_title():
    a = _agg_with_multisource()
    logins = a._login_pages()
    # by path (/login) and by title ("Sign in to Admin")
    assert "https://admin.example.com/login" in logins


def test_interesting_sections():
    a = _agg_with_multisource()
    text = "\n".join(a._interesting())
    assert "[LOGIN]" in text and "[ADMIN]" in text and "[API]" in text
    assert "[INTERESTING PARAMETER]" in text
    assert "download?file=" in text                    # interesting param preserved w/ url


def test_classify_api():
    assert classify_api("https://x/graphql") == "GraphQL"
    assert classify_api("https://x/api/v2/y") == "REST"
    assert classify_api("https://x/openapi.json") == "OpenAPI"
    assert classify_api("https://x/about") is None


# ── writing / directory layout ────────────────────────────────────────────────

def test_write_creates_layout_and_files(tmp_path):
    a = _agg_with_multisource()
    a._out_dir = str(tmp_path)
    scan_dir = a.write("example.com")

    base = tmp_path / "example.com"
    assert (base / "latest").is_dir()
    assert (base / "scans").is_dir()
    assert os.path.isdir(scan_dir)

    for f in ("domains.txt", "live.txt", "urls.txt", "technologies.txt", "ips.txt",
              "ports.txt", "endpoints.txt", "parameters.txt", "api-endpoints.txt",
              "login-pages.txt", "interesting.txt", "summary.txt", "provenance.jsonl"):
        assert (base / "latest" / f).is_file(), f"missing {f}"

    domains = (base / "latest" / "domains.txt").read_text().split()
    assert domains == sorted(set(domains))             # sorted + deduped
    assert "api.example.com" in domains

    summary = (base / "latest" / "summary.txt").read_text()
    assert "Target: example.com" in summary
    assert "Subdomains:" in summary and "Sources:" in summary

    prov = (base / "latest" / "provenance.jsonl").read_text().strip().splitlines()
    assert all(json.loads(l)["type"] for l in prov)    # provenance retained


def test_second_scan_keeps_history_and_diffs(tmp_path):
    a1 = _agg_with_multisource()
    a1._out_dir = str(tmp_path)
    a1.write("example.com")

    a2 = ResultAggregator(out_dir=str(tmp_path))
    a2.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="new.example.com", source="subfinder"), "subfinder"))
    a2.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="api.example.com", source="subfinder"), "subfinder"))
    a2.write("example.com")

    base = tmp_path / "example.com"
    scans = list((base / "scans").iterdir())
    assert len(scans) == 2                              # history preserved
    diffs = list((base / "diff").glob("*.txt"))
    assert diffs, "expected a diff file for the second scan"
    diff_text = diffs[0].read_text()
    assert "new.example.com" in diff_text               # new domain flagged
    # latest reflects the most recent scan
    latest_domains = (base / "latest" / "domains.txt").read_text()
    assert "new.example.com" in latest_domains


# ── extended layout: dns / files / secrets / data-exposure / subdirs ──────────

def _rich():
    from events.types import AnomalyData
    a = ResultAggregator(out_dir="unused")
    a.observe(ev(EventType.SUBDOMAIN, SubdomainData(hostname="intranet.example.com", source="crt_sh"), "crt_sh"))
    a.observe(ev(EventType.DNS_RECORD, DnsRecordData(hostname="example.com", record_type="MX", value="mail.example.com"), "dnsx"))
    a.observe(ev(EventType.DNS_RECORD, DnsRecordData(hostname="example.com", record_type="TXT", value="contact ops@example.com for info"), "dnsx"))
    a.observe(ev(EventType.URL, UrlData(url="https://example.com/reports/q3.pdf", found_via="wayback"), "wayback"))
    a.observe(ev(EventType.URL, UrlData(url="https://example.com/config.json", found_via="katana"), "katana"))
    a.observe(ev(EventType.URL, UrlData(url="https://example.com/app.js", found_via="js_intel"), "js_intel"))
    a.observe(ev(EventType.ENDPOINT, EndpointData(url="https://api.example.com/api/v1/login", method="POST"), "js_intel"))
    a.observe(ev(EventType.ANOMALY, AnomalyData(host="example.com", description="metadata in q3.pdf: author=jsmith; creator=Microsoft Word", category="document-metadata"), "metascan"))
    a.observe(ev(EventType.ANOMALY, AnomalyData(host="example.com", description="source map referenced: https://example.com/app.js.map", category="exposed-source-map"), "js_intel"))
    a.observe(ev(EventType.FINDING_CANDIDATE, FindingCandidateData(host="example.com", title="Exposed secret: AWS Access Key", description="in app.js", category="exposed-secret", evidence={"value": "AKIA...REDACTED", "line": "184"}, severity_hint="high"), "secretfinder"))
    return a


def test_dns_and_files_and_internal():
    a = _rich()
    assert any("MX\tmail.example.com" in l for l in a._dns_lines())
    assert "https://example.com/reports/q3.pdf" in a._files()
    assert "https://example.com/config.json" in a._files()
    assert "ops@example.com" in a.emails            # extracted from TXT (data, not instruction)
    de = a._data_exposure()
    assert "intranet.example.com" in de["internal-hostnames.txt"]
    assert "jsmith" in de["usernames.txt"]           # from document metadata
    assert "https://example.com/app.js.map" in de["source-maps.txt"]
    assert "https://example.com/config.json" in de["configuration.txt"]


def test_secret_findings_redacted_only():
    a = _rich()
    txt, js = a._secrets()
    joined = "\n".join(txt)
    assert "AWS Access Key" in joined and "REDACTED" in joined
    assert js[0]["type"] == "exposed-secret" and js[0]["confidence"] == "high"
    # aggregator stores only what secretfinder already redacted — no full secret synthesized
    assert "AKIA...REDACTED" in js[0]["evidence_redacted"]["value"]


def test_source_aware_subfiles():
    a = _rich()
    assert "https://example.com/reports/q3.pdf" in a._urls_by_source("wayback")
    assert "https://example.com/config.json" not in a._urls_by_source("wayback")
    assert "https://api.example.com/api/v1/login" in a._js_endpoints()


def test_full_tree_written(tmp_path):
    a = _rich(); a._out_dir = str(tmp_path)
    a.write("example.com")
    latest = tmp_path / "example.com" / "latest"
    for rel in ("dns.txt", "files.txt", "interesting-parameters.txt", "domain-sources.json",
                "javascript/js-files.txt", "javascript/sourcemaps.txt",
                "wayback/urls.txt", "secrets/findings.txt", "secrets/findings.json",
                "file-analysis/metadata.txt", "images/images.txt", "images/ocr.txt",
                "data-exposure/summary.txt", "data-exposure/usernames.txt",
                "data-exposure/emails.txt", "data-exposure/source-maps.txt"):
        assert (latest / rel).is_file(), f"missing {rel}"
    import json as _j
    ds = _j.loads((latest / "domain-sources.json").read_text())
    assert "intranet.example.com" in ds and "crt_sh" in ds["intranet.example.com"]
