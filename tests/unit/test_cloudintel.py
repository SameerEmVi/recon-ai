"""
Tests for the Cloud Asset Intelligence engine (recon.cloudintel):
representative fingerprints across AWS/Azure/GCP/Firebase/CDN and the
evidence-correlation / confidence model.
"""

from __future__ import annotations

import pytest

from recon import cloudintel as C


# ── hostname / CNAME fingerprints ──────────────────────────────────────────────

@pytest.mark.parametrize("host,provider,service,kind", [
    ("my-bucket.s3.amazonaws.com", "AWS", "S3", C.STORAGE),
    ("d123abc.cloudfront.net", "AWS", "CloudFront", C.CDN),
    ("prod-alb-123.us-east-1.elb.amazonaws.com", "AWS", "Elastic Load Balancer", C.LB),
    ("abc123.execute-api.us-east-1.amazonaws.com", "AWS", "API Gateway", C.API),
    ("assets.blob.core.windows.net", "Azure", "Blob Storage", C.STORAGE),
    ("myapp.azurewebsites.net", "Azure", "App Service", C.COMPUTE),
    ("cdn.azureedge.net", "Azure", "CDN", C.CDN),
    ("data.storage.googleapis.com", "GCP", "Cloud Storage", C.STORAGE),
    ("svc-xyz.run.app", "GCP", "Cloud Run", C.COMPUTE),
    ("myproject.appspot.com", "GCP", "App Engine", C.COMPUTE),
    ("myapp.firebaseio.com", "Firebase", "Realtime Database", C.DATABASE),
    ("site.web.app", "Firebase", "Hosting", C.COMPUTE),
    ("x.fastly.net", "Fastly", "CDN", C.CDN),
    ("y.akamaiedge.net", "Akamai", "CDN", C.CDN),
])
def test_hostname_fingerprints(host, provider, service, kind):
    sigs = C.classify_hostname(host)
    match = [s for s in sigs if s.provider == provider and s.service == service]
    assert match, f"expected {provider}/{service} for {host}, got {[(s.provider, s.service) for s in sigs]}"
    assert match[0].kind == kind
    assert match[0].weight >= C.W_MEDIUM


def test_unrelated_hostname_no_signal():
    assert C.classify_hostname("www.example.com") == []
    assert C.classify_hostname("") == []


# ── header fingerprints ────────────────────────────────────────────────────────

def test_header_fingerprint_s3():
    sigs = C.classify_headers({"x-amz-request-id": "abc", "server": "AmazonS3"})
    provs = {(s.provider, s.service) for s in sigs}
    assert ("AWS", "S3") in provs


def test_header_fingerprint_gcs_prefix():
    sigs = C.classify_headers({"x-goog-generation": "1", "x-guploader-uploadid": "z"})
    assert any(s.provider == "GCP" for s in sigs)


def test_header_fingerprint_server_string():
    sigs = C.classify_headers(None, server="cloudflare")
    assert any(s.provider == "Cloudflare" for s in sigs)


def test_header_bad_input_safe():
    assert C.classify_headers(object()) == []          # non-mapping → no crash


# ── technology fingerprints ────────────────────────────────────────────────────

@pytest.mark.parametrize("name,provider", [
    ("Amazon S3", "AWS"),
    ("Amazon CloudFront", "AWS"),
    ("Cloudflare", "Cloudflare"),
    ("Fastly", "Fastly"),
    ("Firebase", "Firebase"),
    ("Microsoft Azure", "Azure"),
    ("Google Cloud", "GCP"),
])
def test_technology_fingerprints(name, provider):
    sigs = C.classify_technology(name)
    assert sigs and sigs[0].provider == provider


def test_url_fingerprint():
    sigs = C.classify_url("https://cdn.b-cdn.net/app.js")
    assert any(s.provider == "BunnyCDN" for s in sigs)


# ── correlation / confidence (noisy-OR of independent evidence) ───────────────

def test_correlation_combines_evidence_and_raises_confidence():
    corr = C.CloudCorrelator()
    host = "www.example.com"
    # Evidence 1: CNAME to CloudFront (DNS). Evidence 2: server header. Evidence 3: tech.
    corr.add(host, C.classify_hostname("d123.cloudfront.net", source="dns"))
    c1 = corr.assets()[0].confidence
    corr.add(host, C.classify_headers(None, server="cloudfront"))
    corr.add(host, C.classify_technology("Amazon CloudFront"))

    assets = corr.assets()
    asset = [a for a in assets if a.service == "CloudFront"][0]
    assert asset.confidence > c1                  # corroboration raised confidence
    assert asset.confidence <= 1.0                # never exceeds 1
    assert {"dns", "http", "technology"} <= asset.sources   # provenance tracked
    assert len(asset.evidence) >= 2               # evidence retained


def test_correlation_dedups_assets_per_host_provider_service():
    corr = C.CloudCorrelator()
    host = "b.example.com"
    # same S3 evidence twice
    corr.add(host, C.classify_hostname("x.s3.amazonaws.com", source="dns"))
    corr.add(host, C.classify_hostname("x.s3.amazonaws.com", source="dns"))
    s3 = [a for a in corr.assets() if a.service == "S3"]
    assert len(s3) == 1                            # one asset, not two


def test_min_confidence_filter():
    corr = C.CloudCorrelator()
    corr.add("c.example.com", C.classify_hostname("x.googleusercontent.com"))  # W_LOW
    assert corr.assets(min_confidence=0.5) == []   # weak lone signal filtered
    assert corr.assets(min_confidence=0.0)         # present at 0 threshold


# ── active-verification helper (pure) ─────────────────────────────────────────

def test_public_bucket_listing_detection():
    assert C.looks_like_public_bucket_listing('<?xml version="1.0"?><ListBucketResult>')
    assert C.looks_like_public_bucket_listing("<Error><Code>AccessDenied</Code>")
    assert not C.looks_like_public_bucket_listing("<html>hello</html>")
    assert not C.looks_like_public_bucket_listing("")
