"""Normalize parser unit tests — pure functions, no I/O needed."""

from normalize.parsers import parse_subfinder_line, parse_dnsx_line, parse_httpx_json


# ── parse_subfinder_line ───────────────────────────────────────────────────────

def test_subfinder_normal_line():
    d = parse_subfinder_line("api.example.com\n")
    assert d is not None
    assert d.hostname == "api.example.com"
    assert d.source == "subfinder"


def test_subfinder_normalizes_case():
    d = parse_subfinder_line("API.Example.COM")
    assert d is not None
    assert d.hostname == "api.example.com"


def test_subfinder_empty_line_returns_none():
    assert parse_subfinder_line("") is None
    assert parse_subfinder_line("   \n") is None


def test_subfinder_strips_control_chars_via_pydantic():
    d = parse_subfinder_line("api.example.com\x00")
    assert d is not None
    assert "\x00" not in d.hostname


# ── parse_dnsx_line ────────────────────────────────────────────────────────────

def test_dnsx_a_record_returns_ip_data():
    result = parse_dnsx_line("api.example.com [A] 93.184.216.34", "api.example.com")
    assert result is not None
    dns, ip = result
    assert dns.record_type == "A"
    assert dns.value == "93.184.216.34"
    assert ip is not None
    assert ip.address == "93.184.216.34"
    assert ip.resolved_from == "api.example.com"


def test_dnsx_aaaa_record_returns_ip_data():
    result = parse_dnsx_line("api.example.com [AAAA] 2606:2800::1", "api.example.com")
    assert result is not None
    _, ip = result
    assert ip is not None
    assert ip.address == "2606:2800::1"


def test_dnsx_cname_does_not_return_ip():
    result = parse_dnsx_line("www.example.com [CNAME] example.com", "www.example.com")
    assert result is not None
    dns, ip = result
    assert dns.record_type == "CNAME"
    assert ip is None


def test_dnsx_short_line_returns_none():
    assert parse_dnsx_line("api.example.com", "api.example.com") is None
    assert parse_dnsx_line("", "example.com") is None


# ── parse_httpx_json ───────────────────────────────────────────────────────────

def test_httpx_normal_json():
    line = '{"url":"https://api.example.com/","status-code":200,"title":"Home","webserver":"nginx"}'
    d = parse_httpx_json(line)
    assert d is not None
    assert d.url == "https://api.example.com/"
    assert d.status_code == 200
    assert d.title == "Home"
    assert d.server == "nginx"


def test_httpx_missing_status_returns_none():
    line = '{"url":"https://api.example.com/"}'
    assert parse_httpx_json(line) is None


def test_httpx_empty_line_returns_none():
    assert parse_httpx_json("") is None
    assert parse_httpx_json("   ") is None


def test_httpx_invalid_json_returns_none():
    assert parse_httpx_json("not json at all") is None


def test_httpx_fallback_host_used_when_no_url():
    line = '{"status-code":200}'
    d = parse_httpx_json(line, fallback_host="10.0.0.1")
    assert d is not None
    assert "10.0.0.1" in d.url


def test_httpx_title_sanitized():
    title = "A" * 300
    line = f'{{"url":"https://x.com/","status-code":200,"title":"{title}"}}'
    d = parse_httpx_json(line)
    assert d is not None
    assert len(d.title) <= 256
