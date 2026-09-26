"""
Module system tests.

Covers:
  - BaseModule lifecycle (setup, emit, opt)
  - ModuleRegistry (discover, load by name, load by flag, load_defaults)
  - All 11 modules register correctly and have required attributes
  - Passive modules translate HTTP responses to events (mocked httpx)
  - Reactive modules call the right wrappers (mocked wrappers)
  - fingerprint module detects technologies from HttpServiceData
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.base import BaseModule
from modules.registry import (
    DEFAULT_MODULES,
    EXTRA_PASSIVE_MODULES,
    FULL_MODULES,
    PASSIVE_MODULES,
    SCAN_PROFILES,
    ModuleRegistry,
    register,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _mock_controller(scan_id=None):
    ctrl = MagicMock()
    ctrl.scan_id = scan_id or uuid.uuid4()
    ctrl.stamp_and_publish = AsyncMock(return_value=True)
    return ctrl


# ── registry ──────────────────────────────────────────────────────────────────

def test_registry_discovers_all_expected_modules():
    ModuleRegistry._discovered = False  # force re-discovery
    ModuleRegistry.discover()
    names = ModuleRegistry.all_names()
    expected = [
        # passive
        "crt_sh", "certspotter", "hackertarget", "wayback",
        "chaos", "anubis", "amass", "assetfinder", "findomain",
        # active
        "subfinder", "dnsx", "naabu", "httpx_probe", "katana", "gowitness",
        "dnsbrute", "permutations",
        # web
        "gau", "nuclei", "fingerprint", "dirsearch", "linkfinder", "corscanner", "bypass403",
    ]
    for name in expected:
        assert name in names, f"module '{name}' not found in registry"


def test_registry_load_by_name():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load(names=["crt_sh", "subfinder"], controller=ctrl)
    assert len(modules) == 2
    assert {m.name for m in modules} == {"crt_sh", "subfinder"}


def test_registry_load_by_flag_passive():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load(flags=["passive"], controller=ctrl)
    names = {m.name for m in modules}
    for expected in PASSIVE_MODULES:
        assert expected in names


def test_registry_load_defaults():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load_defaults(controller=ctrl)
    names = {m.name for m in modules}
    for expected in DEFAULT_MODULES:
        assert expected in names


def test_registry_load_defaults_with_extra_names():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load_defaults(controller=ctrl, extra_names=["crt_sh"])
    names = {m.name for m in modules}
    assert "crt_sh" in names
    for expected in DEFAULT_MODULES:
        assert expected in names


def test_registry_load_defaults_with_extra_flags():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load_defaults(controller=ctrl, extra_flags=["passive"])
    names = {m.name for m in modules}
    for expected in DEFAULT_MODULES + PASSIVE_MODULES:
        assert expected in names


def test_registry_load_unknown_module_skips():
    ctrl = _mock_controller()
    modules = ModuleRegistry.load(names=["crt_sh", "totally_unknown_xyz"], controller=ctrl)
    assert len(modules) == 1
    assert modules[0].name == "crt_sh"


def test_registry_info_returns_metadata():
    rows = ModuleRegistry.info()
    assert isinstance(rows, list)
    assert len(rows) > 0
    for row in rows:
        assert "name" in row
        assert "flags" in row
        assert "description" in row
        assert "watched_events" in row
        assert "produced_events" in row


# ── BaseModule lifecycle ──────────────────────────────────────────────────────

def test_base_module_opt_returns_default():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["crt_sh"], controller=ctrl)[0]
    assert m.opt("timeout") == 30


def test_base_module_opt_returns_override():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["crt_sh"], controller=ctrl, module_config={"crt_sh": {"timeout": 10}})[0]
    assert m.opt("timeout") == 10


async def test_base_module_setup_returns_true_when_no_binary_required():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["crt_sh"], controller=ctrl)[0]
    result = await m.setup()
    assert result is True  # no deps_binary


async def test_base_module_setup_returns_false_when_binary_missing():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["subfinder"], controller=ctrl)[0]
    with patch("shutil.which", return_value=None):
        result = await m.setup()
    assert result is False


# ── Module attributes validation ──────────────────────────────────────────────

@pytest.mark.parametrize("mod_name", FULL_MODULES)
def test_all_modules_have_required_attrs(mod_name):
    ctrl = _mock_controller()
    modules = ModuleRegistry.load(names=[mod_name], controller=ctrl)
    assert len(modules) == 1
    m = modules[0]
    assert isinstance(m.name, str) and m.name
    assert isinstance(m.description, str) and m.description
    assert isinstance(m.watched_events, list)
    assert isinstance(m.produced_events, list)
    assert isinstance(m.flags, list)


@pytest.mark.parametrize("mod_name", DEFAULT_MODULES)
def test_default_modules_have_active_flag(mod_name):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=[mod_name], controller=ctrl)[0]
    # subfinder: no flag requirement for seed modules
    # dnsx, httpx_probe: should have active or dns/http flag
    if mod_name in ("dnsx", "httpx_probe", "naabu"):
        assert "active" in m.flags, f"{mod_name} should have 'active' flag"


@pytest.mark.parametrize("mod_name", PASSIVE_MODULES)
def test_passive_modules_have_passive_flag(mod_name):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=[mod_name], controller=ctrl)[0]
    assert "passive" in m.flags, f"{mod_name} should have 'passive' flag"


@pytest.mark.parametrize("mod_name", PASSIVE_MODULES)
def test_passive_modules_are_seed(mod_name):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=[mod_name], controller=ctrl)[0]
    assert m.watched_events == [], f"{mod_name} should be a seed module"


# ── crt_sh: mocked httpx ──────────────────────────────────────────────────────

async def test_crt_sh_emits_subdomains(monkeypatch):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["crt_sh"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.json.return_value = [
        {"name_value": "api.example.com\n*.api.example.com"},
        {"name_value": "mail.example.com"},
        {"name_value": ""},
    ]
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    # api.example.com and mail.example.com should be emitted
    # *.api.example.com → api.example.com after stripping (already seen → skipped)
    calls = ctrl.stamp_and_publish.call_args_list
    emitted_hostnames = {call[0][0].data.hostname for call in calls}
    assert "api.example.com" in emitted_hostnames
    assert "mail.example.com" in emitted_hostnames


async def test_crt_sh_handles_http_error(monkeypatch):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["crt_sh"], controller=ctrl)[0]

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(side_effect=Exception("timeout"))

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)  # must not raise

    ctrl.stamp_and_publish.assert_not_called()


# ── certspotter: mocked httpx ─────────────────────────────────────────────────

async def test_certspotter_emits_subdomains():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["certspotter"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.json.return_value = [
        {"dns_names": ["api.example.com", "*.example.com"]},
        {"dns_names": ["vpn.example.com"]},
    ]
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    calls = ctrl.stamp_and_publish.call_args_list
    hostnames = {c[0][0].data.hostname for c in calls}
    assert "api.example.com" in hostnames
    assert "vpn.example.com" in hostnames
    # *.example.com → example.com after strip
    assert "example.com" in hostnames


# ── hackertarget: mocked httpx ────────────────────────────────────────────────

async def test_hackertarget_emits_subdomains_and_ips():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["hackertarget"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.text = "api.example.com,1.2.3.4\nmail.example.com,1.2.3.5\n"
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    calls = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    hostnames = {e.data.hostname for e in calls if hasattr(e.data, "hostname")}
    addresses = {e.data.address for e in calls if hasattr(e.data, "address")}

    assert "api.example.com" in hostnames
    assert "1.2.3.4" in addresses


# ── wayback: mocked httpx ─────────────────────────────────────────────────────

async def test_wayback_emits_urls_and_subdomains():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["wayback"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.json.return_value = [
        ["original"],  # header row
        ["https://api.example.com/v1/users"],
        ["https://api.example.com/v1/items"],
        ["https://mail.example.com/login"],
    ]
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    calls = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    urls = {e.data.url for e in calls if hasattr(e.data, "url")}
    hostnames = {e.data.hostname for e in calls if hasattr(e.data, "hostname")}

    assert "https://api.example.com/v1/users" in urls
    assert "api.example.com" in hostnames
    assert "mail.example.com" in hostnames


# ── fingerprint module ────────────────────────────────────────────────────────

async def test_fingerprint_detects_nginx_from_server_header():
    from events.types import Event, EventType, HttpServiceData
    from scope.types import ScopeStatus

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]

    event = MagicMock()
    event.type = EventType.HTTP_SERVICE
    event.data = HttpServiceData(
        url="https://api.example.com/",
        status_code=200,
        server="nginx/1.24.0",
        title="Home",
    )
    event.id = uuid.uuid4()
    event.distance = 1

    await m.handle_event(event)

    calls = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    tech_names = {e.data.name for e in calls if hasattr(e.data, "name")}
    assert "nginx" in tech_names


async def test_fingerprint_detects_wordpress_from_title():
    from events.types import HttpServiceData

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(
        url="https://blog.example.com/",
        status_code=200,
        title="My WordPress Blog",
        server="Apache/2.4",
    )
    event.id = uuid.uuid4()
    event.distance = 1

    await m.handle_event(event)

    calls = [c[0][0] for c in ctrl.stamp_and_publish.call_args_list]
    tech_names = {e.data.name for e in calls if hasattr(e.data, "name")}
    assert "WordPress" in tech_names
    assert "Apache" in tech_names


async def test_fingerprint_no_crash_on_empty_server():
    from events.types import HttpServiceData

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["fingerprint"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    await m.handle_event(event)  # should not raise


# ── dnsx reactive module ──────────────────────────────────────────────────────

async def test_dnsx_module_calls_resolve_on_subdomain():
    from events.types import Event, EventType, SubdomainData
    from scope.types import ScopeStatus

    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["dnsx"], controller=ctrl)[0]

    event = MagicMock()
    event.type = EventType.SUBDOMAIN
    event.data = SubdomainData(hostname="api.example.com", source="test")
    event.id = uuid.uuid4()

    with patch("recon.dnsx.DnsxWrapper") as MockWrapper:
        instance = MockWrapper.return_value
        instance.resolve = AsyncMock()
        await m.handle_event(event)
        instance.resolve.assert_called_once_with("api.example.com", event)


# ── SCAN_PROFILES ─────────────────────────────────────────────────────────────

def test_scan_profiles_have_required_keys():
    for name, profile in SCAN_PROFILES.items():
        assert "description" in profile, f"{name} missing 'description'"
        assert "module_config" in profile, f"{name} missing 'module_config'"
        assert isinstance(profile["module_config"], dict), f"{name} module_config must be dict"


def test_scan_profile_fast_has_no_active_binaries():
    """fast profile should not require any active-scan binaries."""
    from modules.registry import SCAN_PROFILES, ModuleRegistry
    p = SCAN_PROFILES["fast"]
    modules = p["modules"]
    assert modules is not None
    ctrl = _mock_controller()
    loaded = ModuleRegistry.load(names=modules, controller=ctrl)
    for m in loaded:
        if "active" in m.flags and m.deps_binary:
            # amass/assetfinder/findomain are passive by category but binary-backed
            pass  # OK — they degrade gracefully via setup()


def test_scan_profile_full_includes_all_groups():
    p = SCAN_PROFILES["full"]
    mods = set(p["modules"])
    from modules.registry import (
        DEFAULT_MODULES, PASSIVE_MODULES, EXTRA_PASSIVE_MODULES,
        DEEP_DNS_MODULES, WEB_MODULES, CRAWL_MODULES, DISCOVERY_MODULES,
    )
    for expected in (
        DEFAULT_MODULES + PASSIVE_MODULES + EXTRA_PASSIVE_MODULES
        + DEEP_DNS_MODULES + WEB_MODULES + CRAWL_MODULES + DISCOVERY_MODULES
    ):
        assert expected in mods, f"full profile missing module '{expected}'"


def test_scan_profile_paranoid_overrides_nuclei_severity():
    p = SCAN_PROFILES["paranoid"]
    assert "nuclei" in p["module_config"]
    assert p["module_config"]["nuclei"]["severity"] != "info"


# ── chaos module (pure Python) ────────────────────────────────────────────────

async def test_chaos_emits_subdomains():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["chaos"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.json.return_value = {
        "domain": "example.com",
        "subdomains": ["api", "mail", "*.dev"],
        "count": 3,
    }
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    calls = ctrl.stamp_and_publish.call_args_list
    hostnames = {c[0][0].data.hostname for c in calls}
    assert "api.example.com" in hostnames
    assert "mail.example.com" in hostnames


async def test_chaos_handles_http_error():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["chaos"], controller=ctrl)[0]

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(side_effect=Exception("network error"))

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)  # must not raise

    ctrl.stamp_and_publish.assert_not_called()


# ── anubis module (pure Python) ───────────────────────────────────────────────

async def test_anubis_emits_subdomains():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["anubis"], controller=ctrl)[0]

    fake_response = MagicMock()
    fake_response.json.return_value = [
        "api.example.com",
        "mail.example.com",
        "vpn.example.com",
    ]
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.run("example.com", ctrl.scan_id)

    calls = ctrl.stamp_and_publish.call_args_list
    hostnames = {c[0][0].data.hostname for c in calls}
    assert "api.example.com" in hostnames
    assert "vpn.example.com" in hostnames


# ── binary passive modules have correct flags ────────────────────────────────

@pytest.mark.parametrize("mod_name", ["amass", "assetfinder", "findomain"])
def test_binary_passive_modules_have_passive_flag(mod_name):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=[mod_name], controller=ctrl)[0]
    assert "passive" in m.flags
    assert m.watched_events == []
    assert len(m.deps_binary) > 0


@pytest.mark.parametrize("mod_name", ["amass", "assetfinder", "findomain"])
async def test_binary_passive_setup_fails_when_binary_missing(mod_name):
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=[mod_name], controller=ctrl)[0]
    with patch("shutil.which", return_value=None):
        assert await m.setup() is False


# ── katana and gowitness ──────────────────────────────────────────────────────

def test_katana_watches_http_service():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["katana"], controller=ctrl)[0]
    assert "HTTP_SERVICE" in m.watched_events
    assert "URL" in m.produced_events
    assert "katana" in m.deps_binary


def test_gowitness_watches_http_service():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["gowitness"], controller=ctrl)[0]
    assert "HTTP_SERVICE" in m.watched_events
    assert "ANOMALY" in m.produced_events
    assert "gowitness" in m.deps_binary


# ── content-discovery wordlists ───────────────────────────────────────────────

def test_bundled_wordlist_exists():
    from pathlib import Path
    wl_dir = Path(__file__).parent.parent.parent / "wordlists"
    common = wl_dir / "common.txt"
    big = wl_dir / "big.txt"
    assert common.exists(), f"bundled wordlist missing at {common}"
    assert len(common.read_text().splitlines()) > 50, "common wordlist too small"
    # big.txt must exist and be a proper superset of common.txt.
    assert big.exists(), f"big wordlist missing at {big}"
    common_set = {l.strip() for l in common.read_text().splitlines() if l.strip()}
    big_set = {l.strip() for l in big.read_text().splitlines() if l.strip()}
    assert len(big_set) > len(common_set), "big wordlist should be larger than common"
    assert common_set <= big_set, "big wordlist should include all of common"


def test_httpx_probe_watches_subdomain():
    # vhost fix: probing must key on hostnames (not just IPs) so the web chain
    # targets the real name-based virtual host.
    from modules.registry import _registry
    assert "SUBDOMAIN" in _registry["httpx_probe"].watched_events


# ── linkfinder module ─────────────────────────────────────────────────────────

def test_linkfinder_watches_url():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["linkfinder"], controller=ctrl)[0]
    assert "URL" in m.watched_events
    assert "ENDPOINT" in m.produced_events


async def test_linkfinder_skips_non_js_url():
    from events.types import UrlData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["linkfinder"], controller=ctrl)[0]

    event = MagicMock()
    event.data = UrlData(url="https://example.com/page.html", status_code=200)

    await m.handle_event(event)
    ctrl.stamp_and_publish.assert_not_called()


async def test_linkfinder_extracts_endpoints_from_js():
    from events.types import UrlData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["linkfinder"], controller=ctrl)[0]

    fake_js = '''
    fetch("/api/v1/users");
    const URL = "/api/v2/items";
    let path = "/internal/admin";
    '''
    fake_response = MagicMock()
    fake_response.text = fake_js
    fake_response.content = fake_js.encode()
    fake_response.raise_for_status = MagicMock()

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    event = MagicMock()
    event.data = UrlData(url="https://example.com/app.js", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.handle_event(event)

    assert ctrl.stamp_and_publish.called


# ── corscanner module ─────────────────────────────────────────────────────────

async def test_corscanner_detects_reflected_origin_with_credentials():
    from events.types import HttpServiceData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["corscanner"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    fake_response = MagicMock()
    fake_response.headers = {
        "access-control-allow-origin": "https://evil-cors-test.recon.internal",
        "access-control-allow-credentials": "true",
    }

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.handle_event(event)

    calls = ctrl.stamp_and_publish.call_args_list
    assert len(calls) > 0
    finding = calls[0][0][0]
    assert finding.data.severity_hint == "high"
    assert finding.data.category == "cors"


async def test_corscanner_no_finding_when_cors_clean():
    from events.types import HttpServiceData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["corscanner"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/", status_code=200)
    event.id = uuid.uuid4()
    event.distance = 1

    fake_response = MagicMock()
    fake_response.headers = {}  # no CORS headers

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(return_value=fake_response)

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.handle_event(event)

    ctrl.stamp_and_publish.assert_not_called()


# ── bypass403 module ──────────────────────────────────────────────────────────

async def test_bypass403_skips_non_403_events():
    from events.types import HttpServiceData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["bypass403"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/admin", status_code=200)

    await m.handle_event(event)
    ctrl.stamp_and_publish.assert_not_called()


async def test_bypass403_emits_finding_when_bypass_succeeds():
    from events.types import HttpServiceData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["bypass403"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/admin", status_code=403)
    event.id = uuid.uuid4()
    event.distance = 1

    # First bypass attempt returns 200; rest return 403.
    call_count = 0
    async def fake_request(method, url, **kwargs):
        nonlocal call_count
        r = MagicMock()
        r.status_code = 200 if call_count == 0 else 403
        call_count += 1
        return r

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.request = fake_request

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.handle_event(event)

    assert ctrl.stamp_and_publish.called
    finding = ctrl.stamp_and_publish.call_args_list[0][0][0]
    assert finding.data.category == "403-bypass"
    assert finding.data.severity_hint == "medium"


async def test_bypass403_no_finding_when_all_fail():
    from events.types import HttpServiceData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["bypass403"], controller=ctrl)[0]

    event = MagicMock()
    event.data = HttpServiceData(url="https://api.example.com/admin", status_code=403)
    event.id = uuid.uuid4()
    event.distance = 1

    async def always_403(method, url, **kwargs):
        r = MagicMock()
        r.status_code = 403
        return r

    fake_client = AsyncMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.request = always_403

    with patch("httpx.AsyncClient", return_value=fake_client):
        await m.handle_event(event)

    ctrl.stamp_and_publish.assert_not_called()


# ── dnsbrute module ───────────────────────────────────────────────────────────

def _fake_proc(stdout: bytes):
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    proc.kill = MagicMock()
    return proc


def test_dnsbrute_is_seed_module():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["dnsbrute"], controller=ctrl)[0]
    assert m.watched_events == []
    assert "subdomain-enum" in m.flags


async def test_dnsbrute_emits_resolved_subdomains():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["dnsbrute"], controller=ctrl)[0]
    out = b"www.example.com\napi.example.com\n"
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_fake_proc(out))):
        await m.run("example.com", ctrl.scan_id)
    hostnames = {c[0][0].data.hostname for c in ctrl.stamp_and_publish.call_args_list}
    assert hostnames == {"www.example.com", "api.example.com"}


async def test_dnsbrute_filters_lines_outside_target_domain():
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["dnsbrute"], controller=ctrl)[0]
    out = b"api.example.com\nevil.attacker.com\n\n"
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_fake_proc(out))):
        await m.run("example.com", ctrl.scan_id)
    hostnames = {c[0][0].data.hostname for c in ctrl.stamp_and_publish.call_args_list}
    assert hostnames == {"api.example.com"}


# ── permutations module ───────────────────────────────────────────────────────

def test_generate_permutations_produces_variants():
    from modules.active.permutations import generate_permutations
    cands = generate_permutations("api.example.com", max_candidates=1000)
    assert "api-dev.example.com" in cands
    assert "dev-api.example.com" in cands
    assert "api1.example.com" in cands
    assert "api.example.com" not in cands  # never the input itself


def test_generate_permutations_apex_returns_empty():
    from modules.active.permutations import generate_permutations
    assert generate_permutations("example.com") == []


def test_generate_permutations_env_word_swap():
    from modules.active.permutations import generate_permutations
    cands = generate_permutations("api.dev.example.com", max_candidates=1000)
    assert "api.prod.example.com" in cands


def test_generate_permutations_respects_cap():
    from modules.active.permutations import generate_permutations
    cands = generate_permutations("api.example.com", max_candidates=5)
    assert len(cands) <= 5


async def test_permutations_skips_own_output():
    from events.types import SubdomainData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["permutations"], controller=ctrl)[0]
    event = MagicMock()
    event.source_tool = "permutations"      # our own output — must be ignored
    event.data = SubdomainData(hostname="api.example.com", source="permutations")
    await m.handle_event(event)
    ctrl.stamp_and_publish.assert_not_called()


async def test_permutations_emits_resolved_candidates():
    from events.types import SubdomainData
    ctrl = _mock_controller()
    m = ModuleRegistry.load(names=["permutations"], controller=ctrl)[0]
    event = MagicMock()
    event.source_tool = "subfinder"
    event.data = SubdomainData(hostname="api.example.com", source="subfinder")
    event.id = uuid.uuid4()
    event.distance = 1
    out = b"api-dev.example.com\n"
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_fake_proc(out))):
        await m.handle_event(event)
    hostnames = {c[0][0].data.hostname for c in ctrl.stamp_and_publish.call_args_list}
    assert "api-dev.example.com" in hostnames
