"""
Tests for net.headers — the browser header-profile feature.

Covers: no accept-encoding anywhere (we can't decode br/zstd); sec-ch-ua only on
Chromium; deterministic+stable 'random'; fail-closed resolve on a typo; off/None
→ None; get_headers test-safety; http_client injects the UA but a caller's explicit
header wins; cli_args round-trips every header as repeated -H pairs.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from net.headers import (
    PROFILES,
    HeaderProfile,
    available,
    get_headers,
    resolve,
)

_CHROMIUM = {"chrome-windows", "chrome-mac", "chrome-android"}
_NON_CHROMIUM = {"firefox-windows", "safari-mac"}


def test_every_profile_omits_accept_encoding():
    # httpx only decodes gzip/deflate here (no brotli/zstd libs). Advertising
    # br/zstd would make bodies arrive undecodable and break downstream modules.
    for name, prof in PROFILES.items():
        assert "accept-encoding" not in prof.as_dict(), f"{name} must not set accept-encoding"


def test_chromium_profiles_have_sec_ch_ua():
    for name in _CHROMIUM:
        keys = PROFILES[name].as_dict()
        assert "sec-ch-ua" in keys, f"{name} should carry client hints"
        assert "sec-ch-ua-mobile" in keys and "sec-ch-ua-platform" in keys


def test_non_chromium_profiles_have_no_client_hints():
    for name in _NON_CHROMIUM:
        keys = PROFILES[name].as_dict()
        assert not any(k.startswith("sec-ch-ua") for k in keys), \
            f"{name} must NOT send sec-ch-ua* (Chromium-only)"


def test_header_names_are_lowercased():
    for prof in PROFILES.values():
        for k, _ in prof.headers:
            assert k == k.lower()


def test_no_ip_spoofing_or_trust_headers_anywhere():
    banned = {"x-forwarded-for", "x-real-ip", "cookie", "authorization", "x-forwarded-host"}
    for name, prof in PROFILES.items():
        assert not (set(prof.as_dict()) & banned), f"{name} leaks a trust/spoof header"


def test_default_profile_present():
    assert "chrome-windows" in PROFILES


def test_resolve_random_is_deterministic_and_stable():
    a = resolve("random", seed="scan-abc")
    b = resolve("random", seed="scan-abc")
    assert isinstance(a, HeaderProfile)
    assert a is b or a == b                       # same profile for the same seed
    # a different seed may select a different profile, but each is stable
    c = resolve("random", seed="scan-abc")
    assert c == a
    # and it's one of the real profiles
    assert a.name in PROFILES


def test_resolve_random_varies_by_seed_but_fixed_per_seed():
    picks = {resolve("random", seed=f"s{i}").name for i in range(50)}
    assert len(picks) >= 2                        # not pinned to a single profile
    assert picks <= set(PROFILES)


def test_resolve_unknown_raises_valueerror():
    with pytest.raises(ValueError):
        resolve("bogus")
    with pytest.raises(ValueError):
        resolve("chrome")                         # close-but-wrong name still fails


def test_resolve_off_and_none_return_none():
    assert resolve("off") is None
    assert resolve(None) is None
    assert resolve("OFF") is None                 # case-insensitive
    assert resolve("") is None


def test_resolve_known_names_case_insensitive():
    assert resolve("chrome-windows") is PROFILES["chrome-windows"]
    assert resolve("Chrome-Windows") is PROFILES["chrome-windows"]


def test_available_lists_profiles_plus_selectors():
    av = available()
    assert set(PROFILES) <= set(av)
    assert "off" in av and "random" in av


def test_get_headers_test_safety():
    # A MagicMock controller must yield None so tests keep httpx default headers.
    assert get_headers(MagicMock()) is None
    # object without .headers → None
    assert get_headers(object()) is None
    # a real HeaderProfile on .headers → returned as-is
    ctrl = MagicMock()
    ctrl.headers = PROFILES["chrome-windows"]
    assert get_headers(ctrl) is PROFILES["chrome-windows"]


def test_cli_args_round_trips_every_header_as_repeated_H():
    prof = PROFILES["chrome-windows"]
    args = prof.cli_args("-H")
    # structure: [-H, "k: v", -H, "k: v", ...]
    assert len(args) == 2 * len(prof.headers)
    assert all(flag == "-H" for flag in args[0::2])
    pairs = {kv.split(": ", 1)[0]: kv.split(": ", 1)[1] for kv in args[1::2]}
    assert pairs == prof.as_dict()


def test_http_client_injects_profile_but_caller_header_wins():
    from modules.base import BaseModule

    class _M(BaseModule):
        name = "t"

    ctrl = MagicMock()
    ctrl.headers = PROFILES["chrome-windows"]      # real profile → injected
    mod = _M(ctrl)

    # profile UA is applied
    client = mod.http_client()
    try:
        assert "Chrome" in client.headers["user-agent"]
        assert "sec-ch-ua" in client.headers
    finally:
        pass

    # a caller's explicit header overrides the profile's
    client2 = mod.http_client(headers={"user-agent": "custom-ua/9"})
    assert client2.headers["user-agent"] == "custom-ua/9"


def test_http_client_no_profile_keeps_httpx_defaults():
    from modules.base import BaseModule

    class _M(BaseModule):
        name = "t"

    ctrl = MagicMock()                             # MagicMock → get_headers None
    client = _M(ctrl).http_client()
    # httpx sets its own default UA (python-httpx/…); our profile UA is absent
    assert "Chrome" not in client.headers.get("user-agent", "")
