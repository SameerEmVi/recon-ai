"""External-tool proxy propagation: configuring --proxy threads each tool's own
proxy flag (nuclei -proxy, ffuf -x, katana -proxy, httpx -proxy) — and nothing
is added when no proxy is set."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

from modules.registry import ModuleRegistry
from net.proxy import ProxyConfig
from recon.ffuf import build_command
from recon.httpx_wrap import HttpxWrapper
from recon.nuclei import NucleiWrapper

PROXY = "http://127.0.0.1:8080"


def _ctrl(proxy: ProxyConfig | None = None):
    from ratelimit import NOOP
    c = MagicMock()
    c.scan_id = uuid.uuid4()
    c.rate_limiter = NOOP
    c.stamp_and_publish = AsyncMock(return_value=True)
    if proxy is not None:
        c.proxy = proxy
    return c


def _kw():
    return dict(target_url="http://x.com/FUZZ", wordlist="w.txt", output_file="o.json")


def test_ffuf_adds_dash_x_only_when_proxy_set():
    assert "-x" not in build_command(**_kw())
    cmd = build_command(**_kw(), proxy=PROXY)
    assert cmd[cmd.index("-x") + 1] == PROXY


def test_nuclei_adds_proxy_flag_only_when_set():
    assert NucleiWrapper()._proxy_url is None
    w = NucleiWrapper(proxy_url=PROXY)
    assert w._proxy_url == PROXY


def test_httpx_args_add_proxy_from_controller():
    w_off = HttpxWrapper(_ctrl())              # no proxy
    assert "-proxy" not in w_off._args("x.com")
    w_on = HttpxWrapper(_ctrl(ProxyConfig.from_sources(cli_proxy=PROXY)))
    args = w_on._args("x.com")
    assert args[args.index("-proxy") + 1] == PROXY


def test_katana_module_adds_proxy_flag():
    ModuleRegistry.discover()
    m_on = ModuleRegistry.load(names=["katana"],
                               controller=_ctrl(ProxyConfig.from_sources(cli_proxy=PROXY)))[0]
    assert m_on.proxy_url == PROXY
    m_off = ModuleRegistry.load(names=["katana"], controller=_ctrl())[0]
    assert m_off.proxy_url is None
