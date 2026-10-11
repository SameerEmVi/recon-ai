"""
policy — central mode & capability enforcement for recon-ai.

The selected execution mode (osint / active / vuln / full) maps to a set of
*capabilities* a scan is allowed to exercise. Every module is classified by the
capabilities it actually uses (by behaviour, never by name), and the policy
rejects any module — or any runtime action — whose capability is not permitted by
the mode. This is enforced centrally (module loading + the network primitives +
the agent tools), not merely by CLI filtering, so a passive (`osint`) scan is
*technically unable* to launch active target probes.

The ScopeEngine remains the authoritative scope gate; the capability policy is an
orthogonal, additional gate and never widens scope.
"""

from __future__ import annotations

from policy.policy import (
    ALL_CAPABILITIES,
    ALLOW_ALL,
    CAP_ACTIVE_DISCOVERY,
    CAP_FUZZING,
    CAP_INTRUSIVE_TEST,
    CAP_PASSIVE_EXTERNAL,
    CAP_PORT_SCANNING,
    CAP_TARGET_DNS_QUERY,
    CAP_TARGET_HTTP_REQUEST,
    CAP_VULNERABILITY_CHECK,
    MODES,
    MODULE_CAPABILITIES,
    CapabilityDenied,
    CapabilityPolicy,
    get_policy,
)

__all__ = [
    "CapabilityPolicy",
    "CapabilityDenied",
    "get_policy",
    "ALLOW_ALL",
    "MODES",
    "MODULE_CAPABILITIES",
    "ALL_CAPABILITIES",
    "CAP_PASSIVE_EXTERNAL",
    "CAP_TARGET_DNS_QUERY",
    "CAP_TARGET_HTTP_REQUEST",
    "CAP_ACTIVE_DISCOVERY",
    "CAP_FUZZING",
    "CAP_PORT_SCANNING",
    "CAP_VULNERABILITY_CHECK",
    "CAP_INTRUSIVE_TEST",
]
