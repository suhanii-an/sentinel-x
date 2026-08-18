"""Network address classification.

There is a trap here worth documenting, because it silently disabled a detection
factor during development.

``ipaddress.ip_address(x).is_private`` answers "is this address in one of IANA's
special-purpose registries?", and that set includes the documentation ranges
reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those are
exactly the ranges this project uses to represent *external, adversary-controlled*
infrastructure, so ``is_private`` returns True for every simulated attacker
address — and any rule asking "did this come from outside?" answers "no".

A SOC does not mean "IANA special-purpose" when it says private. It means "inside
my network". So internality is defined here against the ranges an enterprise
actually routes internally, and everything else — including documentation space —
is external.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

#: Ranges an enterprise routes internally.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",        # RFC 1918
        "172.16.0.0/12",     # RFC 1918
        "192.168.0.0/16",    # RFC 1918
        "127.0.0.0/8",       # loopback
        "169.254.0.0/16",    # link-local
        "100.64.0.0/10",     # RFC 6598 carrier-grade NAT, commonly internal
        "::1/128",           # IPv6 loopback
        "fc00::/7",          # IPv6 unique local
        "fe80::/10",         # IPv6 link-local
    )
)

#: Documentation ranges. Called out explicitly so their treatment is a stated
#: decision rather than a side effect: in this project they stand in for the
#: public internet and are therefore external.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


@lru_cache(maxsize=4096)
def parse(address: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not address:
        return None
    try:
        return ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None


@lru_cache(maxsize=4096)
def is_internal(address: str | None) -> bool:
    """True when the address belongs to internally-routed space."""
    parsed = parse(address)
    if parsed is None:
        return False
    return any(parsed in network for network in _INTERNAL_NETWORKS)


def is_external(address: str | None) -> bool:
    """True when the address is outside the organisation's networks.

    Returns False for an unparseable or missing address: "unknown" must not be
    treated as "external", or every malformed record becomes a finding.
    """
    parsed = parse(address)
    if parsed is None:
        return False
    return not is_internal(address)


def is_documentation(address: str | None) -> bool:
    parsed = parse(address)
    if parsed is None:
        return False
    return any(parsed in network for network in DOCUMENTATION_NETWORKS)


def classify(address: str | None) -> str:
    """``internal`` | ``external`` | ``unknown`` — for display and metadata."""
    parsed = parse(address)
    if parsed is None:
        return "unknown"
    return "internal" if is_internal(address) else "external"
