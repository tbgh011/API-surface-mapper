"""Guards that keep the scanner pointed outward and politely paced.

Two concerns live here:

1. SSRF. The engine fetches URLs derived from DNS answers and HTTP redirects,
   which are attacker-influenceable. Every hostname is resolved and every
   resolved address is checked against the reserved ranges before a socket is
   opened, and each redirect hop is checked again.
2. Scope and pacing. An optional allowlist restricts which domains this
   instance will touch, and a token bucket caps how often a client can start
   a scan.
"""
from __future__ import annotations

import ipaddress
import re
import time
from collections import deque

from . import config

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# Cloud instance metadata services, which are the classic SSRF target and are
# not all inside the RFC1918 ranges.
METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
    ipaddress.ip_address("fd00:ec2::254"),    # AWS IMDSv2 over IPv6
}


class ScanRefused(Exception):
    """Raised when a request is out of scope, malformed, or rate limited."""


def clean_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0]
    d = re.sub(r":\d+$", "", d)
    d = d.strip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def validate_domain(raw: str) -> str:
    """Normalise and check a scan target, or raise ScanRefused."""
    domain = clean_domain(raw)
    if not domain:
        raise ScanRefused("No domain supplied.")
    if not DOMAIN_RE.match(domain):
        raise ScanRefused(
            "That does not look like a domain. Use a form like example.com."
        )
    # An IP literal would sidestep the whole point of resolving before fetching.
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ScanRefused("Scan a domain name, not an IP address.")

    if config.SCOPE_ALLOWLIST:
        allowed = any(
            domain == suffix or domain.endswith("." + suffix)
            for suffix in config.SCOPE_ALLOWLIST
        )
        if not allowed:
            raise ScanRefused(
                "This instance is restricted to an allowlist of domains and "
                f"{domain} is not on it."
            )
    return domain


def is_public_address(addr: str) -> bool:
    """True only for addresses it is safe to open a connection to."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip in METADATA_ADDRESSES:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def filter_public(addresses: list[str]) -> tuple[list[str], list[str]]:
    """Split addresses into (public, blocked)."""
    public, blocked = [], []
    for a in addresses:
        (public if is_public_address(a) else blocked).append(a)
    return public, blocked


class RateLimiter:
    """Fixed-window-free token bucket: N scan starts per minute per client."""

    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._hits: dict[str, deque[float]] = {}

    def check(self, client: str) -> None:
        now = time.monotonic()
        window = self._hits.setdefault(client, deque())
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            wait = int(60 - (now - window[0])) + 1
            raise ScanRefused(
                f"Rate limit reached ({self.per_minute} scans per minute). "
                f"Try again in {wait}s."
            )
        window.append(now)
        # Keep the map from growing without bound on a long-lived process.
        if len(self._hits) > 512:
            for key in [k for k, v in self._hits.items() if not v]:
                self._hits.pop(key, None)


rate_limiter = RateLimiter(config.RATE_LIMIT_PER_MIN)
