"""DNS resolution with the detail a browser cannot get.

The browser engine can only ask DNS-over-HTTPS "does this name have an A
record". Here we get the full CNAME chain, both address families, wildcard
detection so a catch-all record does not manufacture hundreds of fake hosts,
and dangling-CNAME detection, which is a genuine inventory finding: a name that
still points at a deprovisioned third-party host is a subdomain takeover
candidate.
"""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from .. import config, safety


@dataclass
class HostResult:
    host: str
    addresses: list[str] = field(default_factory=list)
    blocked_addresses: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    dangling_cname: str | None = None

    @property
    def resolves(self) -> bool:
        return bool(self.addresses) or self.dangling_cname is not None


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=True)
    # Public resolvers, so results do not depend on the container's DNS and are
    # comparable to what the browser engine sees.
    r.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    r.timeout = config.DNS_TIMEOUT
    r.lifetime = config.DNS_TIMEOUT * 2
    return r


def _cname_chain(answer) -> list[str]:
    chain: list[str] = []
    for rrset in answer.response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for rdata in rrset:
                chain.append(str(rdata.target).rstrip("."))
    return chain


async def _addresses(resolver, host: str, rdtype: str) -> tuple[list[str], list[str]]:
    try:
        answer = await resolver.resolve(host, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], []
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
        return [], []
    addrs = [str(r) for rrset in answer.response.answer
             if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
             for r in rrset]
    return addrs, _cname_chain(answer)


async def _cname_only(resolver, host: str) -> str | None:
    try:
        answer = await resolver.resolve(host, "CNAME", raise_on_no_answer=False)
    except dns.exception.DNSException:
        return None
    chain = _cname_chain(answer)
    return chain[-1] if chain else None


async def resolve_host(resolver, host: str) -> HostResult:
    result = HostResult(host=host)

    a_addrs, a_chain = await _addresses(resolver, host, "A")
    if a_addrs:
        addrs, chain = a_addrs, a_chain
    else:
        aaaa_addrs, aaaa_chain = await _addresses(resolver, host, "AAAA")
        addrs, chain = aaaa_addrs, aaaa_chain or a_chain

    result.cname_chain = chain

    if addrs:
        public, blocked = safety.filter_public(addrs)
        result.addresses = public
        result.blocked_addresses = blocked
        return result

    # No address. If a CNAME still exists, the name points at something that is
    # gone: a takeover candidate worth reporting.
    target = chain[-1] if chain else await _cname_only(resolver, host)
    if target:
        result.dangling_cname = target
    return result


async def detect_wildcard(resolver, domain: str) -> set[str]:
    """Address set returned by a name that should not exist, if any."""
    probes = [f"{secrets.token_hex(6)}.{domain}" for _ in range(2)]
    seen: list[set[str]] = []
    for probe in probes:
        addrs, _ = await _addresses(resolver, probe, "A")
        seen.append(set(addrs))
    if seen and all(seen) and seen[0] == seen[-1]:
        return seen[0]
    return set()


async def resolve_many(hosts: list[str], domain: str,
                       on_progress=None) -> tuple[list[HostResult], set[str]]:
    """Resolve every host concurrently. Returns (results, wildcard address set).

    `domain` is the scanned apex and must be passed explicitly: deriving it from
    the first hostname gives the public suffix, and probing a random label under
    `com` tells you nothing.
    """
    resolver = _resolver()
    wildcard = await detect_wildcard(resolver, domain) if domain else set()

    sem = asyncio.Semaphore(config.DNS_CONCURRENCY)
    results: list[HostResult] = []
    done = 0
    total = len(hosts)

    async def one(host: str) -> None:
        nonlocal done
        async with sem:
            res = await resolve_host(resolver, host)
        done += 1
        if on_progress:
            on_progress(done, total)
        if res.resolves:
            results.append(res)

    await asyncio.gather(*(one(h) for h in hosts))

    if wildcard:
        # Keep only names that say something the wildcard does not: a different
        # address set, or a CNAME of their own.
        results = [
            r for r in results
            if r.cname_chain or r.dangling_cname or set(r.addresses) != wildcard
        ]

    results.sort(key=lambda r: (r.host.count("."), r.host))
    return results, wildcard
