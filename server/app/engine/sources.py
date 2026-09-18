"""Hostname candidate sources.

The browser engine guesses from a fixed wordlist because every real enumeration
source blocks cross-origin reads. From a server we can query certificate
transparency logs, which return names that were actually issued certificates
rather than names someone thought to guess.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from .. import config

# Same wordlist the browser engine uses. Kept as a floor: CT only shows names
# that got a public certificate, so a plain-HTTP or internal-CA host still needs
# guessing.
API_HOSTS = [
    "api", "apis", "api-gateway", "gateway", "gw", "edge",
    "developer", "developers", "dev", "devapi",
    "graphql", "gql", "rest", "rpc",
    "data", "public-api", "open-api", "openapi",
    "docs", "apidocs", "api-docs", "reference",
    "sandbox", "api-sandbox", "staging-api", "api-staging", "test-api",
    "v1", "v2", "v3",
    "services", "service", "backend", "bff",
    "mobile-api", "app-api", "partner", "partners", "integrations", "connect",
    "auth", "oauth", "id", "identity", "sso",
    "webhook", "webhooks", "events", "stream", "streaming", "realtime",
]

# Names worth probing for an API surface even when CT returns hundreds of hosts.
INTERESTING = re.compile(
    r"(^|[.\-])(api|apis|gw|gateway|graphql|gql|rest|rpc|grpc|dev|developer|"
    r"developers|sandbox|staging|stage|test|qa|uat|preprod|internal|admin|"
    r"auth|oauth|sso|id|identity|login|token|account|accounts|idp|"
    r"webhook|webhooks|events|stream|streaming|realtime|"
    r"service|services|svc|backend|bff|edge|data|partner|partners|"
    r"integrations|connect|mobile|app|v[0-9]+|openapi|swagger|docs|apidocs)"
    r"([.\-]|$)"
)

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def _clean_names(raw_names, domain: str) -> set[str]:
    out: set[str] = set()
    suffix = "." + domain
    for raw in raw_names:
        for name in str(raw).split("\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or not HOST_RE.match(name):
                continue
            if name == domain or name.endswith(suffix):
                out.add(name)
    return out


async def _crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    r = await client.get(url, params=params, timeout=config.CT_TIMEOUT)
    r.raise_for_status()
    rows = r.json()
    names = []
    for row in rows:
        names.append(row.get("name_value", ""))
        names.append(row.get("common_name", ""))
    return _clean_names(names, domain)


async def _certspotter(client: httpx.AsyncClient, domain: str) -> set[str]:
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    }
    r = await client.get(url, params=params, timeout=config.CT_TIMEOUT)
    r.raise_for_status()
    names = []
    for row in r.json():
        names.extend(row.get("dns_names", []) or [])
    return _clean_names(names, domain)


async def certificate_transparency(domain: str) -> tuple[set[str], str]:
    """Names seen in CT logs. Returns (names, source description)."""
    headers = {"user-agent": config.USER_AGENT, "accept": "application/json"}
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        for name, fn in (("crt.sh", _crtsh), ("certspotter", _certspotter)):
            try:
                found = await fn(client, domain)
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
                continue
            if found:
                return found, name
    return set(), ""


def _split(names: set[str]) -> tuple[list[str], list[str]]:
    interesting = sorted(n for n in names if INTERESTING.search(n))
    return interesting, sorted(names - set(interesting))


def candidate_hosts(domain: str, ct_names: set[str], cap: int) -> tuple[list[str], int]:
    """Merge the wordlist with CT names and rank them for probing.

    A name from a certificate transparency log was issued a certificate, so it
    almost certainly exists; a wordlist entry is a guess. When the cap bites, the
    guesses are what should be dropped, so confirmed names sort ahead of them.

    Returns (hosts, number_trimmed).
    """
    confirmed = set(ct_names) | {domain}
    guesses = {f"{h}.{domain}" for h in API_HOSTS} - confirmed

    confirmed_api, confirmed_other = _split(confirmed)
    guess_api, guess_other = _split(guesses)

    ordered = [domain] + [
        n for n in confirmed_api + guess_api + confirmed_other + guess_other
        if n != domain
    ]

    trimmed = max(0, len(ordered) - cap)
    return ordered[:cap], trimmed
