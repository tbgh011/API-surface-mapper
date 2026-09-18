"""Scan orchestration: an async generator of UI events.

Phases mirror the browser engine so the same renderer can draw both, then add
what only a server can reach: certificate transparency, full DNS, readable
responses, parsed specs, and CORS behaviour observed from outside a browser.
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Any, AsyncIterator

import httpx

from .. import config
from . import dns_probe, http_probe, owasp, sources, specs

DESCRIPTOR_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/v3/api-docs", "/v2/api-docs", "/api-docs",
    "/.well-known/openapi.json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/security.txt",
    "/graphql",
]

GROUPS = {
    "dir": (
        "Documented public APIs",
        "Listed in the APIs.guru open directory with a machine-readable spec.",
    ),
    "hosts": (
        "Live API hosts",
        "Names from certificate transparency logs and the built-in wordlist that "
        "resolve right now. Resolving means the host exists, not that it is an open API.",
    ),
    "specs": (
        "Endpoints and specifications",
        "Well-known paths fetched directly. The server reads responses the browser "
        "cannot, so these are verdicts rather than candidates.",
    ),
    "config": (
        "Response and configuration findings",
        "What the responses themselves disclose: CORS policy, version banners, "
        "transport settings. Invisible to a browser scanning someone else's host.",
    ),
}

BLANKET_NOTES = {
    200: "a catch-all route answering everything, so these paths are probably not real endpoints",
    401: "a host-wide authentication gate, not per-endpoint protection",
    403: "a host-wide deny, typically a CDN or WAF, not per-endpoint protection",
    405: "the host rejects the method on every path",
    "default": "the same response on every path, so this is host-wide behaviour rather than a finding per path",
}


def _blanket_status(results: list, probe_count: int) -> int | None:
    """The status a host returns to (almost) everything, if it does that.

    A CDN answering 403 to twelve probed paths is one fact about the host, not
    twelve protected endpoints. Reporting it once keeps the output honest.
    """
    answered = [r.status for r in results if r.status is not None]
    # One missing answer is tolerated (a timeout says nothing), but one
    # *different* answer is the interesting result and must not be collapsed.
    if len(answered) < probe_count - 1:
        return None
    distinct = set(answered)
    return distinct.pop() if len(distinct) == 1 else None


_apis_guru_cache: dict[str, Any] | None = None
_apis_guru_fetched_at = 0.0
_APIS_GURU_TTL = 3600.0


def _event(name: str, **data) -> dict[str, Any]:
    return {"event": name, "data": data}


def _finding(group: str, tier: str, url: str, label: str,
             meta: list[tuple[str, str]], owasp_ids: list[str]) -> dict[str, Any]:
    return _event(
        "finding",
        group=group,
        tier=tier,
        url=url,
        label=label,
        meta=[[k, str(v)] for k, v in meta if v not in ("", None)],
        owasp=owasp_ids,
    )


# ---- phases ---------------------------------------------------------------


async def _directory(domain: str, sld: str) -> AsyncIterator[dict[str, Any]]:
    global _apis_guru_cache, _apis_guru_fetched_at

    yield _event("group", id="dir", title=GROUPS["dir"][0], blurb=GROUPS["dir"][1])

    now = time.monotonic()
    if _apis_guru_cache is None or now - _apis_guru_fetched_at > _APIS_GURU_TTL:
        try:
            async with httpx.AsyncClient(
                headers={"user-agent": config.USER_AGENT}, timeout=20, follow_redirects=True
            ) as client:
                r = await client.get("https://api.apis.guru/v2/list.json")
                r.raise_for_status()
                _apis_guru_cache = r.json()
                _apis_guru_fetched_at = now
        except (httpx.HTTPError, ValueError):
            yield _event("note", group="dir", text="Could not reach the public API directory.")
            return

    hits = 0
    for key, entry in (_apis_guru_cache or {}).items():
        provider = key.split(":")[0].lower()
        # Compare registrable labels, not substrings. A bare "sld in provider"
        # matches apis.guru against apisetu.gov.in and buries the real entry
        # under forty unrelated ones.
        provider_sld = provider.split(".")[-2] if "." in provider else provider
        match = (
            provider == domain
            or provider.endswith("." + domain)
            or domain.endswith("." + provider)
            or provider_sld == sld
        )
        if not match:
            continue
        versions = entry.get("versions") or {}
        preferred = entry.get("preferred")
        pref = versions.get(preferred) or next(iter(versions.values()), None)
        if not pref:
            continue
        info = pref.get("info") or {}
        spec = pref.get("swaggerUrl") or pref.get("swaggerYamlUrl") or ""
        link = pref.get("link") or (info.get("contact") or {}).get("url") or spec
        yield _finding(
            "dir", "documented", spec or link, info.get("title") or key,
            [("provider", provider), ("spec", spec)], ["API9"],
        )
        hits += 1
        if hits >= 40:
            break
    if not hits:
        yield _event("note", group="dir",
                     text="No entries for this domain in the public directory.")


async def _hosts(domain: str) -> AsyncIterator[dict[str, Any]]:
    yield _event("status", text="Querying certificate transparency logs...", pct=10)
    ct_names, ct_source = await sources.certificate_transparency(domain)

    hosts, trimmed = sources.candidate_hosts(domain, ct_names, config.MAX_HOSTS)

    yield _event("group", id="hosts", title=GROUPS["hosts"][0], blurb=GROUPS["hosts"][1])
    if ct_source:
        text = (f"{len(ct_names)} names from certificate transparency ({ct_source}), "
                "merged with the built-in wordlist.")
        if trimmed:
            text += f" Probing the {len(hosts)} most API-shaped; {trimmed} not checked."
        yield _event("note", group="hosts", text=text)
    else:
        yield _event(
            "note", group="hosts",
            text="Certificate transparency logs were unreachable, so this falls back "
                 "to the built-in wordlist.",
        )

    yield _event("status", text=f"Resolving {len(hosts)} hostnames...", pct=16)
    results, wildcard = await dns_probe.resolve_many(hosts, domain)

    if wildcard:
        yield _event(
            "note", group="hosts",
            text=f"This domain has a wildcard DNS record ({', '.join(sorted(wildcard))}). "
                 "Names that only match the wildcard are excluded, since they would "
                 "otherwise all look live.",
        )

    live: list[str] = []
    for res in results:
        if res.dangling_cname:
            yield _finding(
                "hosts", "candidate", "https://" + res.host, res.host,
                [("dangling cname", res.dangling_cname),
                 ("takeover candidate", "the target does not resolve")],
                ["API9"],
            )
            continue
        live.append(res.host)
        meta: list[tuple[str, str]] = []
        if res.cname_chain:
            meta.append(("cname", " -> ".join(res.cname_chain)))
        meta.append(("addresses", ", ".join(res.addresses[:4])))
        if res.blocked_addresses:
            meta.append(("not probed", "resolves to a reserved address"))
        yield _finding("hosts", "live", "https://" + res.host, res.host,
                       meta, owasp.for_host(res.host))

    if not live:
        yield _event("note", group="hosts",
                     text="No API-style hostnames resolved for this domain.")

    yield _event("hosts-resolved", hosts=live)


def _spec_findings(doc: dict[str, Any]) -> tuple[list[tuple[str, str]], list[str]]:
    meta: list[tuple[str, str]] = []
    ids = ["API3", "API8"]

    if specs.is_openapi(doc):
        s = specs.summarise_openapi(doc)
        if s.title:
            meta.append(("title", f"{s.title}{' v' + s.version if s.version else ''}"))
        if s.spec_version:
            meta.append(("spec", s.spec_version))
        meta.append(("surface", f"{s.path_count} paths, {s.operation_count} operations"))
        if s.servers:
            meta.append(("servers", ", ".join(s.servers[:3])))
        if s.schemes:
            meta.append(("auth schemes", ", ".join(s.schemes)))
        else:
            meta.append(("auth schemes", "none declared"))
            ids.append("API2")
        if s.unauthenticated:
            shown = ", ".join(s.unauthenticated[:4])
            more = f" (+{len(s.unauthenticated) - 4} more)" if len(s.unauthenticated) > 4 else ""
            meta.append((f"{len(s.unauthenticated)} operations declare no auth", shown + more))
            ids.append("API5")
        if s.widest_schema:
            name, count = s.widest_schema
            meta.append(("widest schema", f"{name} exposes {count} properties"))
        return meta, ids

    if "issuer" in doc and any(k.endswith("_endpoint") for k in doc):
        o = specs.summarise_oidc(doc)
        ids = ["API2", "API8"]
        meta.append(("issuer", o.issuer))
        meta.append(("endpoints", str(o.endpoints)))
        if o.grant_types:
            meta.append(("grants", ", ".join(o.grant_types[:6])))
        for weakness in o.weak:
            meta.append(("weak", weakness))
        return meta, ids

    meta.append(("readable", "document parsed, not an API specification"))
    return meta, ["API8"]


async def _descriptors(domain: str, live: list[str],
                       fetcher: http_probe.SafeFetcher) -> AsyncIterator[dict[str, Any]]:
    yield _event("group", id="specs", title=GROUPS["specs"][0], blurb=GROUPS["specs"][1])

    ordered = [domain] + [h for h in live if h != domain]
    origins = ordered[: config.MAX_PROBE_ORIGINS]
    skipped = len(ordered) - len(origins)
    if skipped > 0:
        yield _event(
            "note", group="specs",
            text=f"Probing spec paths on the first {len(origins)} hosts; "
                 f"{skipped} more resolved but were not probed.",
        )

    total = len(origins)
    found_anything = False
    graphql_origins: set[str] = set()

    for index, host in enumerate(origins, 1):
        yield _event("status", text=f"Probing spec paths on {host} ({index}/{total})",
                     pct=58 + (index / max(1, total)) * 32)

        urls = [f"https://{host}{p}" for p in DESCRIPTOR_PATHS]
        results = await asyncio.gather(*(
            fetcher.fetch(u, headers={"accept": "application/json, text/yaml, */*"})
            for u in urls
        ))

        parsed: dict[str, dict[str, Any]] = {}
        for url, res in zip(urls, results):
            if res.ok and not url.endswith("security.txt"):
                doc = specs.parse_document(res.text, res.content_type)
                if doc is not None:
                    parsed[url] = doc

        blanket = _blanket_status(results, len(urls)) if not parsed else None
        if blanket is not None:
            if blanket in (404, 410):
                continue
            found_anything = True
            tier = "candidate" if blanket >= 500 else "live"
            yield _finding(
                "specs", tier, f"https://{host}/", host,
                [("blanket response", f"every probed path returns {blanket}"),
                 ("note", BLANKET_NOTES.get(blanket, BLANKET_NOTES["default"]))],
                owasp.merge(["API9"], ["API8"] if blanket >= 500 else []),
            )
            continue

        for url, res in zip(urls, results):
            if res.error:
                # The host resolved but the request failed: genuinely unknown, so
                # it stays a candidate rather than being silently dropped.
                if "public address" not in res.error:
                    found_anything = True
                    yield _finding("specs", "candidate", url, url,
                                   [("unresolved", res.error)], owasp.for_path(url))
                continue

            status = res.status or 0
            if url.endswith("/graphql") and status in (200, 400, 405, 422):
                graphql_origins.add(url)
                continue
            if status in (404, 410):
                continue

            if res.ok:
                # security.txt is plain text, and a YAML parser will happily read
                # it as a mapping, so it is classified by path before parsing.
                if url.endswith("security.txt"):
                    if "contact" in res.text.lower():
                        found_anything = True
                        yield _finding(
                            "specs", "documented", url, url,
                            [("status", f"{status} {res.content_type}"),
                             ("security.txt", "published, use it for disclosure contact")],
                            ["API8"],
                        )
                    continue

                doc = parsed.get(url)
                if doc is not None:
                    meta, ids = _spec_findings(doc)
                    meta.insert(0, ("status", f"{status} {res.content_type}"))
                    if res.redirects:
                        meta.append(("redirected to", res.redirects[-1]))
                    found_anything = True
                    yield _finding("specs", "documented", res.final_url or url, url, meta, ids)
                    continue

                found_anything = True
                body_note = (
                    f"served, but larger than the {config.MAX_BODY_BYTES // 1_000_000}MB "
                    "read limit, so it could not be parsed. Raise MAX_BODY_BYTES to read it."
                    if res.truncated else
                    "served, but not a parseable specification"
                )
                yield _finding(
                    "specs", "live", url, url,
                    [("status", f"{status} {res.content_type}"), ("body", body_note)],
                    owasp.for_path(url),
                )
                continue

            if status in (401, 403):
                found_anything = True
                yield _finding(
                    "specs", "live", url, url,
                    [("status", f"{status} authentication required"),
                     ("note", "the endpoint exists and is protected")],
                    owasp.merge(owasp.for_path(url), ["API2"]),
                )
            elif status >= 500:
                found_anything = True
                yield _finding(
                    "specs", "candidate", url, url,
                    [("status", f"{status} server error"),
                     ("note", "the path exists but the server failed on it")],
                    owasp.merge(owasp.for_path(url), ["API8"]),
                )

    for url in sorted(graphql_origins):
        res = await fetcher.fetch(
            url, method="POST",
            json=specs.INTROSPECTION_QUERY,
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        if res.error or res.status is None:
            continue
        g = specs.summarise_graphql(res.text)
        found_anything = True
        if g.introspection:
            yield _finding(
                "specs", "documented", url, url,
                [("graphql", "introspection is enabled"),
                 ("types", f"{g.type_count} exposed"),
                 ("note", "the full schema is readable by anyone")],
                ["API4", "API3", "API9"],
            )
        else:
            yield _finding(
                "specs", "live", url, url,
                [("graphql", g.note or f"endpoint responds ({res.status})")],
                ["API4", "API9"],
            )

    if not found_anything:
        yield _event("note", group="specs",
                     text="No specification or well-known endpoint responded on the probed hosts.")


async def _configuration(live: list[str],
                         fetcher: http_probe.SafeFetcher) -> AsyncIterator[dict[str, Any]]:
    origins = live[: config.MAX_PROBE_ORIGINS]
    if not origins:
        return
    yield _event("group", id="config", title=GROUPS["config"][0], blurb=GROUPS["config"][1])
    yield _event("status", text="Inspecting response headers and CORS policy...", pct=92)

    urls = [f"https://{host}/" for host in origins]
    results = await asyncio.gather(*(
        fetcher.fetch(u, headers={"origin": http_probe.PROBE_ORIGIN}) for u in urls
    ))

    emitted = False
    for host, url, res in zip(origins, urls, results):
        if res.error or not res.headers:
            continue
        meta = http_probe.analyse_cors(res.headers) + http_probe.analyse_headers(res.headers, url)
        if not meta:
            continue
        emitted = True
        # API8 covers all of this. The 2023 text names a missing or improper CORS
        # policy under Security Misconfiguration explicitly, so there is nothing
        # to gain by reaching for a second category.
        yield _finding("config", "live", url, host,
                       [("status", str(res.status)), *meta], ["API8"])

    if not emitted:
        yield _event("note", group="config",
                     text="Nothing notable in the response headers of the probed hosts.")


# ---- entry point ----------------------------------------------------------


async def run_scan(domain: str) -> AsyncIterator[dict[str, Any]]:
    sld = domain.split(".")[-2] if domain.count(".") >= 1 else domain
    started = time.monotonic()

    yield _event("status", text="Checking the public API directory...", pct=4)
    async for ev in _directory(domain, sld):
        yield ev

    live: list[str] = []
    async for ev in _hosts(domain):
        if ev["event"] == "hosts-resolved":
            live = ev["data"]["hosts"]
            continue
        yield ev

    fetcher = http_probe.SafeFetcher()
    try:
        async for ev in _descriptors(domain, live, fetcher):
            yield ev
        async for ev in _configuration(live, fetcher):
            yield ev
    finally:
        await fetcher.aclose()

    yield _event("done", elapsed=round(time.monotonic() - started, 1))
