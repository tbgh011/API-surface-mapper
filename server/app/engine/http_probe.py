"""HTTP probing without the browser's cross-origin blindfold.

Everything here goes through SafeFetcher, which resolves a hostname and checks
every resolved address against the reserved ranges before a connection is made,
and repeats that check on each redirect hop. Redirects are followed manually for
exactly that reason.

Known limitation, stated rather than hidden: the address check and the connect
are separate steps, so a resolver answering differently between them could still
be followed. For a loopback-bound tool scanning domains you chose, that is an
acceptable residual risk; pinning the checked address into the transport would
close it.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from .. import config
from . import dns_probe


# Timeouts say the same thing every time, so they get a plain label. Anything
# else keeps its message: a TLS certificate failure is itself worth reading, and
# flattening it to "connection error" would throw that away.
ERROR_LABELS = {
    "ConnectTimeout": "connection timed out",
    "ReadTimeout": "read timed out",
    "WriteTimeout": "write timed out",
    "PoolTimeout": "connection pool timed out",
    "RemoteProtocolError": "malformed HTTP response",
}


def _describe(exc: Exception) -> str:
    name = type(exc).__name__
    label = ERROR_LABELS.get(name)
    if label:
        return label
    detail = str(exc).strip().splitlines()[0][:100] if str(exc).strip() else ""
    return f"{name}: {detail}" if detail else name


@dataclass
class ProbeResult:
    url: str
    final_url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    text: str = ""
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


class SafeFetcher:
    def __init__(self) -> None:
        self._resolver = dns_probe._resolver()
        self._host_cache: dict[str, bool] = {}
        self._sem = asyncio.Semaphore(config.HTTP_CONCURRENCY)
        self._client = httpx.AsyncClient(
            headers={"user-agent": config.USER_AGENT},
            follow_redirects=False,
            timeout=config.HTTP_TIMEOUT,
            verify=True,
            limits=httpx.Limits(max_connections=config.HTTP_CONCURRENCY),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def host_allowed(self, host: str) -> bool:
        if host in self._host_cache:
            return self._host_cache[host]
        res = await dns_probe.resolve_host(self._resolver, host)
        allowed = bool(res.addresses) and not res.blocked_addresses
        self._host_cache[host] = allowed
        return allowed

    async def fetch(self, url: str, method: str = "GET", **kwargs) -> ProbeResult:
        out = ProbeResult(url=url)
        current = url
        async with self._sem:
            for hop in range(config.MAX_REDIRECTS + 1):
                host = urlsplit(current).hostname or ""
                if not host:
                    out.error = "malformed url"
                    return out
                if not await self.host_allowed(host):
                    out.error = "host does not resolve to a public address"
                    return out
                try:
                    req = self._client.build_request(method, current, **kwargs)
                    resp = await self._client.send(req, stream=True)
                except httpx.HTTPError as exc:
                    out.error = _describe(exc)
                    return out

                try:
                    if resp.is_redirect and hop < config.MAX_REDIRECTS:
                        # The finally below closes the response either way.
                        location = resp.headers.get("location", "")
                        if not location:
                            out.error = "redirect without a Location header"
                            return out
                        current = urljoin(current, location)
                        out.redirects.append(current)
                        continue

                    body = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= config.MAX_BODY_BYTES:
                            # A truncated document will not parse. The caller is
                            # told why rather than being left to conclude the
                            # response was not a specification.
                            truncated = True
                            del body[config.MAX_BODY_BYTES:]
                            break
                finally:
                    await resp.aclose()

                out.final_url = current
                out.status = resp.status_code
                out.headers = {k.lower(): v for k, v in resp.headers.items()}
                out.content_type = out.headers.get("content-type", "").split(";")[0].strip()
                out.text = bytes(body).decode("utf-8", errors="replace")
                out.truncated = truncated
                return out

        out.error = "too many redirects"
        return out


# ---- response analysis ----------------------------------------------------

PROBE_ORIGIN = "https://api-surface-mapper.invalid"


def analyse_cors(headers: dict[str, str]) -> list[tuple[str, str]]:
    """CORS findings a browser can never report on someone else's host."""
    findings: list[tuple[str, str]] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower() == "true"
    if not acao:
        return findings
    if acao == PROBE_ORIGIN:
        note = f"reflects an arbitrary Origin header ({acao})"
        if acac:
            note += ", with credentials allowed, so any site can read authenticated responses"
        findings.append(("cors", note))
    elif acao == "*" and acac:
        findings.append(("cors", "allows any origin with credentials, which browsers reject but non-browser clients do not"))
    elif acao == "*":
        findings.append(("cors", "open to any origin"))
    return findings


def analyse_headers(headers: dict[str, str], url: str) -> list[tuple[str, str]]:
    """Security-relevant response headers. Maps to API8."""
    findings: list[tuple[str, str]] = []
    banner = " ".join(
        v for k, v in headers.items()
        if k in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
    ).strip()
    if banner and any(ch.isdigit() for ch in banner):
        findings.append(("banner", banner))
    if url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(("hsts", "missing"))
    return findings
