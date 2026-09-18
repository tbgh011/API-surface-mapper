"""OWASP API Security Top 10 (2023) mapping, mirroring the browser engine.

The frontend owns the presentation (titles, links, guidance copy). The server
only emits category ids, so the two engines stay in step as long as the id set
matches.
"""
from __future__ import annotations

import re

AUTH_LABELS = re.compile(r"^(auth|oauth|sso|id|identity|login|token|account|accounts|idp|auth0)$")
GRAPHQL_LABELS = re.compile(r"^(graphql|gql)$")
SSRF_LABELS = re.compile(r"^(webhook|webhooks|integrations|connect|partner|partners|proxy|fetch)$")


def for_host(host: str) -> list[str]:
    label = host.split(".")[0]
    if AUTH_LABELS.match(label):
        return ["API2"]
    if GRAPHQL_LABELS.match(label):
        return ["API4"]
    if SSRF_LABELS.match(label):
        return ["API7"]
    return ["API9"]


def for_path(url: str) -> list[str]:
    if "openid-configuration" in url or "oauth-authorization-server" in url:
        return ["API2"]
    if re.search(r"/graphql/?$", url):
        return ["API4"]
    return ["API9"]


def merge(*groups: list[str]) -> list[str]:
    """Union of category lists, order preserved, duplicates dropped."""
    out: list[str] = []
    for group in groups:
        for item in group or []:
            if item not in out:
                out.append(item)
    return out
