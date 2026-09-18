"""Parsing what the probes retrieve.

The browser engine can say "a spec exists". With the document in hand we can say
what is in it: how many operations, which of them declare no authentication,
what auth schemes exist, and how wide the object schemas are. That is the
difference between an inventory entry and a review starting point.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def parse_document(text: str, content_type: str = "") -> dict[str, Any] | None:
    """Parse a JSON or YAML document, or return None if it is neither."""
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.startswith("{") or "json" in content_type:
        try:
            doc = json.loads(stripped)
            return doc if isinstance(doc, dict) else None
        except ValueError:
            pass
    if stripped.startswith("<"):
        return None  # HTML error page dressed up with a JSON content type
    try:
        doc = yaml.safe_load(stripped)
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def is_openapi(doc: dict[str, Any]) -> bool:
    if not isinstance(doc, dict):
        return False
    return bool(doc.get("openapi") or doc.get("swagger")) and isinstance(doc.get("paths"), dict)


@dataclass
class SpecSummary:
    title: str = ""
    version: str = ""
    spec_version: str = ""
    servers: list[str] = field(default_factory=list)
    path_count: int = 0
    operation_count: int = 0
    unauthenticated: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    schema_count: int = 0
    widest_schema: tuple[str, int] | None = None


def summarise_openapi(doc: dict[str, Any]) -> SpecSummary:
    s = SpecSummary()
    info = doc.get("info") or {}
    s.title = str(info.get("title") or "")
    s.version = str(info.get("version") or "")
    s.spec_version = str(doc.get("openapi") or doc.get("swagger") or "")

    servers = doc.get("servers")
    if isinstance(servers, list):
        s.servers = [str(x.get("url")) for x in servers if isinstance(x, dict) and x.get("url")]
    elif doc.get("host"):  # Swagger 2
        scheme = (doc.get("schemes") or ["https"])[0]
        s.servers = [f"{scheme}://{doc['host']}{doc.get('basePath', '')}"]

    components = doc.get("components") or {}
    schemes = components.get("securitySchemes") or doc.get("securityDefinitions") or {}
    if isinstance(schemes, dict):
        s.schemes = sorted(str(k) for k in schemes)

    root_security = doc.get("security")
    root_protected = bool(root_security) and root_security != [{}]

    paths = doc.get("paths") or {}
    s.path_count = len(paths)
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            s.operation_count += 1
            op_security = op.get("security")
            if op_security is not None:
                protected = bool(op_security) and op_security != [{}]
            else:
                protected = root_protected
            if not protected:
                s.unauthenticated.append(f"{method.upper()} {path}")

    schemas = components.get("schemas") or doc.get("definitions") or {}
    if isinstance(schemas, dict):
        s.schema_count = len(schemas)
        widest = None
        for name, schema in schemas.items():
            if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                count = len(schema["properties"])
                if widest is None or count > widest[1]:
                    widest = (str(name), count)
        s.widest_schema = widest
    return s


@dataclass
class OidcSummary:
    issuer: str = ""
    endpoints: int = 0
    grant_types: list[str] = field(default_factory=list)
    weak: list[str] = field(default_factory=list)


def summarise_oidc(doc: dict[str, Any]) -> OidcSummary:
    o = OidcSummary()
    o.issuer = str(doc.get("issuer") or "")
    o.endpoints = sum(1 for k in doc if k.endswith("_endpoint"))
    grants = doc.get("grant_types_supported")
    if isinstance(grants, list):
        o.grant_types = [str(g) for g in grants]

    auth_methods = doc.get("token_endpoint_auth_methods_supported") or []
    if isinstance(auth_methods, list) and "none" in auth_methods:
        o.weak.append("token endpoint accepts unauthenticated clients (auth method 'none')")
    if "implicit" in o.grant_types:
        o.weak.append("implicit grant is offered, which is deprecated and leaks tokens via the URL")
    if "password" in o.grant_types:
        o.weak.append("resource owner password grant is offered, which invites credential stuffing")
    return o


INTROSPECTION_QUERY = {
    "query": "query{__schema{queryType{name} types{name}}}"
}


@dataclass
class GraphQLSummary:
    introspection: bool = False
    type_count: int = 0
    note: str = ""


def summarise_graphql(text: str) -> GraphQLSummary:
    g = GraphQLSummary()
    doc = parse_document(text, "json")
    if not doc:
        return g
    if doc.get("errors") and not doc.get("data"):
        g.note = "responds to GraphQL but introspection is disabled or rejected"
        return g
    schema = ((doc.get("data") or {}).get("__schema")) or {}
    if schema:
        g.introspection = True
        types = schema.get("types")
        g.type_count = len(types) if isinstance(types, list) else 0
    return g
