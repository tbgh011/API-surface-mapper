"""Runtime configuration, all from environment variables with local-safe defaults."""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _list(name: str) -> list[str]:
    raw = os.environ.get(name, "") or ""
    return [p.strip() for p in raw.split(",") if p.strip()]


STATIC_DIR = os.environ.get("STATIC_DIR", "")

# Domain suffixes this instance may scan. Empty list means unrestricted.
SCOPE_ALLOWLIST: list[str] = [d.lower().lstrip(".") for d in _list("SCOPE_ALLOWLIST")]

# Browser origins allowed to call the API cross-origin. Empty means same-origin
# only: no CORS middleware is installed at all.
ALLOWED_ORIGINS: list[str] = _list("ALLOWED_ORIGINS")

RATE_LIMIT_PER_MIN = _int("RATE_LIMIT_PER_MIN", 12)
MAX_HOSTS = _int("MAX_HOSTS", 400)
HTTP_CONCURRENCY = _int("HTTP_CONCURRENCY", 24)
DNS_CONCURRENCY = _int("DNS_CONCURRENCY", 32)

HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "8"))
DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", "4"))
CT_TIMEOUT = float(os.environ.get("CT_TIMEOUT", "30"))

MAX_REDIRECTS = _int("MAX_REDIRECTS", 4)
MAX_BODY_BYTES = _int("MAX_BODY_BYTES", 8_000_000)

USER_AGENT = os.environ.get(
    "USER_AGENT",
    "api-surface-mapper/1.0 (+https://github.com/tbgh011/API-surface-mapper)",
)

# Origins to run the descriptor probe against. CT can return hundreds of live
# hosts and probing every path on every one of them is neither fast nor polite.
MAX_PROBE_ORIGINS = _int("MAX_PROBE_ORIGINS", 25)
