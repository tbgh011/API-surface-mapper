"""FastAPI app: serves the static UI and the scan API from the same origin.

Serving both from one container is deliberate. The frontend then talks to
/api/... with no CORS preflight, no mixed-content warning, and no configuration
step, and the GitHub Pages copy of index.html keeps working untouched because
the server is only ever an enhancement it probes for.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import config, safety
from .engine import scan

log = logging.getLogger("mapper")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

VERSION = "1.0.0"

app = FastAPI(title="API Surface Mapper", version=VERSION, docs_url=None, redoc_url=None)

if config.ALLOWED_ORIGINS:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.ALLOWED_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    log.info("CORS enabled for %s", ", ".join(config.ALLOWED_ORIGINS))


@app.get("/api/healthz")
async def healthz() -> dict:
    return {
        "ok": True,
        "engine": "server",
        "version": VERSION,
        "scoped": bool(config.SCOPE_ALLOWLIST),
        "capabilities": [
            "certificate-transparency",
            "deep-dns",
            "cors-free-fetch",
            "spec-parsing",
            "graphql-introspection",
            "header-analysis",
        ],
    }


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


@app.get("/api/scan")
async def api_scan(request: Request, domain: str = Query(..., max_length=253)):
    """Stream scan events. GET so the browser can consume it with EventSource."""
    client = request.client.host if request.client else "unknown"
    try:
        target = safety.validate_domain(domain)
        safety.rate_limiter.check(client)
    except safety.ScanRefused as exc:
        return JSONResponse({"error": str(exc)}, status_code=429 if "Rate limit" in str(exc) else 400)

    log.info("scan %s requested by %s", target, client)

    async def stream():
        yield _sse("status", {"text": f"Server engine scanning {target}...", "pct": 2})
        try:
            async for event in scan.run_scan(target):
                if await request.is_disconnected():
                    log.info("scan %s abandoned by client", target)
                    return
                yield _sse(event["event"], event["data"])
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # a scan failing must not kill the stream silently
            log.exception("scan %s failed", target)
            yield _sse("error", {"message": f"{type(exc).__name__}: {exc}"})

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-cache, no-transform",
            "x-accel-buffering": "no",
            "connection": "keep-alive",
        },
    )


# ---- static UI -------------------------------------------------------------

_static = Path(config.STATIC_DIR or (Path(__file__).resolve().parents[2]))
if (_static / "index.html").is_file():
    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(_static / "index.html", headers={"cache-control": "no-cache"})

    app.mount("/", StaticFiles(directory=_static, html=True), name="static")
    log.info("serving the UI from %s", _static)
else:
    log.warning("no index.html under %s; running as an API-only service", _static)
