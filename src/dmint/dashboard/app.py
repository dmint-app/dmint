"""FastAPI application factory for Dmint Dashboard."""

from __future__ import annotations

import os
import secrets
import urllib.parse
from collections.abc import Collection
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from dmint.version import __version__
from .core_client import CoreClient
from .routes import build_router

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "[::1]", "testserver"})


def create_app(
    core_client: CoreClient,
    *,
    auth_token: str | None = None,
    allowed_hosts: Collection[str] | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    The core_client is injected so tests can supply a test-specific store
    without touching real files.
    """
    if not isinstance(core_client, CoreClient):
        raise TypeError("core_client must be a CoreClient")

    app = FastAPI(
        title="Dmint Dashboard",
        description="Local human approval dashboard for Dmint",
        version=__version__,
        docs_url=None,  # no interactive docs in dashboard
        redoc_url=None,
    )

    # 1. Configure authentication token
    effective_token = (
        auth_token
        or os.environ.get("DMINT_DASHBOARD_TOKEN")
        or os.environ.get("DMINT_DASHBOARD_PASSWORD")
        or secrets.token_urlsafe(32)
    )

    # 2. Configure Host header allowlist (for DNS rebinding defense)
    hosts: set[str] = set(DEFAULT_ALLOWED_HOSTS)
    if allowed_hosts:
        for h in allowed_hosts:
            if h and h not in ("0.0.0.0", "::"):
                hosts.add(h.strip().lower())

    # Store state on app
    app.state.core_client = core_client
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.state.auth_token = effective_token
    app.state.sessions = {}
    app.state.allowed_hosts = hosts

    # Security Middleware
    @app.middleware("http")
    async def security_middleware(request: Request, call_next) -> Response:
        # A. Host header validation (DNS rebinding defense)
        raw_host = request.headers.get("host", "").strip()
        if not raw_host:
            return Response("Missing Host header", status_code=400)

        # Parse host component (supporting IPv6 [::1]:8080)
        if raw_host.startswith("[") and "]" in raw_host:
            host_name = raw_host[: raw_host.index("]") + 1].lower()
        else:
            host_name = raw_host.split(":")[0].lower()

        if host_name not in app.state.allowed_hosts:
            return Response("Invalid Host header (DNS rebinding protection)", status_code=400)

        # B. Origin / Referer validation on state-changing POST requests
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin:
                parsed_origin = urllib.parse.urlparse(origin)
                origin_host = (parsed_origin.hostname or "").lower()
                if origin_host not in app.state.allowed_hosts:
                    return JSONResponse(
                        {"error": "invalid_origin", "detail": "Cross-origin request rejected."},
                        status_code=403,
                    )
            elif request.headers.get("referer"):
                parsed_ref = urllib.parse.urlparse(request.headers["referer"])
                ref_host = (parsed_ref.hostname or "").lower()
                if ref_host not in app.state.allowed_hosts:
                    return JSONResponse(
                        {"error": "invalid_referer", "detail": "Cross-origin request rejected."},
                        status_code=403,
                    )

        # C. Authentication check on protected routes
        path = request.url.path
        if path not in ("/login", "/health", "/favicon.ico") and not path.startswith("/static"):
            session_cookie = request.cookies.get("dmint_session")
            session = app.state.sessions.get(session_cookie) if session_cookie else None

            # Support Bearer token header for programmatic access
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                bearer_token = auth_header[7:].strip()
                if secrets.compare_digest(bearer_token, app.state.auth_token):
                    session = {"identity": "bearer-api", "csrf_token": "api"}

            if not session:
                if path.startswith("/api/") or "application/json" in request.headers.get("accept", ""):
                    return JSONResponse(
                        {"error": "unauthorized", "detail": "Authentication required."},
                        status_code=401,
                    )
                next_param = urllib.parse.quote(path)
                return RedirectResponse(f"/login?next={next_param}", status_code=303)

            request.state.session = session

        return await call_next(request)

    # Static files (CSS, SVG).
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Include all HTTP routes.
    app.include_router(build_router())

    return app
