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

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "[::1]"})


def create_app(
    core_client: CoreClient,
    *,
    auth_token: str | None = None,
    token_file: str | Path | None = None,
    allowed_hosts: Collection[str] | None = None,
    approver_id: str | None = None,
    trusted_proxy: bool | None = None,
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
    from .auth import LoginRateLimiter, load_token_from_file

    effective_token: str
    if token_file:
        effective_token = load_token_from_file(token_file)
    elif auth_token:
        effective_token = auth_token
    elif os.environ.get("DMINT_DASHBOARD_TOKEN_FILE"):
        effective_token = load_token_from_file(os.environ["DMINT_DASHBOARD_TOKEN_FILE"])
    else:
        effective_token = (
            os.environ.get("DMINT_DASHBOARD_TOKEN")
            or os.environ.get("DMINT_DASHBOARD_PASSWORD")
            or secrets.token_urlsafe(32)
        )

    # 2. Configure Host header allowlist (for DNS rebinding defense)
    hosts: set[str] = set(DEFAULT_ALLOWED_HOSTS)
    if allowed_hosts:
        for h in allowed_hosts:
            if h and h not in ("0.0.0.0", "::"):
                hosts.add(h.strip().lower())

    # Configure approver identity (no shared constant)
    configured_approver_id = (
        approver_id
        or os.environ.get("DMINT_APPROVER_ID")
        or getattr(core_client, "approver_id", None)
        or "dashboard-approver"
    )

    # Trusted proxy setting: defaults to False (off)
    is_trusted_proxy = (
        trusted_proxy
        if trusted_proxy is not None
        else (os.environ.get("DMINT_DASHBOARD_TRUSTED_PROXY", "").lower() in ("1", "true", "yes"))
    )

    # Store state on app
    app.state.core_client = core_client
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.state.auth_token = effective_token
    app.state.sessions = {}
    app.state.allowed_hosts = hosts
    app.state.rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0)
    app.state.approver_id = configured_approver_id
    app.state.trusted_proxy = is_trusted_proxy

    # Security Middleware
    @app.middleware("http")
    async def security_middleware(request: Request, call_next) -> Response:
        # A. Host header validation (DNS rebinding defense) — applies to ALL requests, including Bearer
        raw_host = request.headers.get("host", "").strip()
        if not raw_host:
            resp = Response("Missing Host header", status_code=400)
            _add_security_headers(resp)
            return resp

        # Parse host component (supporting IPv6 [::1]:8080)
        if raw_host.startswith("[") and "]" in raw_host:
            host_name = raw_host[: raw_host.index("]") + 1].lower()
        else:
            host_name = raw_host.split(":")[0].lower()

        if host_name not in app.state.allowed_hosts:
            resp = Response("Invalid Host header (DNS rebinding protection)", status_code=400)
            _add_security_headers(resp)
            return resp

        # Determine effective scheme
        effective_scheme = (
            request.headers.get("x-forwarded-proto", "").lower()
            if app.state.trusted_proxy and request.headers.get("x-forwarded-proto")
            else request.url.scheme
        )
        if effective_scheme not in ("http", "https"):
            effective_scheme = request.url.scheme

        # Compute full dashboard expected origin (e.g. "http://localhost:8080" or "http://testserver")
        expected_origin = f"{effective_scheme}://{raw_host}".rstrip("/").lower()

        # B. Origin / Referer validation on state-changing POST requests
        auth_header = request.headers.get("authorization", "")
        is_bearer = False
        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header[7:].strip()
            if secrets.compare_digest(bearer_token, app.state.auth_token):
                is_bearer = True

        if request.method in ("POST", "PUT", "DELETE", "PATCH") and not is_bearer:
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")

            # Must have at least Origin or Referer from browser
            if not origin and not referer:
                resp = JSONResponse(
                    {"error": "missing_origin_referer", "detail": "Missing Origin and Referer headers."},
                    status_code=403,
                )
                _add_security_headers(resp)
                return resp

            if origin:
                # Compare full origin (scheme + host + port)
                parsed_origin = urllib.parse.urlparse(origin)
                norm_origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}".rstrip("/").lower()
                if norm_origin != expected_origin:
                    resp = JSONResponse(
                        {"error": "invalid_origin", "detail": "Cross-origin request rejected."},
                        status_code=403,
                    )
                    _add_security_headers(resp)
                    return resp
            elif referer:
                parsed_ref = urllib.parse.urlparse(referer)
                ref_origin = f"{parsed_ref.scheme}://{parsed_ref.netloc}".rstrip("/").lower()
                if ref_origin != expected_origin:
                    resp = JSONResponse(
                        {"error": "invalid_referer", "detail": "Cross-origin request rejected."},
                        status_code=403,
                    )
                    _add_security_headers(resp)
                    return resp

        # C. Authentication check on protected routes
        path = request.url.path
        if path not in ("/login", "/health", "/favicon.ico") and not path.startswith("/static"):
            session_cookie = request.cookies.get("dmint_session")
            session = None
            if session_cookie and session_cookie in app.state.sessions:
                sess_data = app.state.sessions[session_cookie]
                import time

                now = time.time()
                # Check both hard expiration (12h) and idle expiration (30m)
                is_expired = False
                if sess_data.get("expires_at", 0) <= now:
                    is_expired = True
                elif sess_data.get("last_active", 0) + (30 * 60) <= now:
                    is_expired = True

                if is_expired:
                    app.state.sessions.pop(session_cookie, None)
                else:
                    # Update activity timestamp on active session
                    sess_data["last_active"] = now
                    session = sess_data

            if is_bearer:
                session = {"identity": "bearer-api", "csrf_token": "api"}

            if not session:
                if path.startswith("/api/") or "application/json" in request.headers.get("accept", ""):
                    resp = JSONResponse(
                        {"error": "unauthorized", "detail": "Authentication required."},
                        status_code=401,
                    )
                    _add_security_headers(resp)
                    return resp
                next_param = urllib.parse.quote(path)
                resp = RedirectResponse(f"/login?next={next_param}", status_code=303)
                _add_security_headers(resp)
                return resp

            request.state.session = session

        response = await call_next(request)
        _add_security_headers(response)
        return response

    # Static files (CSS, SVG).
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Include all HTTP routes.
    app.include_router(build_router())

    return app


def _add_security_headers(response: Response) -> None:
    """Add defensive security headers to all HTTP responses."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
