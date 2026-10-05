"""FastAPI application factory for Dmint Dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dmint.version import __version__
from .core_client import CoreClient
from .routes import build_router

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"


def create_app(core_client: CoreClient) -> FastAPI:
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

    # Store the client and templates on app state for route access.
    app.state.core_client = core_client
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Static files (CSS).
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Include all HTTP routes.
    app.include_router(build_router())

    return app
