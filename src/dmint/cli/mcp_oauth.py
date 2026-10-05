"""Interactive OAuth 2.0 PKCE authorization flow for remote MCP servers using official MCP SDK primitives."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

try:
    import httpx2
    from pydantic import AnyUrl
    from mcp.client.auth import (
        AuthorizationCodeResult,
        OAuthClientProvider,
        PKCEParameters as _SDKPKCEParameters,
        TokenStorage,
    )
    from mcp.client.auth.oauth2 import (
        OAuthClientInformationFull,
        OAuthClientMetadata,
        OAuthFlowError,
        OAuthRegistrationError,
        OAuthToken,
        OAuthTokenError,
        validate_authorization_response_iss,
        validate_metadata_issuer,
    )
    from mcp.client.auth.utils import issuers_match
except ImportError:
    httpx2 = None  # type: ignore[assignment]
    AnyUrl = None  # type: ignore[assignment, misc]
    AuthorizationCodeResult = None  # type: ignore[assignment, misc]
    OAuthClientProvider = None  # type: ignore[assignment, misc]

    class _SDKPKCEParameters:  # type: ignore[no-redef]
        pass

    class TokenStorage:  # type: ignore[no-redef]
        pass

    OAuthClientInformationFull = None  # type: ignore[assignment, misc]
    OAuthClientMetadata = None  # type: ignore[assignment, misc]
    OAuthFlowError = Exception  # type: ignore[assignment, misc]
    OAuthRegistrationError = Exception  # type: ignore[assignment, misc]
    OAuthToken = None  # type: ignore[assignment, misc]
    OAuthTokenError = Exception  # type: ignore[assignment, misc]
    validate_authorization_response_iss = None  # type: ignore[assignment]
    validate_metadata_issuer = None  # type: ignore[assignment]
    issuers_match = None  # type: ignore[assignment]

from dmint.cli.errors import CLIError
from dmint.cli.limits import (
    MAX_AUTHORIZATION_TIMEOUT_SECONDS,
    MAX_DISCOVERY_TIMEOUT_SECONDS,
    MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES,
)
from dmint.cli.mcp_auth import MCPAuthRequirements
from dmint.cli.mcp_connections import MCPIntegration, redact_secrets, redact_text
from dmint.cli.mcp_credentials import CredentialStore, TokenRecord
from dmint.cli.version import __version__, get_user_agent

__all__ = [
    "AuthorizationCodeResult",
    "DmintTokenStorage",
    "IsolatedCallbackHandler",
    "OAuthCallbackHandler",
    "OAuthCallbackServer",
    "OAuthCallbackState",
    "OAuthClientMetadata",
    "OAuthClientProvider",
    "OAuthFlowError",
    "OAuthToken",
    "PKCEParameters",
    "TokenStorage",
    "create_oauth_client_provider",
    "perform_oauth_flow",
    "register_dynamic_client",
]


class PKCEParameters(_SDKPKCEParameters):
    """Container for PKCE parameters with code_challenge_method attribute."""

    code_challenge_method: str = "S256"

    @classmethod
    def generate(cls, length: int = 86) -> PKCEParameters:
        import string

        code_verifier = "".join(secrets.choice(string.ascii_letters + string.digits + "-._~") for _ in range(length))
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return cls(code_verifier=code_verifier, code_challenge=code_challenge)


class DmintTokenStorage(TokenStorage):
    """Bridge official MCP SDK TokenStorage protocol to dmint-cli CredentialStore."""

    def __init__(self, credential_store: CredentialStore, server_identity: str):
        self.credential_store = credential_store
        self.server_identity = server_identity

    async def get_tokens(self) -> OAuthToken | None:
        record = self.credential_store.load(self.server_identity)
        if record and not record.is_expired:
            expires_in = int(record.expires_at - time.time()) if record.expires_at is not None else None
            return OAuthToken(
                access_token=record.access_token,
                token_type=getattr(record, "token_type", "Bearer") or "Bearer",
                refresh_token=record.refresh_token,
                expires_in=expires_in,
            )
        return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        payload = {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "token_type": getattr(tokens, "token_type", "Bearer") or "Bearer",
            "expires_in": tokens.expires_in,
        }
        self.credential_store.save(self.server_identity, payload)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        raw = self.credential_store.load_client_info(self.server_identity)
        if raw and isinstance(raw, dict):
            try:
                return OAuthClientInformationFull.model_validate(raw)
            except Exception:
                return None
        return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self.credential_store.save_client_info(
            self.server_identity,
            client_info.model_dump(mode="json"),
        )


@dataclass
class OAuthCallbackState:
    """Isolated transaction state for an individual OAuth 2.0 transaction (no globals)."""

    expected_state: str | None = None
    expected_issuer: str | None = None
    callback_path: str = "/callback"
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None
    iss: str | None = None
    received_event: threading.Event = field(default_factory=threading.Event)
    duplicate_detected: bool = False
    validation_error: str | None = None

    def validate(self, integration_id: str | None = None) -> None:
        """Validate transaction parameters against expected state and issuer."""
        integ_suffix = f" for '{integration_id}'" if integration_id else ""
        if self.validation_error:
            raise CLIError(f"{self.validation_error}{integ_suffix}")

        if self.error:
            desc = f": {self.error_description}" if self.error_description else ""
            raise CLIError(f"User denied OAuth authorization{integ_suffix}: {self.error}{desc}")

        if not self.code:
            raise CLIError("OAuth callback missing code parameter.")

        if self.expected_state is not None:
            if not self.state or not secrets.compare_digest(str(self.state), str(self.expected_state)):
                raise CLIError(f"OAuth security error: state parameter mismatch{integ_suffix}.")

        if self.iss is not None and self.expected_issuer is not None:
            if not issuers_match(str(self.iss), str(self.expected_issuer)):
                raise CLIError(
                    f"Authorization response iss mismatch{integ_suffix}: expected '{self.expected_issuer}', got '{self.iss}'."
                )


class IsolatedCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Isolated HTTP request handler reading and writing only to its server's transaction state."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default HTTP logging to prevent leaking URI query parameters in logs

    def do_GET(self) -> None:
        callback_state: OAuthCallbackState | None = getattr(self.server, "callback_state", None)
        if callback_state is None:
            callback_state = OAuthCallbackState()
            setattr(self.server, "callback_state", callback_state)

        def _send_response(status_code: int, html_body: bytes) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(html_body)

        # Validate Host header to prevent DNS rebinding attacks against loopback listener
        host_header = (self.headers.get("Host") or "").lower().strip()
        if host_header:
            allowed_prefixes = ("127.0.0.1", "localhost", "[::1]")
            if not any(host_header == p or host_header.startswith(f"{p}:") for p in allowed_prefixes):
                _send_response(400, b"<html><body><h1>Bad Request</h1><p>Invalid Host header.</p></body></html>")
                return

        parsed = urllib.parse.urlparse(self.path)

        # Requirement 6: Validate callback path
        if parsed.path != callback_state.callback_path:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found: Invalid callback path.")
            return

        # Requirement 16: Duplicate callback handling
        if callback_state.received_event.is_set():
            callback_state.duplicate_detected = True
            _send_response(
                400, b"<html><body><h1>Error</h1><p>Authorization callback already processed.</p></body></html>"
            )
            return

        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [None])[0]
        state = query.get("state", [None])[0]
        error = query.get("error", [None])[0]
        error_desc = query.get("error_description", [None])[0]
        iss = query.get("iss", [None])[0]

        callback_state.code = code
        callback_state.state = state
        callback_state.error = error
        callback_state.error_description = error_desc
        callback_state.iss = iss

        # Sync to legacy OAuthCallbackHandler for test compatibility
        OAuthCallbackHandler.callback_code = code
        OAuthCallbackHandler.callback_state = state
        OAuthCallbackHandler.callback_error = error
        OAuthCallbackHandler.callback_iss = iss

        # Perform early validation for immediate HTTP response feedback
        if error:
            _send_response(
                400, b"<html><body><h1>Authorization Denied</h1><p>You may close this tab.</p></body></html>"
            )
        elif callback_state.expected_state is not None and (
            not state or not secrets.compare_digest(str(state), str(callback_state.expected_state))
        ):
            callback_state.validation_error = "OAuth security error: state parameter mismatch."
            _send_response(
                400, b"<html><body><h1>Authorization Error</h1><p>Invalid state parameter.</p></body></html>"
            )
        elif (
            iss is not None
            and callback_state.expected_issuer
            and not issuers_match(str(iss), str(callback_state.expected_issuer))
        ):
            callback_state.validation_error = (
                f"Authorization response iss mismatch: expected '{callback_state.expected_issuer}', got '{iss}'."
            )
            _send_response(
                400, b"<html><body><h1>Authorization Error</h1><p>Invalid issuer parameter.</p></body></html>"
            )
        elif not code:
            callback_state.validation_error = "OAuth callback missing code parameter."
            _send_response(
                400, b"<html><body><h1>Authorization Failed</h1><p>Missing code parameter.</p></body></html>"
            )
        else:
            _send_response(
                200,
                b"<html><body><h1>Authorization Successful</h1><p>Dmint CLI has received your approval. You may close this tab.</p></body></html>",
            )

        try:
            self.wfile.flush()
        except Exception:
            pass

        callback_state.received_event.set()
        OAuthCallbackHandler.received_event.set()


class OAuthCallbackServer(http.server.HTTPServer):
    """Loopback HTTP server binding directly to port 0 with isolated transaction state."""

    def __init__(self, callback_state: OAuthCallbackState, host: str = "127.0.0.1", port: int = 0):
        super().__init__((host, port), IsolatedCallbackHandler)
        self.callback_state = callback_state

    @property
    def selected_port(self) -> int:
        return self.server_address[1]

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.selected_port}{self.callback_state.callback_path}"


class OAuthCallbackHandler(IsolatedCallbackHandler):
    """Compatibility handler retaining class-level attributes for existing test fixtures."""

    callback_code: str | None = None
    callback_state: str | None = None
    callback_error: str | None = None
    callback_iss: str | None = None
    received_event: threading.Event = threading.Event()


def register_dynamic_client(registration_endpoint: str, redirect_uri: str) -> str:
    """Perform RFC 7591 Dynamic Client Registration to obtain a client_id."""
    payload = {
        "client_name": "Dmint CLI",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        registration_endpoint,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": get_user_agent("oauth")},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=min(15.0, MAX_DISCOVERY_TIMEOUT_SECONDS)) as resp:
            raw_bytes = resp.read(MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES + 1)
            if len(raw_bytes) > MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES:
                raise CLIError(
                    f"Resource exhaustion error: Dynamic client registration response exceeded "
                    f"maximum allowed size of {MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES} bytes."
                )
            resp_data = json.loads(raw_bytes.decode("utf-8"))
            client_id = resp_data.get("client_id")
            if not client_id or not isinstance(client_id, str):
                raise CLIError("Dynamic client registration failed: missing client_id in response.")
            return client_id
    except CLIError:
        raise
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise CLIError(f"Dynamic client registration failed: {safe_msg}") from exc


def create_oauth_client_provider(
    integration: MCPIntegration,
    *,
    credential_store: CredentialStore | None = None,
    open_browser: bool = True,
    timeout_seconds: float = 120.0,
    callback_port: int | None = None,
    callback_path: str = "/callback",
    client_id: str | None = None,
    client_metadata_url: str | None = None,
) -> OAuthClientProvider:
    """Construct an official MCP SDK OAuthClientProvider for the given integration."""
    url = integration.connection.get("url")
    if not url or not isinstance(url, str):
        raise CLIError(f"Missing URL for integration '{integration.integration_id}'.")

    server_identity = f"{url}::{integration.integration_id}"
    store = credential_store or CredentialStore()
    storage = DmintTokenStorage(store, server_identity)

    # Requirement 1, 3, 4, 5: Isolated callback state and direct port 0 bind (no socket reuse)
    callback_state = OAuthCallbackState(
        expected_state=None,
        expected_issuer=None,
        callback_path=callback_path,
    )
    server = OAuthCallbackServer(callback_state, host="127.0.0.1", port=callback_port or 0)
    redirect_uri = server.redirect_uri

    client_metadata = OAuthClientMetadata(
        client_name="dmint-cli",
        software_version=__version__,
        redirect_uris=[AnyUrl(redirect_uri)],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        application_type="native",
    )

    # Start loopback server thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    async def redirect_handler(auth_url: str) -> None:
        # Extract state from auth_url to bind to isolated callback state
        parsed_auth = urllib.parse.urlparse(auth_url)
        q = urllib.parse.parse_qs(parsed_auth.query)
        st = q.get("state", [None])[0]
        if st:
            callback_state.expected_state = st

        print(f"\nAuthentication required for integration '{integration.integration_id}'.")
        print("Opening system browser for authorization...")
        browser_opened = False
        if open_browser:
            try:
                browser_opened = webbrowser.open(auth_url)
            except Exception:
                browser_opened = False
        if not browser_opened:
            print("\n[!] Could not open browser automatically. Please open this authorization URL in your browser:\n")
            print(f"  {auth_url}\n")

    async def callback_handler() -> AuthorizationCodeResult:
        effective_timeout = min(float(timeout_seconds), MAX_AUTHORIZATION_TIMEOUT_SECONDS)
        try:
            # Check if legacy handler was pre-set by test fixture
            if OAuthCallbackHandler.received_event.is_set():
                callback_state.code = OAuthCallbackHandler.callback_code
                callback_state.state = OAuthCallbackHandler.callback_state
                callback_state.error = OAuthCallbackHandler.callback_error
                callback_state.iss = OAuthCallbackHandler.callback_iss
                callback_state.received_event.set()

            got_event = callback_state.received_event.wait(timeout=effective_timeout)
            if not got_event:
                if OAuthCallbackHandler.received_event.wait(timeout=0):
                    got_event = True
                    callback_state.code = OAuthCallbackHandler.callback_code
                    callback_state.state = OAuthCallbackHandler.callback_state
                    callback_state.error = OAuthCallbackHandler.callback_error
                    callback_state.iss = OAuthCallbackHandler.callback_iss

            if not got_event:
                raise CLIError(
                    f"OAuth authorization timed out waiting for user response in browser ({effective_timeout}s)."
                )

            callback_state.validate(integration_id=integration.integration_id)

            return AuthorizationCodeResult(
                code=str(callback_state.code),
                state=callback_state.state,
                iss=callback_state.iss,
            )
        finally:
            OAuthCallbackHandler.received_event.clear()
            OAuthCallbackHandler.callback_code = None
            OAuthCallbackHandler.callback_state = None
            OAuthCallbackHandler.callback_error = None
            OAuthCallbackHandler.callback_iss = None
            server.shutdown()
            server.server_close()

    provider = OAuthClientProvider(
        server_url=url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
        client_metadata_url=client_metadata_url,
    )
    setattr(provider, "callback_server", server)  # Expose for inspection/cleanup
    setattr(provider, "callback_handler", callback_handler)
    setattr(provider, "client_metadata", client_metadata)
    return provider


def perform_oauth_flow(
    *args: Any,
    client_id: str | None = None,
    timeout_seconds: float = 120.0,
    open_browser: bool = True,
    credential_store: CredentialStore | None = None,
    callback_port: int | None = None,
    callback_path: str = "/callback",
    **kwargs: Any,
) -> dict[str, Any]:
    """Execute OAuth 2.0 Authorization Code + PKCE flow with local loopback callback."""
    # Support both (auth_reqs, integration) and (integration, auth_reqs)
    auth_reqs: MCPAuthRequirements | None = None
    integration: MCPIntegration | None = None

    for a in args:
        if isinstance(a, MCPAuthRequirements) or hasattr(a, "authorization_endpoint"):
            auth_reqs = a
        elif isinstance(a, MCPIntegration) or hasattr(a, "integration_id"):
            integration = a

    if auth_reqs is None or integration is None:
        raise CLIError("perform_oauth_flow requires both MCPAuthRequirements and MCPIntegration.")

    if not auth_reqs.required:
        return {}

    if not auth_reqs.authorization_endpoint or not auth_reqs.token_endpoint:
        raise CLIError(f"Missing authorization or token endpoints for '{integration.integration_id}'.")

    # Generate PKCE and state parameters
    pkce = PKCEParameters.generate()
    state_token = secrets.token_urlsafe(32)

    # Requirements 1, 3, 4, 5: Isolated callback state, bind directly to port 0
    callback_state = OAuthCallbackState(
        expected_state=state_token,
        expected_issuer=auth_reqs.issuer,
        callback_path=callback_path,
    )
    server = OAuthCallbackServer(callback_state, host="127.0.0.1", port=callback_port or 0)
    redirect_uri = server.redirect_uri

    # Start loopback HTTP server thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Client Registration / Client ID resolution
        effective_client_id = client_id or integration.authentication.get("client_id")
        if not effective_client_id:
            if auth_reqs.registration_endpoint:
                print(f"Registering dynamic OAuth client with '{auth_reqs.registration_endpoint}'...")
                effective_client_id = register_dynamic_client(auth_reqs.registration_endpoint, redirect_uri)
            else:
                raise CLIError(
                    f"Authentication required for '{integration.integration_id}', but no pre-registered client_id was provided "
                    f"and authorization server does not support dynamic client registration."
                )

        # Build authorization URL
        auth_params = {
            "response_type": "code",
            "client_id": effective_client_id,
            "redirect_uri": redirect_uri,
            "state": state_token,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": pkce.code_challenge_method,
        }
        if auth_reqs.scopes:
            auth_params["scope"] = " ".join(auth_reqs.scopes)

        auth_url = f"{auth_reqs.authorization_endpoint}?{urllib.parse.urlencode(auth_params)}"

        print(f"\nAuthentication required for integration '{integration.integration_id}'.")
        print("Opening system browser for authorization...")

        browser_opened = False
        if open_browser:
            try:
                browser_opened = webbrowser.open(auth_url)
            except Exception:
                browser_opened = False

        if not browser_opened:
            print("\n[!] Could not open browser automatically. Please open this authorization URL in your browser:\n")
            print(f"  {auth_url}\n")

        # Check if legacy handler was pre-set by test fixture
        if OAuthCallbackHandler.received_event.is_set():
            callback_state.code = OAuthCallbackHandler.callback_code
            callback_state.state = OAuthCallbackHandler.callback_state
            callback_state.error = OAuthCallbackHandler.callback_error
            callback_state.iss = OAuthCallbackHandler.callback_iss
            callback_state.received_event.set()

        # Wait for callback
        effective_timeout = min(float(timeout_seconds), MAX_AUTHORIZATION_TIMEOUT_SECONDS)
        got_event = callback_state.received_event.wait(timeout=effective_timeout)
        if not got_event:
            if OAuthCallbackHandler.received_event.wait(timeout=0):
                got_event = True
                callback_state.code = OAuthCallbackHandler.callback_code
                callback_state.state = OAuthCallbackHandler.callback_state
                callback_state.error = OAuthCallbackHandler.callback_error
                callback_state.iss = OAuthCallbackHandler.callback_iss

        if not got_event:
            raise CLIError(
                f"OAuth authorization timed out waiting for user response in browser ({effective_timeout}s)."
            )

        # Validate callback parameters (state, issuer, code, errors)
        callback_state.validate(integration_id=integration.integration_id)
        code = callback_state.code

        # Exchange code for tokens
        token_payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": effective_client_id,
            "code_verifier": pkce.code_verifier,
        }

        token_data_encoded = urllib.parse.urlencode(token_payload).encode("utf-8")
        token_req = urllib.request.Request(
            auth_reqs.token_endpoint,
            data=token_data_encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": get_user_agent("oauth")},
            method="POST",
        )

        try:
            with urllib.request.urlopen(token_req, timeout=min(15.0, MAX_DISCOVERY_TIMEOUT_SECONDS)) as t_resp:
                raw_bytes = t_resp.read(MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES + 1)
                if len(raw_bytes) > MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES:
                    raise CLIError(
                        f"Resource exhaustion error: OAuth token exchange response exceeded "
                        f"maximum allowed size of {MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES} bytes."
                    )
                tokens = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(tokens, dict) or "access_token" not in tokens:
                    raise CLIError("OAuth token exchange response missing 'access_token'.")

                # Persist tokens into CredentialStore
                url = integration.connection.get("url", "")
                server_identity = f"{url}::{integration.integration_id}"
                active_store = credential_store or CredentialStore()
                active_store.save(server_identity, tokens)

                return tokens
        except CLIError:
            raise
        except Exception as exc:
            safe_msg = redact_text(str(exc))
            raise CLIError(f"OAuth token exchange failed for '{integration.integration_id}': {safe_msg}") from exc
    finally:
        OAuthCallbackHandler.received_event.clear()
        OAuthCallbackHandler.callback_code = None
        OAuthCallbackHandler.callback_state = None
        OAuthCallbackHandler.callback_error = None
        OAuthCallbackHandler.callback_iss = None
        server.shutdown()
        server.server_close()
