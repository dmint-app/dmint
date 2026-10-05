"""Agent transport authentication and identity binding for Dmint MCP."""

from __future__ import annotations

from contextvars import ContextVar
import hmac
from typing import Mapping

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from dmint.errors import RequestValidationError
from dmint.models import validate_text
from .errors import MCPConfigurationError

# ContextVar holding the authoritative bound agent_id for the current request
CURRENT_AGENT_ID: ContextVar[str | None] = ContextVar("current_agent_id", default=None)

DEFAULT_MAX_REQUEST_BODY_SIZE = 4 * 1024 * 1024  # 4 MB


class AgentAuthenticator:
    """Authenticates inbound agent transport credentials and binds identity.

    Uses constant-time comparison (hmac.compare_digest) to verify tokens,
    preventing timing attacks. Maps valid tokens to authoritative agent_id strings.
    """

    def __init__(
        self,
        token_mapping: Mapping[str, str] | None = None,
        *,
        single_token: str | None = None,
        default_agent_id: str = "mcp-agent",
    ) -> None:
        self._token_to_agent: dict[str, str] = {}

        if single_token is not None:
            if not isinstance(single_token, str) or not single_token.strip():
                raise MCPConfigurationError("single_token must be a non-empty string")
            clean_token = single_token.strip()
            try:
                valid_agent = validate_text(default_agent_id, "agent_id")
            except (RequestValidationError, TypeError) as exc:
                raise MCPConfigurationError("invalid default_agent_id") from exc
            self._token_to_agent[clean_token] = valid_agent

        if token_mapping is not None:
            if not isinstance(token_mapping, Mapping):
                raise MCPConfigurationError("token_mapping must be a mapping of token to agent_id")
            for token, agent_id in token_mapping.items():
                if not isinstance(token, str) or not token.strip():
                    raise MCPConfigurationError("token in token_mapping must be a non-empty string")
                clean_token = token.strip()
                try:
                    valid_agent = validate_text(agent_id, "agent_id")
                except (RequestValidationError, TypeError) as exc:
                    raise MCPConfigurationError("invalid agent_id in token_mapping") from exc
                self._token_to_agent[clean_token] = valid_agent

    @property
    def has_tokens(self) -> bool:
        """Whether at least one authentication token is configured."""
        return bool(self._token_to_agent)

    @property
    def configured_agents(self) -> list[str]:
        """List of configured agent IDs."""
        return sorted(set(self._token_to_agent.values()))

    def authenticate(self, candidate_token: str | None) -> str | None:
        """Verify candidate token against configured credentials in constant time.

        Returns the authoritative agent_id on match, or None on failure.
        """
        if not isinstance(candidate_token, str) or not candidate_token:
            return None

        clean_candidate = candidate_token.strip()
        matched_agent: str | None = None

        # Constant-time comparison across all tokens
        for token, agent_id in self._token_to_agent.items():
            if hmac.compare_digest(token, clean_candidate):
                matched_agent = agent_id

        return matched_agent

    def authenticate_header(self, auth_header: str | None) -> str | None:
        """Parse HTTP Authorization header and authenticate bearer token.

        Accepts header of the form: 'Bearer <token>'.
        Returns authoritative agent_id on success, or None on failure.
        """
        if not isinstance(auth_header, str) or not auth_header.strip():
            return None

        parts = auth_header.strip().split()
        if len(parts) != 2:
            return None

        scheme, token = parts
        if scheme.lower() != "bearer":
            return None

        return self.authenticate(token)

    @classmethod
    def from_spec(
        cls,
        spec: str,
        *,
        default_agent_id: str = "mcp-agent",
    ) -> AgentAuthenticator:
        """Construct an AgentAuthenticator from a CLI/environment token specification.

        Supported syntax:
        - Single token: 'secret_key_123' (binds to default_agent_id)
        - Multi-token mapping: 'tokenA=agent1,tokenB=agent2'
        """
        if not isinstance(spec, str) or not spec.strip():
            raise MCPConfigurationError("auth token specification cannot be empty")

        clean_spec = spec.strip()
        if "=" not in clean_spec:
            return cls(single_token=clean_spec, default_agent_id=default_agent_id)

        mapping: dict[str, str] = {}
        pairs = clean_spec.split(",")
        for pair in pairs:
            clean_pair = pair.strip()
            if not clean_pair:
                continue
            if "=" not in clean_pair:
                raise MCPConfigurationError(f"invalid token pair '{clean_pair}', expected 'token=agent_id'")
            token, _, agent = clean_pair.partition("=")
            token = token.strip()
            agent = agent.strip()
            if not token or not agent:
                raise MCPConfigurationError(f"empty token or agent_id in '{clean_pair}'")
            mapping[token] = agent

        if not mapping:
            raise MCPConfigurationError("no valid token pairs found in specification")

        return cls(token_mapping=mapping, default_agent_id=default_agent_id)


class AgentAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware enforcing transport authentication and request limits.

    - Validates Bearer token in HTTP Authorization header before any request reaches
      the MCP handler or Core authorization engine.
    - Rejects unauthorized requests immediately with HTTP 401 Unauthorized.
    - Enforces maximum request body size (HTTP 413 Payload Too Large).
    - Sets authoritative agent identity in request.state and ContextVar.
    - Sanitizes internal unhandled errors at the ASGI boundary (HTTP 500).
    - Never leaks tokens, stack traces, paths, or SQLite errors in responses.
    """

    def __init__(
        self,
        app: ASGIApp,
        authenticator: AgentAuthenticator | None = None,
        *,
        default_agent_id: str = "mcp-agent",
        max_request_body_size: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
    ) -> None:
        super().__init__(app)
        self.authenticator = authenticator
        self.default_agent_id = default_agent_id
        self.max_request_body_size = max_request_body_size

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # 1. Enforce payload size limit from Content-Length header
        content_length_header = request.headers.get("content-length")
        if content_length_header is not None:
            try:
                cl = int(content_length_header)
                if cl > self.max_request_body_size:
                    return JSONResponse(
                        {
                            "error": "payload_too_large",
                            "message": f"Request body exceeds maximum permitted size of {self.max_request_body_size} bytes",
                        },
                        status_code=413,
                    )
            except ValueError:
                pass

        # 2. Enforce Bearer authentication if authenticator is configured
        if self.authenticator is not None and self.authenticator.has_tokens:
            auth_header = request.headers.get("authorization")
            agent_id = self.authenticator.authenticate_header(auth_header)
            if agent_id is None:
                return JSONResponse(
                    {
                        "error": "unauthorized",
                        "message": "Missing or invalid authorization token",
                    },
                    status_code=401,
                    headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            effective_agent_id = agent_id
        else:
            effective_agent_id = self.default_agent_id

        # 3. Bind authoritative identity to request state and contextvar
        request.state.agent_id = effective_agent_id
        request.scope["agent_id"] = effective_agent_id
        token = CURRENT_AGENT_ID.set(effective_agent_id)

        try:
            return await call_next(request)
        except Exception:
            # Catch unhandled exceptions at the ASGI boundary; never leak stack traces
            return JSONResponse(
                {
                    "error": "internal_error",
                    "message": "An internal server error occurred",
                },
                status_code=500,
            )
        finally:
            CURRENT_AGENT_ID.reset(token)
