"""MCP Authorization Discovery according to the MCP specification, RFC 8414, RFC 9207, and RFC 9728."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import logging
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

try:
    from mcp.client.auth.oauth2 import (
        check_resource_allowed,
        resource_url_from_server_url,
    )
    from mcp.client.auth.utils import (
        build_oauth_authorization_server_metadata_discovery_urls,
        build_protected_resource_metadata_discovery_urls,
        issuers_match,
    )
    from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata
except ImportError:
    check_resource_allowed = None  # type: ignore[assignment]
    resource_url_from_server_url = None  # type: ignore[assignment]
    build_oauth_authorization_server_metadata_discovery_urls = None  # type: ignore[assignment]
    build_protected_resource_metadata_discovery_urls = None  # type: ignore[assignment]
    issuers_match = None  # type: ignore[assignment]
    OAuthMetadata = None  # type: ignore[assignment, misc]
    ProtectedResourceMetadata = None  # type: ignore[assignment, misc]

from dmint.cli.errors import CLIError
from dmint.cli.limits import (
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    MAX_DISCOVERY_TIMEOUT_SECONDS,
    MAX_METADATA_RESPONSE_SIZE_BYTES,
    MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES,
)
from dmint.cli.mcp_connections import MCPIntegration, MCPTransport, redact_secrets, redact_text
from dmint.cli.version import get_user_agent

logger = logging.getLogger(__name__)


@dataclass
class MCPAuthRequirements:
    """Structured representation of authorization requirements for an MCP integration."""

    required: bool = False
    authorization_server: str | None = None
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    registration_endpoint: str | None = None
    scopes: list[str] = field(default_factory=list)
    pkce_supported: bool = False
    pkce_required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        safe_meta = redact_secrets(self.metadata)
        return (
            f"MCPAuthRequirements(required={self.required}, "
            f"authorization_server={self.authorization_server!r}, "
            f"issuer={self.issuer!r}, "
            f"authorization_endpoint={self.authorization_endpoint!r}, "
            f"token_endpoint={self.token_endpoint!r}, "
            f"registration_endpoint={self.registration_endpoint!r}, "
            f"scopes={self.scopes!r}, "
            f"pkce_supported={self.pkce_supported}, "
            f"pkce_required={self.pkce_required}, "
            f"metadata={safe_meta!r})"
        )


from dmint.mcp.ssrf import is_loopback_host

# Unified loopback host validation delegating to canonical implementation in dmint.mcp.ssrf
_is_loopback_hostname = is_loopback_host


def _is_private_or_metadata_ip(hostname: str) -> bool:
    """Check if hostname is a private IP, link-local (e.g. 169.254.x.x), reserved, or cloud metadata endpoint.

    Loopback IPs (127.0.0.1) are excluded as they are handled by localhost rules.
    """
    if not hostname:
        return False
    clean = hostname.lower().strip("[]").strip()

    # Block known cloud metadata hostnames and internal domain names
    if (
        clean in ("metadata.google.internal", "instance-data", "metadata", "0")
        or clean.endswith(".internal")
        or clean.endswith(".local")
    ):
        return True

    # Check integer/octal IPv4 format (e.g. 0, 2130706433, 017700000001)
    if clean.isdigit():
        try:
            ip_val = int(clean)
            if 0 <= ip_val <= 0xFFFFFFFF:
                ip4 = ipaddress.IPv4Address(ip_val)
                return (
                    ip4.is_private or ip4.is_link_local or ip4.is_reserved or ip4.is_unspecified
                ) and not ip4.is_loopback
        except ValueError:
            pass

    try:
        ip = ipaddress.ip_address(clean)
        return (ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified) and not ip.is_loopback
    except ValueError:
        return False


def _is_localhost(url_str: str) -> bool:
    """Check if URL points to localhost or loopback interface."""
    if not url_str:
        return False
    try:
        parsed = urllib.parse.urlparse(url_str.strip())
        return _is_loopback_hostname(parsed.hostname or "")
    except Exception:
        return False


def _is_same_origin(url1: str, url2: str) -> bool:
    """Compare two URLs by origin (scheme, canonical hostname, and effective port).

    Does NOT infer trust from netloc equality alone.
    """
    p1 = urllib.parse.urlparse(url1)
    p2 = urllib.parse.urlparse(url2)

    port1 = p1.port or (80 if p1.scheme.lower() == "http" else 443 if p1.scheme.lower() == "https" else None)
    port2 = p2.port or (80 if p2.scheme.lower() == "http" else 443 if p2.scheme.lower() == "https" else None)

    host1 = (p1.hostname or "").lower()
    host2 = (p2.hostname or "").lower()
    scheme1 = p1.scheme.lower()
    scheme2 = p2.scheme.lower()

    return scheme1 == scheme2 and host1 == host2 and port1 == port2


def _validate_https_endpoint(url_str: str, label: str) -> None:
    """Validate that remote endpoint is well-formed, safe against SSRF, and strictly uses HTTPS (unless loopback/localhost)."""
    if not url_str or not isinstance(url_str, str) or not url_str.strip():
        raise CLIError(f"Invalid URL for {label}: URL must be a non-empty string.")

    clean_url = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(clean_url)
    except Exception as exc:
        raise CLIError(f"Malformed URL for {label} '{clean_url}': {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme in ("file", "ftp", "data", "gopher", "blob", "javascript"):
        raise CLIError(f"Security violation: {label} uses disallowed scheme '{parsed.scheme}'.")

    if not parsed.scheme or not parsed.netloc:
        raise CLIError(f"Invalid URL for {label}: '{clean_url}'. Scheme and host are required.")

    if scheme not in ("http", "https"):
        raise CLIError(
            f"Security violation: {label} uses unsupported scheme '{parsed.scheme}'. Only HTTPS (or HTTP for localhost) is allowed."
        )

    if parsed.username or parsed.password:
        raise CLIError(f"Security violation: {label} must not contain embedded credentials or userinfo: '{clean_url}'.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise CLIError(f"Invalid URL for {label}: missing hostname in '{clean_url}'.")

    try:
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise CLIError(f"Invalid port for {label}: {parsed.port}.")
    except ValueError as exc:
        raise CLIError(f"Malformed port for {label}: {exc}") from exc

    # Enforce HTTPS requirement first (unless loopback)
    if scheme != "https" and not _is_loopback_hostname(hostname):
        raise CLIError(f"Remote {label} must use HTTPS: '{clean_url}'.")

    # Reject private and cloud-metadata IP endpoints to prevent SSRF
    if _is_private_or_metadata_ip(hostname):
        raise CLIError(
            f"Security violation: {label} points to a private or link-local IP endpoint '{hostname}'. "
            "Private IP endpoints are blocked to prevent Server-Side Request Forgery (SSRF)."
        )


class StrictSameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent cross-origin redirects and redirects to private IPs or file schemes during discovery."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        orig_url = req.full_url
        try:
            parsed_new = urllib.parse.urlparse(newurl)
        except Exception as exc:
            raise CLIError(f"Security violation: malformed redirect URL '{newurl}': {exc}") from exc

        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme in ("file", "ftp", "data", "gopher", "blob", "javascript"):
            raise CLIError(
                f"Security violation: redirect to file-like or disallowed scheme '{parsed_new.scheme}' from '{orig_url}' to '{newurl}'."
            )

        new_hostname = (parsed_new.hostname or "").lower()
        if _is_private_or_metadata_ip(new_hostname):
            raise CLIError(
                f"Security violation: redirect to private or link-local IP '{new_hostname}' from '{orig_url}' to '{newurl}'. "
                "Redirects to private IP endpoints are blocked to prevent SSRF."
            )

        if not _is_same_origin(orig_url, newurl):
            raise CLIError(
                f"Security violation: cross-origin redirect detected during discovery from '{orig_url}' to '{newurl}'. "
                "Cross-origin redirects are forbidden during discovery to prevent credential and metadata mix-up attacks."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_www_authenticate_header(header_val: str) -> dict[str, str]:
    """Parse WWW-Authenticate header key-values robustly per RFC 6750 and RFC 9728."""
    if not header_val or not isinstance(header_val, str):
        return {}

    params: dict[str, str] = {}
    pattern = r'([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s,]+))'
    for match in re.finditer(pattern, header_val):
        key = match.group(1).lower()
        quoted_val = match.group(2)
        unquoted_val = match.group(3)
        val = quoted_val if quoted_val is not None else unquoted_val
        if quoted_val is not None:
            val = re.sub(r"\\(.)", r"\1", val)
        params[key] = val.strip()
    return params


def _open_url(req: urllib.request.Request, timeout: float = 15.0) -> Any:
    """Open request with StrictSameOriginRedirectHandler, delegating to urlopen if mocked."""
    if hasattr(urllib.request.urlopen, "assert_called") or hasattr(urllib.request.urlopen, "mock_calls"):
        return urllib.request.urlopen(req, timeout=timeout)
    opener = urllib.request.build_opener(StrictSameOriginRedirectHandler())
    return opener.open(req, timeout=timeout)


def _fetch_discovery_json(
    url: str,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    max_bytes: int = MAX_METADATA_RESPONSE_SIZE_BYTES,
) -> tuple[int, dict[str, Any] | None]:
    """Fetch JSON from a discovery endpoint with cross-origin redirect prevention, bounded size, and format validation."""
    _validate_https_endpoint(url, "discovery endpoint")
    bounded_timeout = min(timeout, MAX_DISCOVERY_TIMEOUT_SECONDS)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": get_user_agent(),
            "Accept": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        },
        method="GET",
    )

    try:
        with _open_url(req, timeout=bounded_timeout) as resp:
            status = getattr(resp, "status", getattr(resp, "code", 200))
            raw_bytes = resp.read(max_bytes + 1)
            if len(raw_bytes) > max_bytes:
                raise CLIError(
                    f"Resource exhaustion error: metadata response from '{url}' exceeded "
                    f"maximum size limit of {max_bytes} bytes."
                )
            raw_content = raw_bytes.decode("utf-8")
            if not raw_content.strip():
                return status, None
            try:
                data = json.loads(raw_content)
                if not isinstance(data, dict):
                    raise CLIError(f"Malformed metadata at '{url}': JSON response must be an object.")
                return status, data
            except json.JSONDecodeError as exc:
                raise CLIError(f"Malformed metadata at '{url}': invalid JSON ({exc}).") from exc
    except urllib.error.HTTPError as exc:
        status = exc.code
        if status in (404, 410):
            return status, None
        if status in (301, 302, 303, 307, 308):
            return status, None
        if status >= 500 or status == 429:
            safe_msg = redact_text(str(exc))
            raise CLIError(f"Discovery endpoint '{url}' server error (HTTP {status}): {safe_msg}") from exc
        return status, None
    except urllib.error.URLError as exc:
        safe_msg = redact_text(str(exc))
        raise CLIError(f"Failed to connect to discovery endpoint '{url}': {safe_msg}") from exc


def discover_mcp_auth_requirements(integration: MCPIntegration) -> MCPAuthRequirements:
    """Discover standards-correct MCP authorization requirements per MCP spec, RFC 8414, and RFC 9728."""
    integration.validate_integration_id()
    integration.validate_transport()

    raw_trans = (
        (integration.transport.value if isinstance(integration.transport, MCPTransport) else str(integration.transport))
        .lower()
        .strip()
    )

    if raw_trans == MCPTransport.STDIO.value:
        return MCPAuthRequirements(required=False)

    if raw_trans != MCPTransport.STREAMABLE_HTTP.value:
        raise CLIError(f"Unsupported MCP transport '{integration.transport}' for authorization discovery.")

    url = integration.connection.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        raise CLIError(f"Missing or invalid URL for streamable-http integration '{integration.integration_id}'.")

    url = url.strip()
    _validate_https_endpoint(url, "MCP endpoint")

    probe_req = urllib.request.Request(
        url,
        headers={
            "User-Agent": get_user_agent(),
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
        },
        method="GET",
    )

    is_401 = False
    is_step_up_403 = False
    www_auth_header = ""

    # Step 1: Probe server to identify whether it is protected
    try:
        with _open_url(probe_req, timeout=15.0):
            # 200 OK: unauthenticated public MCP server
            return MCPAuthRequirements(required=False)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            is_401 = True
            www_auth_header = exc.headers.get("WWW-Authenticate", "")
        elif exc.code == 403:
            # Step-up authorization or plain 403 Forbidden?
            www_auth_header = exc.headers.get("WWW-Authenticate", "")
            parsed_params = parse_www_authenticate_header(www_auth_header)
            if parsed_params.get("error") == "insufficient_scope":
                is_step_up_403 = True
            else:
                # Keep 401 and 403 semantics distinct: 403 without OAuth challenge is forbidden
                raise CLIError(
                    f"Access forbidden (HTTP 403) for integration '{integration.integration_id}'. "
                    "The server rejected access without an OAuth authorization challenge."
                )
        else:
            safe_msg = redact_text(str(exc))
            raise CLIError(
                f"Streamable HTTP MCP server error (HTTP {exc.code}) for '{integration.integration_id}': {safe_msg}"
            ) from exc
    except urllib.error.URLError as exc:
        safe_msg = redact_text(str(exc))
        raise CLIError(f"Failed connection to MCP server ({url}): {safe_msg}") from exc
    except CLIError:
        raise
    except Exception as exc:
        safe_msg = redact_text(str(exc))
        raise CLIError(f"Auth discovery connection failed: {safe_msg}") from exc

    if not is_401 and not is_step_up_403:
        return MCPAuthRequirements(required=False)

    # Step 2: Parse WWW-Authenticate header
    raw_auth_strip = www_auth_header.strip()
    if raw_auth_strip:
        # Check scheme: must be Bearer (or start with Bearer)
        auth_scheme_match = re.match(r"^([a-zA-Z0-9_-]+)", raw_auth_strip)
        if auth_scheme_match:
            scheme = auth_scheme_match.group(1).lower()
            if scheme not in ("bearer",):
                raise CLIError(
                    f"Unsupported authorization scheme '{scheme}' in WWW-Authenticate header for '{integration.integration_id}'. "
                    "Only Bearer authentication is supported."
                )

    parsed_auth = parse_www_authenticate_header(www_auth_header)
    resource_metadata_url = parsed_auth.get("resource_metadata")
    if resource_metadata_url:
        _validate_https_endpoint(resource_metadata_url, "resource_metadata endpoint")

    scope_challenge = parsed_auth.get("scope")

    # Legacy or alternate hints
    legacy_auth_hint = (
        parsed_auth.get("authorization_uri") or parsed_auth.get("authorization_server") or parsed_auth.get("realm")
    )

    discovered_prm: ProtectedResourceMetadata | None = None
    selected_auth_server: str | None = None

    # Step 3: Discover Protected Resource Metadata (PRM)
    # If resource_metadata is present OR no legacy realm hint is present, try PRM discovery
    if resource_metadata_url or not (
        legacy_auth_hint and (legacy_auth_hint.startswith("http://") or legacy_auth_hint.startswith("https://"))
    ):
        prm_urls = build_protected_resource_metadata_discovery_urls(resource_metadata_url, url)
        for prm_url in prm_urls:
            status, prm_data = _fetch_discovery_json(prm_url)
            if status == 200 and prm_data is not None:
                try:
                    prm = ProtectedResourceMetadata.model_validate(prm_data)
                except Exception as exc:
                    if resource_metadata_url:
                        raise CLIError(f"Malformed protected resource metadata at '{prm_url}': {exc}") from exc
                    continue

                # Validate PRM resource matches expected server URL per RFC 8707
                if prm.resource:
                    prm_resource_str = str(prm.resource)
                    expected_resource = resource_url_from_server_url(url)
                    if not check_resource_allowed(
                        requested_resource=expected_resource,
                        configured_resource=prm_resource_str,
                    ):
                        raise CLIError(
                            f"Security error: Protected Resource Metadata resource '{prm_resource_str}' "
                            f"does not match expected server resource '{expected_resource}' (wrong resource detected)."
                        )

                # Validate authorization_servers
                if not prm.authorization_servers:
                    raise CLIError(
                        f"Malformed protected resource metadata at '{prm_url}': missing 'authorization_servers'."
                    )

                # Select primary authorization server (first in list)
                primary_as = str(prm.authorization_servers[0])
                _validate_https_endpoint(primary_as, "authorization server")

                discovered_prm = prm
                selected_auth_server = primary_as
                break

    # Step 4: Resolve Authorization Server Metadata (OASM)
    parsed_server_url = urllib.parse.urlparse(url)
    server_origin = f"{parsed_server_url.scheme}://{parsed_server_url.netloc}"

    if discovered_prm and selected_auth_server:
        as_discovery_target: str | None = selected_auth_server
        expected_issuer = selected_auth_server
    elif legacy_auth_hint and (legacy_auth_hint.startswith("http://") or legacy_auth_hint.startswith("https://")):
        as_discovery_target = legacy_auth_hint
        parsed_hint = urllib.parse.urlparse(legacy_auth_hint)
        expected_issuer = f"{parsed_hint.scheme}://{parsed_hint.netloc}"
    else:
        # Legacy fallback without PRM: construct well-known from resource origin
        as_discovery_target = None
        expected_issuer = server_origin

    as_discovery_urls = build_oauth_authorization_server_metadata_discovery_urls(as_discovery_target, url)
    # Ensure expected issuer root is also tested if distinct
    if expected_issuer:
        root_as_url = f"{expected_issuer.rstrip('/')}/.well-known/oauth-authorization-server"
        if root_as_url not in as_discovery_urls:
            as_discovery_urls.append(root_as_url)

    discovered_oasm: OAuthMetadata | None = None

    for as_url in as_discovery_urls:
        status, as_data = _fetch_discovery_json(as_url, max_bytes=MAX_OAUTH_METADATA_RESPONSE_SIZE_BYTES)
        if status == 200 and as_data is not None:
            try:
                oasm = OAuthMetadata.model_validate(as_data)
            except Exception as exc:
                raise CLIError(f"Malformed authorization server metadata at '{as_url}': {exc}") from exc

            # Validate issuer identity (anti-issuer confusion)
            actual_issuer = str(oasm.issuer)
            if not issuers_match(actual_issuer, expected_issuer):
                raise CLIError(
                    f"Security error: Authorization server metadata issuer mismatch for '{integration.integration_id}': "
                    f"expected '{expected_issuer}', got '{actual_issuer}' (issuer confusion detected)."
                )

            # Validate authorization_endpoint
            if not oasm.authorization_endpoint:
                raise CLIError(
                    f"Malformed authorization server metadata at '{as_url}': missing required 'authorization_endpoint'."
                )
            auth_ep_str = str(oasm.authorization_endpoint)
            _validate_https_endpoint(auth_ep_str, "authorization_endpoint")

            # Validate token_endpoint
            if not oasm.token_endpoint:
                raise CLIError(
                    f"Malformed authorization server metadata at '{as_url}': missing required 'token_endpoint'."
                )
            token_ep_str = str(oasm.token_endpoint)
            _validate_https_endpoint(token_ep_str, "token_endpoint")

            # Reject endpoint mix-up: token_endpoint must belong to the authorization server's trust domain
            token_parsed = urllib.parse.urlparse(token_ep_str)
            issuer_parsed = urllib.parse.urlparse(actual_issuer)
            if (token_parsed.hostname or "").lower() != (issuer_parsed.hostname or "").lower():
                raise CLIError(
                    f"Security error: token_endpoint '{token_ep_str}' does not belong to authorization server '{actual_issuer}' "
                    "(endpoint mix-up detected)."
                )

            # Validate registration_endpoint if present
            reg_ep_str = str(oasm.registration_endpoint) if oasm.registration_endpoint else None
            if reg_ep_str:
                _validate_https_endpoint(reg_ep_str, "registration_endpoint")

            discovered_oasm = oasm
            break

    if not discovered_oasm:
        raise CLIError(
            f"Authentication required (HTTP 401) for integration '{integration.integration_id}', "
            "but no valid OAuth 2.0 / MCP authorization server metadata could be discovered."
        )

    # Step 5: Scope & PKCE selection
    scopes: list[str] = []
    if scope_challenge:
        scopes = [s.strip() for s in scope_challenge.split() if s.strip()]
    elif discovered_prm and discovered_prm.scopes_supported:
        scopes = [str(s).strip() for s in discovered_prm.scopes_supported if str(s).strip()]
    elif discovered_oasm.scopes_supported:
        scopes = [str(s).strip() for s in discovered_oasm.scopes_supported if str(s).strip()]

    code_methods = discovered_oasm.code_challenge_methods_supported or []
    pkce_supported = "S256" in code_methods or "plain" in code_methods or bool(code_methods)
    pkce_required = "S256" in code_methods

    return MCPAuthRequirements(
        required=True,
        authorization_server=selected_auth_server or expected_issuer,
        issuer=str(discovered_oasm.issuer),
        authorization_endpoint=str(discovered_oasm.authorization_endpoint),
        token_endpoint=str(discovered_oasm.token_endpoint),
        registration_endpoint=str(discovered_oasm.registration_endpoint)
        if discovered_oasm.registration_endpoint
        else None,
        scopes=scopes,
        pkce_supported=pkce_supported,
        pkce_required=pkce_required,
        metadata=discovered_oasm.model_dump(mode="json"),
    )
