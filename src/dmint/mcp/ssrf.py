"""Server-Side Request Forgery (SSRF) validation for remote MCP endpoints.

Provides strict URL validation, scheme checks, hostname normalization, IP
range verification (private, link-local, cloud metadata), and DNS pre-resolution
checks to protect dmint-mcp from SSRF attacks when connecting to downstream
remote MCP servers.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Any, Container

from .errors import MCPConfigurationError, MCPConnectionError

# Hostnames known to belong to cloud provider metadata services
METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.google",
        "metadata",
        "instance-data",
        "169.254.169.254",
        "0.0.0.0",
        "0",
    }
)

# Disallowed schemes
DISALLOWED_SCHEMES: frozenset[str] = frozenset(
    {
        "file",
        "ftp",
        "gopher",
        "data",
        "blob",
        "javascript",
        "dict",
        "ldap",
        "ldaps",
        "tftp",
        "mailto",
        "telnet",
    }
)


def is_loopback_host(hostname: str) -> bool:
    """Check if hostname points to localhost or loopback interface."""
    if not hostname:
        return False
    clean = hostname.lower().strip("[]").strip()
    if clean in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_loopback
    except ValueError:
        return False


def is_private_or_metadata_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool = False,
) -> bool:
    """Check whether an IP address is private, link-local, reserved, multicast, or cloud metadata.

    Args:
        ip: IPv4Address or IPv6Address object.
        allow_loopback: If True, loopback addresses (127.0.0.0/8, ::1) are permitted.

    Returns:
        True if the IP represents a restricted/private/metadata destination.
    """
    # Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) first so that
    # the general IPv6 is_reserved check does not preempt underlying IPv4 classification.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_private_or_metadata_ip(ip.ipv4_mapped, allow_loopback=allow_loopback)

    if ip.is_loopback:
        return not allow_loopback

    # Standard IP classification
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True

    # Cloud metadata check (169.254.169.254 is link-local, but check explicitly)
    if isinstance(ip, ipaddress.IPv4Address):
        if ip == ipaddress.IPv4Address("169.254.169.254"):
            return True
        # Carrier-grade NAT (100.64.0.0/10)
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
        # 0.0.0.0/8
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return True

    return False


def parse_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse hostname if it is an IPv4 or IPv6 address literal (including integer format)."""
    clean = hostname.lower().strip("[]").strip()
    if not clean:
        return None

    # Check numeric integer format (e.g. 2130706433 or 0)
    if clean.isdigit():
        try:
            ip_int = int(clean)
            if 0 <= ip_int <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(ip_int)
        except (ValueError, OverflowError):
            pass

    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        return None


def is_obfuscated_or_short_ip(host: str) -> bool:
    """Check if hostname represents an obfuscated octal, hex, or short-form IP literal."""
    clean = host.lower().strip("[]").strip()
    if not clean:
        return False
    if clean.startswith("0x"):
        return True
    parts = clean.split(".")
    if 1 <= len(parts) <= 4:
        all_numeric = True
        has_octal = False
        has_hex = False
        for p in parts:
            if not p:
                all_numeric = False
                break
            if p.startswith("0x"):
                has_hex = True
                try:
                    int(p, 16)
                except ValueError:
                    all_numeric = False
            elif p.isdigit():
                if len(p) > 1 and p.startswith("0"):
                    has_octal = True
            else:
                all_numeric = False
        if all_numeric:
            if has_octal or has_hex:
                return True
            if 2 <= len(parts) <= 3:
                return True
    return False


class ValidatedURL(str):
    """String subclass representing a validated MCP URL with pinned IP and destination details."""

    pinned_ip: str | None
    hostname: str
    port: int

    def __new__(
        cls,
        url: str,
        *,
        pinned_ip: str | None = None,
        hostname: str = "",
        port: int = 443,
    ) -> "ValidatedURL":
        instance = super().__new__(cls, url)
        instance.pinned_ip = pinned_ip
        instance.hostname = hostname
        instance.port = port
        return instance


class PinnedAsyncNetworkBackend:
    """Network backend that connects directly to a pinned IP while preserving host/SNI semantics."""

    def __init__(self, target_host: str, pinned_ip: str, base_backend: Any = None) -> None:
        import httpcore2._backends.anyio

        self._target_host = target_host.lower()
        self._pinned_ip = pinned_ip
        self._base = base_backend or httpcore2._backends.anyio.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        connect_host = self._pinned_ip if host.lower() == self._target_host else host
        return await self._base.connect_tcp(
            connect_host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> Any:
        return await self._base.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._base.sleep(seconds)


def create_pinned_async_transport(
    target_host: str,
    pinned_ip: str,
    *,
    verify: bool = True,
    **kwargs: Any,
) -> Any:
    """Create an AsyncHTTPTransport pinned to a specific IP address to defeat DNS rebinding."""
    import httpx2

    transport = httpx2.AsyncHTTPTransport(verify=verify, **kwargs)
    backend = PinnedAsyncNetworkBackend(target_host, pinned_ip)
    if hasattr(transport, "_pool") and hasattr(transport._pool, "_network_backend"):
        setattr(transport._pool, "_network_backend", backend)
    return transport


def resolve_and_verify_dns(
    hostname: str,
    port: int,
    *,
    allow_loopback: bool = False,
) -> list[str]:
    """Resolve DNS for hostname and ensure no resolved address points to a private or metadata IP.

    Args:
        hostname: Domain name to resolve.
        port: Destination port.
        allow_loopback: Whether loopback IPs are allowed.

    Returns:
        List of resolved IP address strings.

    Raises:
        MCPConfigurationError: If any resolved IP is restricted or resolution fails.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise MCPConfigurationError(f"DNS resolution failed for downstream endpoint '{hostname}': {exc}") from exc
    except Exception as exc:
        raise MCPConfigurationError(f"DNS resolution error for downstream endpoint '{hostname}': {exc}") from exc

    if not addr_info:
        raise MCPConfigurationError(f"DNS resolution returned no addresses for downstream endpoint '{hostname}'")

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = str(sockaddr[0])
        resolved_ips.append(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise MCPConfigurationError(f"DNS resolved invalid IP address '{ip_str}' for endpoint '{hostname}'")

        if is_private_or_metadata_ip(ip, allow_loopback=allow_loopback):
            raise MCPConfigurationError(
                f"SSRF violation: endpoint '{hostname}' resolved to prohibited IP '{ip_str}'. "
                "Connections to private, link-local, loopback, or cloud metadata IPs are strictly forbidden."
            )

    return resolved_ips


def validate_mcp_url(
    url_str: str,
    *,
    allow_loopback: bool = True,
    resolve_dns: bool = True,
) -> str:
    """Validate a remote MCP endpoint URL against SSRF and scheme security requirements.

    Requirements:
    1. URL must be a non-empty string.
    2. Scheme must be http or https (disallowed schemes rejected).
    3. Userinfo (username / password) is forbidden.
    4. Hostname must be present and port must be valid (1-65535).
    5. Non-loopback endpoints must strictly use HTTPS. Plain HTTP is only permitted for loopback.
    6. IP literals and metadata hostnames must not point to private/link-local/metadata ranges.
    7. If resolve_dns is True and host is a domain name, resolved IPs must not point to private ranges.

    Args:
        url_str: Target URL string.
        allow_loopback: Whether loopback (localhost/127.0.0.1/::1) is permitted.
        resolve_dns: Whether to perform DNS resolution check on hostnames.

    Returns:
        Validated, cleaned URL string.

    Raises:
        MCPConfigurationError: If any security requirement is violated.
    """
    if not url_str or not isinstance(url_str, str) or not url_str.strip():
        raise MCPConfigurationError("remote MCP endpoint URL must be a non-empty string")

    clean_url = url_str.strip()
    try:
        parsed = urllib.parse.urlparse(clean_url)
    except Exception as exc:
        raise MCPConfigurationError(f"malformed remote MCP endpoint URL '{clean_url}': {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if not scheme:
        raise MCPConfigurationError(f"remote MCP endpoint URL '{clean_url}' is missing a scheme")

    if scheme in DISALLOWED_SCHEMES:
        raise MCPConfigurationError(
            f"SSRF violation: scheme '{parsed.scheme}' is disallowed for remote MCP endpoint '{clean_url}'"
        )

    if scheme not in ("http", "https"):
        raise MCPConfigurationError(
            f"SSRF violation: unsupported scheme '{parsed.scheme}'. Only HTTPS (or HTTP for loopback) is allowed."
        )

    if parsed.username or parsed.password:
        raise MCPConfigurationError(
            f"security violation: remote MCP endpoint URL must not contain embedded userinfo: '{clean_url}'"
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise MCPConfigurationError(f"remote MCP endpoint URL '{clean_url}' is missing a hostname")

    clean_host = hostname.strip("[]").strip()
    if clean_host.endswith(".") or any(not label for label in clean_host.split(".")):
        raise MCPConfigurationError(
            f"SSRF violation: trailing-dot or empty-label hostnames are prohibited: '{hostname}'"
        )

    if is_obfuscated_or_short_ip(clean_host):
        raise MCPConfigurationError(
            f"SSRF violation: octal, hex, or short-form IP literals are prohibited: '{hostname}'"
        )

    port = parsed.port
    if port is not None:
        if not (1 <= port <= 65535):
            raise MCPConfigurationError(f"remote MCP endpoint URL has invalid port: {port}")
    else:
        port = 443 if scheme == "https" else 80

    is_loopback = is_loopback_host(hostname)

    # If loopback is explicitly disallowed
    if is_loopback and not allow_loopback:
        raise MCPConfigurationError(
            f"SSRF violation: loopback endpoint '{clean_url}' is disallowed in this configuration"
        )

    # Enforce HTTPS for non-loopback endpoints
    if scheme != "https" and not (is_loopback and allow_loopback):
        raise MCPConfigurationError(
            f"remote MCP endpoint must use HTTPS: '{clean_url}'. HTTP is only allowed for loopback testing."
        )

    pinned_ip: str | None = None
    # Check IP literal directly
    ip_literal = parse_ip_literal(hostname)
    if ip_literal is not None:
        if is_private_or_metadata_ip(ip_literal, allow_loopback=allow_loopback):
            raise MCPConfigurationError(
                f"SSRF violation: remote MCP endpoint points to prohibited IP address '{hostname}'"
            )
        pinned_ip = str(ip_literal)
    else:
        # Check known metadata hostnames and suffixes
        if clean_host in METADATA_HOSTNAMES or clean_host.endswith(".internal") or clean_host.endswith(".local"):
            raise MCPConfigurationError(
                f"SSRF violation: remote MCP endpoint points to prohibited internal or metadata host '{hostname}'"
            )

        if resolve_dns and not is_loopback:
            # Host is a remote domain name: check DNS pre-resolution
            resolved_ips = resolve_and_verify_dns(hostname, port, allow_loopback=allow_loopback)
            if resolved_ips:
                pinned_ip = resolved_ips[0]
        elif is_loopback:
            pinned_ip = "127.0.0.1" if hostname in ("localhost", "127.0.0.1") else hostname

    return ValidatedURL(clean_url, pinned_ip=pinned_ip, hostname=hostname, port=port)
