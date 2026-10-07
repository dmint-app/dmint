"""Deterministic resource matching engine for Dmint.

Provides kind-specific normalization and deterministic matching:
- 'path': POSIX path normalization (resolving '.', '..', duplicate slashes,
  fixing POSIX '//' quirk, normalizing trailing slashes), rejecting root escapes,
  NUL bytes, backslashes, and percent-encoded traversal tokens (%2f, %2e%2e).
  Supports NFC Unicode normalization and an explicit case-insensitive option.
  Deterministic segment-based matcher for '*' (single segment) and '**' (multi-segment)
  with hard bounds on input/pattern length and zero ReDoS / regex backtracking.
  NOTE: String-based path matching cannot inspect the underlying filesystem.
  Symlink resolution (e.g. via os.path.realpath()) is strictly the tool
  resolver's responsibility before passing request resources to Dmint.
- 'url' / 'host': Normalizes scheme (fail-closed: http/https only), lowercase hostname,
  punycode IDN conversion, trailing-dot removal, IPv6 bracketed literals, default port
  removal, userinfo rejection (@), encoded traversal rejection (%2f, %2e%2e), and path
  normalization. Supports domain and path wildcards.
- 'identifier': Rejects leading/trailing whitespace, rejects NUL bytes.
  Wildcard '*' strictly matches [A-Za-z0-9_.-]*.
- Unknown kind: Strictly exact match (no wildcards or heuristic expansion).
"""

from __future__ import annotations

from enum import Enum
import functools
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from .errors import PolicyError


class ResourceMatchingError(PolicyError):
    """Raised when resource normalization or pattern matching fails closed."""

    code = "DMT_RESOURCE_INVALID"


class ResourceKind(str, Enum):
    PATH = "path"
    URL = "url"
    HOST = "host"
    IDENTIFIER = "identifier"
    EXACT = "exact"
    ANY = "any"
    NONE = "none"
    UNKNOWN = "unknown"


# Hard limits for deterministic resource processing
MAX_PATTERN_LENGTH = 1024
MAX_INPUT_LENGTH = 65536
MAX_SEGMENTS = 10000
MAX_WILDCARDS = 64

_ENCODED_TRAVERSAL_TOKENS = (
    "%2f",
    "%2e%2e",
    "%2e.",
    ".%2e",
    "%252f",
    "%252e%252e",
    "%252e.",
    ".%252e",
    "%252e",
)
_IDENTIFIER_PATTERN_REGEX = re.compile(r"^[A-Za-z0-9_.*:\-]+$")


def normalize_path(path: str, case_sensitive: bool = True) -> str:
    """Normalize POSIX paths with strict security checks.

    Rules:
    - Reject empty paths.
    - Enforce MAX_INPUT_LENGTH limit.
    - Reject NUL bytes (\\x00).
    - Reject backslashes (\\) where POSIX path is expected.
    - Reject percent-encoded traversal tokens (%2f, %2e%2e).
    - Unicode normalize to NFC.
    - Optional case folding when case_sensitive=False.
    - Collapse multiple leading slashes (fixes POSIX '//' quirk of posixpath.normpath).
    - Normalize '.' and '..' segments securely without filesystem dependency.
    - Reject any path that attempts to escape the root directory.
    - Normalize duplicate slashes and strip trailing slashes (except root '/').
    """
    if not path:
        raise ResourceMatchingError("path cannot be empty")
    if len(path) > MAX_INPUT_LENGTH:
        raise ResourceMatchingError(f"path exceeds maximum length of {MAX_INPUT_LENGTH}")
    if "\x00" in path:
        raise ResourceMatchingError("path contains NUL byte")
    if "\\" in path:
        raise ResourceMatchingError("path contains backslash where POSIX path is expected")

    # Reject encoded path traversal tokens
    path_lower = path.lower()
    for token in _ENCODED_TRAVERSAL_TOKENS:
        if token in path_lower:
            raise ResourceMatchingError(f"path contains encoded traversal sequence: {token}")

    # Unicode NFC normalization
    path = unicodedata.normalize("NFC", path)

    if not case_sensitive:
        path = path.lower()

    is_abs = path.startswith("/")
    # Collapse multiple leading slashes (fixes POSIX // quirk)
    if is_abs:
        idx = 0
        while idx < len(path) and path[idx] == "/":
            idx += 1
        path = "/" + path[idx:]

    segments: list[str] = []
    parts = path.split("/")
    if len(parts) > MAX_SEGMENTS:
        raise ResourceMatchingError(f"path exceeds maximum segment limit of {MAX_SEGMENTS}")

    for part in parts:
        if part == "" or part == ".":
            continue
        if part == "..":
            if not segments:
                if is_abs:
                    raise ResourceMatchingError("path escapes root directory")
                else:
                    raise ResourceMatchingError("relative path escapes start directory")
            segments.pop()
        else:
            segments.append(part)

    if is_abs:
        res = "/" + "/".join(segments)
        return res if res else "/"
    else:
        if not segments:
            return "."
        return "/".join(segments)


def _split_path_segments(p: str) -> tuple[bool, list[str]]:
    """Split a normalized path into (is_absolute, segments)."""
    if p.startswith("/"):
        if p == "/":
            return True, []
        return True, p[1:].split("/")
    else:
        if p == ".":
            return False, []
        return False, p.split("/")


@functools.lru_cache(maxsize=1024)
def _compile_single_segment_pattern(pat: str) -> re.Pattern[str]:
    """Compile a single segment pattern (contains '*' but no '/') into a safe regex."""
    parts = ["^"]
    for c in pat:
        if c == "*":
            parts.append(".*")
        else:
            parts.append(re.escape(c))
    parts.append("$")
    return re.compile("".join(parts))


def _match_single_segment(pat: str, seg: str) -> bool:
    """Match a single pattern segment against an input segment."""
    if pat == "*":
        return True
    if pat == seg:
        return True
    if "*" in pat:
        return bool(_compile_single_segment_pattern(pat).fullmatch(seg))
    return False


def _parse_pattern_segments(pattern: str, case_sensitive: bool = True) -> tuple[bool, list[str]]:
    """Parse and validate pattern into (is_absolute, segments)."""
    if not pattern:
        raise ResourceMatchingError("pattern cannot be empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ResourceMatchingError(f"pattern exceeds maximum length of {MAX_PATTERN_LENGTH}")
    if "\x00" in pattern:
        raise ResourceMatchingError("pattern contains NUL byte")
    if "\\" in pattern:
        raise ResourceMatchingError("pattern contains backslash where POSIX path is expected")
    if "?" in pattern:
        raise ResourceMatchingError("wildcard '?' is not supported; use '*' or '**'")

    pat_lower = pattern.lower()
    for token in _ENCODED_TRAVERSAL_TOKENS:
        if token in pat_lower:
            raise ResourceMatchingError(f"pattern contains encoded traversal sequence: {token}")

    if pattern.count("*") > MAX_WILDCARDS:
        raise ResourceMatchingError(f"pattern exceeds maximum wildcards limit of {MAX_WILDCARDS}")

    pattern = unicodedata.normalize("NFC", pattern)
    if not case_sensitive:
        pattern = pattern.lower()

    is_abs = pattern.startswith("/")
    if is_abs:
        idx = 0
        while idx < len(pattern) and pattern[idx] == "/":
            idx += 1
        pattern = "/" + pattern[idx:]

    # Strip trailing slash from pattern unless root '/' or ends with '/**' or '**'
    if len(pattern) > 1 and pattern.endswith("/") and not pattern.endswith("**/") and not pattern.endswith("*/"):
        pattern = pattern.rstrip("/")

    if is_abs:
        if pattern == "/":
            raw_parts = []
        else:
            raw_parts = pattern[1:].split("/")
    else:
        raw_parts = pattern.split("/")

    # Collapse consecutive '**' segments: '**/**' -> '**'
    collapsed: list[str] = []
    for part in raw_parts:
        if part == "":
            continue
        if part == "**" and collapsed and collapsed[-1] == "**":
            continue
        collapsed.append(part)

    return is_abs, collapsed


def _match_path_segments_unchecked(pat_segs: list[str], input_segs: list[str]) -> bool:
    """Deterministic segment-level wildcard matching algorithm.

    Guarantees:
    - Runs in bounded O(N * M) time where N is input segments and M is pattern segments.
    - Zero regex backtracking / ReDoS risk.
    - Correctly handles '**' across zero or more segments.
    """
    s_idx = 0
    p_idx = 0
    star_idx = -1
    s_backtrack = -1

    len_s = len(input_segs)
    len_p = len(pat_segs)

    while s_idx < len_s:
        if p_idx < len_p and pat_segs[p_idx] != "**" and _match_single_segment(pat_segs[p_idx], input_segs[s_idx]):
            s_idx += 1
            p_idx += 1
        elif p_idx < len_p and pat_segs[p_idx] == "**":
            star_idx = p_idx
            s_backtrack = s_idx
            p_idx += 1
        elif star_idx != -1:
            p_idx = star_idx + 1
            s_backtrack += 1
            s_idx = s_backtrack
        else:
            return False

    while p_idx < len_p and pat_segs[p_idx] == "**":
        p_idx += 1

    return p_idx == len_p


match_path_segments = _match_path_segments_unchecked


def _match_path_unchecked(rule: str, norm_input: str, case_sensitive: bool = True) -> bool:
    """Low-level path matcher. Assumes norm_input has already been validated and normalized."""
    try:
        is_abs_pat, pat_segs = _parse_pattern_segments(rule, case_sensitive=case_sensitive)
    except ResourceMatchingError:
        return False

    is_abs_in, in_segs = _split_path_segments(norm_input)
    if is_abs_pat != is_abs_in:
        return False

    return _match_path_segments_unchecked(pat_segs, in_segs)


def match_path(rule: str, input_path: str, case_sensitive: bool = True) -> bool:
    """Safe public path matcher: validates and normalizes input_path then delegates."""
    try:
        norm_input = normalize_path(input_path, case_sensitive=case_sensitive)
    except ResourceMatchingError:
        return False

    return _match_path_unchecked(rule, norm_input, case_sensitive=case_sensitive)


@functools.lru_cache(maxsize=1024)
def compile_path_pattern(pattern: str) -> re.Pattern[str]:
    """Retained for legacy/external compatibility; segment-based matching is preferred."""
    _parse_pattern_segments(pattern)
    # Generate an anchored regex for callers expecting a compiled Pattern
    escaped_parts: list[str] = ["^"]
    idx = 0
    n = len(pattern)
    while idx < n:
        if pattern[idx : idx + 2] == "**":
            escaped_parts.append(".*")
            idx += 2
        elif pattern[idx] == "*":
            escaped_parts.append("[^/]*")
            idx += 1
        else:
            escaped_parts.append(re.escape(pattern[idx]))
            idx += 1
    escaped_parts.append("$")
    return re.compile("".join(escaped_parts))


def normalize_host(host_str: str) -> str:
    """Normalize a hostname.

    Rules:
    - Enforce MAX_INPUT_LENGTH limit.
    - Reject NUL bytes, whitespace, '@', and backslashes.
    - Parse bracketed IPv6 literals (e.g. '[::1]').
    - Strip trailing dot (DNS canonicalization: 'api.github.com.' -> 'api.github.com').
    - Punycode IDN conversion for non-ASCII hostnames.
    - Lowercase hostname.
    """
    if not host_str:
        raise ResourceMatchingError("host cannot be empty")
    if len(host_str) > MAX_INPUT_LENGTH:
        raise ResourceMatchingError(f"host exceeds maximum length of {MAX_INPUT_LENGTH}")
    if "\x00" in host_str:
        raise ResourceMatchingError("host contains NUL byte")
    if "@" in host_str:
        raise ResourceMatchingError("host contains userinfo '@', which is forbidden")
    if "\\" in host_str:
        raise ResourceMatchingError("host contains backslash")
    if host_str != host_str.strip():
        raise ResourceMatchingError("host contains leading or trailing whitespace")

    clean = host_str
    if "://" in clean:
        try:
            clean = urlsplit(clean).netloc
        except Exception as exc:
            raise ResourceMatchingError(f"invalid host format: {exc}") from exc

    # Separate port if present
    port = ""
    if clean.startswith("["):
        # Bracketed IPv6
        if "]" not in clean:
            raise ResourceMatchingError("malformed IPv6 literal: missing closing bracket")
        close_idx = clean.index("]")
        host_part = clean[: close_idx + 1]
        rest = clean[close_idx + 1 :]
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in clean:
        parts = clean.split(":")
        if len(parts) > 2:
            raise ResourceMatchingError("malformed host: multiple colons without IPv6 brackets")
        host_part = parts[0]
        port = parts[1]
    else:
        host_part = clean

    # Strip trailing dot
    if host_part.endswith(".") and not host_part.startswith("["):
        host_part = host_part[:-1]

    if not host_part:
        raise ResourceMatchingError("host cannot be empty after normalization")

    # IDN Punycode conversion
    if not host_part.startswith("["):
        try:
            host_part = host_part.encode("idna").decode("ascii").lower()
        except Exception as exc:
            raise ResourceMatchingError(f"invalid IDN hostname: {exc}") from exc
    else:
        host_part = host_part.lower()

    if port:
        try:
            p_val = int(port)
            if not (1 <= p_val <= 65535):
                raise ResourceMatchingError("port out of range (1-65535)")
        except ValueError as exc:
            raise ResourceMatchingError("invalid port") from exc
        return f"{host_part}:{port}"
    return host_part


def normalize_url(url_str: str) -> str:
    """Normalize a URL with strict fail-closed security.

    Rules:
    - Enforce MAX_INPUT_LENGTH limit.
    - Reject NUL bytes.
    - Reject userinfo tricks (e.g. 'https://api.github.com@evil.com/' or 'https://evil.com\\@github.com').
    - Reject backslashes in URL authority/path.
    - Fail-closed on non-http schemes: ONLY 'http' and 'https' are permitted.
    - Hostname normalization: lowercase, punycode IDN, trailing-dot removal, IPv6 literals.
    - Default port removal (80 for http, 443 for https).
    - Reject percent-encoded traversal tokens (%2f, %2e%2e).
    - Path normalization resolving '.' and '..' without escaping root.
    """
    if not url_str:
        raise ResourceMatchingError("URL cannot be empty")
    if len(url_str) > MAX_INPUT_LENGTH:
        raise ResourceMatchingError(f"URL exceeds maximum length of {MAX_INPUT_LENGTH}")
    if "\x00" in url_str:
        raise ResourceMatchingError("URL contains NUL byte")

    # Inspect authority/path before query/fragment for backslash or userinfo tricks
    pre_query = url_str.split("?", 1)[0].split("#", 1)[0]
    if "\\" in pre_query:
        raise ResourceMatchingError("URL contains backslash in authority/path")
    if "@" in pre_query:
        raise ResourceMatchingError("URL contains userinfo '@', which is forbidden")

    try:
        parts = urlsplit(url_str)
    except Exception as exc:
        raise ResourceMatchingError(f"malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ResourceMatchingError(f"unsupported URL scheme '{scheme}'; only http and https are allowed")

    if not parts.netloc:
        raise ResourceMatchingError("invalid URL: missing hostname")

    if parts.username or parts.password:
        raise ResourceMatchingError("URL userinfo is forbidden")

    # Normalize netloc / host
    netloc_raw = parts.netloc
    port = ""
    if netloc_raw.startswith("["):
        if "]" not in netloc_raw:
            raise ResourceMatchingError("malformed IPv6 literal")
        close_idx = netloc_raw.index("]")
        host_part = netloc_raw[: close_idx + 1]
        rest = netloc_raw[close_idx + 1 :]
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in netloc_raw:
        host_part, port = netloc_raw.split(":", 1)
    else:
        host_part = netloc_raw

    # Strip trailing dot
    if host_part.endswith(".") and not host_part.startswith("["):
        host_part = host_part[:-1]

    if not host_part:
        raise ResourceMatchingError("invalid empty host in URL")

    # IDN Punycode
    if not host_part.startswith("["):
        try:
            host_part = host_part.encode("idna").decode("ascii").lower()
        except Exception as exc:
            raise ResourceMatchingError(f"invalid IDN hostname in URL: {exc}") from exc
    else:
        host_part = host_part.lower()

    # Default port removal
    if port:
        try:
            p_val = int(port)
            if not (1 <= p_val <= 65535):
                raise ResourceMatchingError("port out of range (1-65535)")
        except ValueError as exc:
            raise ResourceMatchingError("invalid port in URL") from exc

        if (scheme == "http" and p_val == 80) or (scheme == "https" and p_val == 443):
            port = ""

    normalized_netloc = f"{host_part}:{port}" if port else host_part

    # Path normalization
    raw_path = parts.path or "/"
    norm_path = normalize_path(raw_path)

    return urlunsplit((scheme, normalized_netloc, norm_path, parts.query, parts.fragment))


def normalize_identifier(id_str: str) -> str:
    """Normalize a plain identifier with strict whitespace rejection.

    Rules:
    - Enforce MAX_INPUT_LENGTH limit.
    - Reject empty identifiers.
    - Reject leading or trailing whitespace (strict fail-closed, does NOT strip).
    - Reject NUL bytes.
    """
    if not id_str:
        raise ResourceMatchingError("identifier cannot be empty")
    if len(id_str) > MAX_INPUT_LENGTH:
        raise ResourceMatchingError(f"identifier exceeds maximum length of {MAX_INPUT_LENGTH}")
    if id_str != id_str.strip():
        raise ResourceMatchingError("identifier must not contain leading or trailing whitespace")
    if "\x00" in id_str:
        raise ResourceMatchingError("identifier contains NUL byte")
    return id_str


@functools.lru_cache(maxsize=1024)
def compile_identifier_pattern(pattern: str) -> re.Pattern[str]:
    """Compile an identifier pattern into an anchored regex.

    Wildcard '*' strictly matches [A-Za-z0-9_.-]*.
    """
    if pattern != pattern.strip():
        raise ResourceMatchingError("pattern must not contain leading or trailing whitespace")
    if "\x00" in pattern:
        raise ResourceMatchingError("pattern contains NUL byte")

    res = ["^"]
    for c in pattern:
        if c == "*":
            res.append(r"[A-Za-z0-9_.\-]*")
        else:
            res.append(re.escape(c))
    res.append("$")
    return re.compile("".join(res))


@functools.lru_cache(maxsize=1024)
def compile_host_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a host pattern into an anchored regex."""
    clean = pattern.strip().lower()
    if clean.endswith(".") and not clean.startswith("["):
        clean = clean[:-1]
    res = ["^"]
    for c in clean:
        if c == "*":
            res.append(r"[A-Za-z0-9_.\-]*")
        else:
            res.append(re.escape(c))
    res.append("$")
    return re.compile("".join(res))


def match_host(rule: str, input_host: str) -> bool:
    """Match a normalized hostname against a host pattern."""
    try:
        norm_host = normalize_host(input_host)
    except ResourceMatchingError:
        return False

    try:
        rx = compile_host_pattern(rule)
        return bool(rx.fullmatch(norm_host))
    except ResourceMatchingError:
        return False


def match_identifier(rule: str, input_id: str) -> bool:
    """Match an identifier against an identifier pattern."""
    try:
        norm_id = normalize_identifier(input_id)
        rx = compile_identifier_pattern(rule)
        return bool(rx.fullmatch(norm_id))
    except ResourceMatchingError:
        return False


def match_url(rule: str, input_url: str) -> bool:
    """Match a normalized URL against a URL rule pattern."""
    try:
        norm_input = normalize_url(input_url)
    except ResourceMatchingError:
        return False

    clean_pat = rule.strip()
    if "://" not in clean_pat:
        # Host-only rule pattern
        in_parts = urlsplit(norm_input)
        return match_host(clean_pat, in_parts.netloc)

    try:
        rule_parts = urlsplit(clean_pat)
        rule_scheme = rule_parts.scheme.lower()
        if rule_scheme not in ("http", "https"):
            return False

        in_parts = urlsplit(norm_input)
        if rule_scheme != in_parts.scheme:
            return False

        rule_host = rule_parts.netloc.lower()
        if rule_scheme == "http" and rule_host.endswith(":80"):
            rule_host = rule_host[:-3]
        elif rule_scheme == "https" and rule_host.endswith(":443"):
            rule_host = rule_host[:-4]

        if not match_host(rule_host, in_parts.netloc):
            return False

        rule_path = rule_parts.path or "/"
        in_path = in_parts.path or "/"
        return match_path(rule_path, in_path)
    except Exception:
        return False


def validate_resource_syntax(resource: str, kind: str) -> None:
    """Validate resource syntax according to kind; raises ResourceMatchingError if invalid."""
    kind_lower = (kind or "exact").lower()
    if kind_lower == "path":
        normalize_path(resource)
    elif kind_lower == "url":
        normalize_url(resource)
    elif kind_lower == "host":
        normalize_host(resource)
    elif kind_lower == "identifier":
        normalize_identifier(resource)
    elif kind_lower in ("any", "none"):
        return
    else:
        if "\x00" in resource:
            raise ResourceMatchingError("resource contains NUL byte")
        if len(resource) > MAX_INPUT_LENGTH:
            raise ResourceMatchingError(f"resource exceeds maximum length of {MAX_INPUT_LENGTH}")


def _match_resource_unchecked(rule: str, norm_resource: str, kind: str = "exact", case_sensitive: bool = True) -> bool:
    """Low-level resource matcher. Assumes norm_resource has already been validated."""
    kind_lower = (kind or "exact").lower()
    if kind_lower == "path":
        return _match_path_unchecked(rule, norm_resource, case_sensitive=case_sensitive)
    elif kind_lower == "url":
        return match_url(rule, norm_resource)
    elif kind_lower == "host":
        return match_host(rule, norm_resource)
    elif kind_lower == "identifier":
        return match_identifier(rule, norm_resource)
    elif kind_lower == "any":
        return True
    elif kind_lower == "none":
        return False
    else:
        if not case_sensitive:
            return rule.lower() == norm_resource.lower()
        return rule == norm_resource


def match_resource(rule: str, input_resource: str, kind: str = "exact", case_sensitive: bool = True) -> bool:
    """Safe public resource matcher: validates syntax first then delegates to unchecked matcher."""
    try:
        validate_resource_syntax(input_resource, kind=kind)
    except ResourceMatchingError:
        return False

    kind_lower = (kind or "exact").lower()
    if kind_lower == "path":
        try:
            norm_in = normalize_path(input_resource, case_sensitive=case_sensitive)
        except ResourceMatchingError:
            return False
        return _match_path_unchecked(rule, norm_in, case_sensitive=case_sensitive)

    return _match_resource_unchecked(rule, input_resource, kind=kind, case_sensitive=case_sensitive)
