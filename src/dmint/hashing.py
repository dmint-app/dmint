"""Request fingerprinting."""

from .models import ToolRequest
from .request_binding import request_binding_fingerprint


def request_fingerprint(
    request: ToolRequest,
    *,
    integration_id: str = "local-runtime",
    capability_id: str | None = None,
) -> str:
    """Return the SHA-256 fingerprint of a canonical tool request using JCS request binding."""

    cap = capability_id or f"{request.tool}.{request.action}"
    return request_binding_fingerprint(
        request,
        integration_id=integration_id,
        capability_id=cap,
    )
