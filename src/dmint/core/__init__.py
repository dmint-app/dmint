from typing import TYPE_CHECKING, Any

from dmint.version import __version__

if TYPE_CHECKING:
    from .authority import LocalApprovalAuthority
    from .keys import (
        load_private_key,
        load_private_key_from_file,
        write_private_key_atomic,
    )


from .approvals import (
    APPROVAL_RECORD_SCHEMA_VERSION,
    CANONICALIZATION_PROFILE,
    REQUEST_BINDING_VERSION,
    ApprovalAuthority,
    ApprovalAuthorityKind,
    ApprovalRecord,
    ApprovalState,
    PolicyProvenance,
    new_approval_id,
    new_request_id,
    parse_approval_state,
)
from .verification import (
    ApprovalAssertion,
    ApprovalVerifier,
    VerifiedApproval,
    public_key_from_hex,
    public_key_from_pem,
    public_key_hex,
    public_key_pem,
)
from .canonicalize import MAX_SAFE_INTEGER, canonicalize, canonicalize_request
from .enforcement import AuthorizedRequest, Dmint, InvocationSnapshot
from .redaction import redact_database_url
from .errors import (
    ApprovalAlgorithmUnsupportedError,
    ApprovalAudienceInvalidError,
    ApprovalConcurrentConsumeError,
    ApprovalCredentialInvalidError,
    ApprovalConsumedError,
    ApprovalDeploymentInvalidError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalIntegrationMismatchError,
    ApprovalInvalidError,
    ApprovalIssuerInvalidError,
    ApprovalMalformedError,
    ApprovalNotFoundError,
    ApprovalNotApprovedError,
    ApprovalPolicyInvalidError,
    ApprovalPrincipalMismatchError,
    ApprovalRequestMismatchError,
    ApprovalRequiredError,
    ApprovalSignatureInvalidError,
    ApprovalStoreConfigurationError,
    ApprovalStoreError,
    ApprovalVersionUnsupportedError,
    AuthorizationError,
    CanonicalizationError,
    CorruptApprovalRecordError,
    DmintError,
    ExecutionError,
    IllegalApprovalTransitionError,
    KeyExistsError,
    KeyLoadError,
    KeyPermissionError,
    MalformedApprovalError,
    PolicyError,
    RequestValidationError,
    UnknownApprovalStateError,
    UnknownApprovalVersionError,
)
from .hashing import request_fingerprint
from .models import (
    ANY_RESOURCE,
    NO_RESOURCE,
    AnyResource,
    Decision,
    NoResource,
    ToolRequest,
    TrustedContext,
)
from .policy import Condition, ConditionOperator, Policy, Rule, policy_digest
from .request_binding import (
    canonical_request_binding,
    request_binding_envelope,
    request_binding_fingerprint,
)
from .storage import (
    ApprovalStore,
    SQLAlchemyApprovalStore,
    SQLiteApprovalStore,
    ThreadSafeApprovalStore,
    create_approval_store,
)
from .versions import APPROVAL_CREDENTIAL_VERSION, APPROVAL_SIGNATURE_ALGORITHM
from .webhooks import (
    WebhookConfig,
    WebhookNotifier,
    build_discord_payload,
    build_slack_payload,
    build_teams_payload,
    build_denial_payload,
    dispatch_approval_webhook,
    dispatch_denial_webhook,
)

__all__ = [
    "__version__",
    "AuthorizationError",
    "AuthorizedRequest",
    "ANY_RESOURCE",
    "APPROVAL_RECORD_SCHEMA_VERSION",
    "ApprovalAuthority",
    "ApprovalAuthorityKind",
    "APPROVAL_CREDENTIAL_VERSION",
    "ApprovalAlgorithmUnsupportedError",
    "ApprovalAudienceInvalidError",
    "ApprovalConcurrentConsumeError",
    "ApprovalCredentialInvalidError",
    "ApprovalConsumedError",
    "ApprovalDeploymentInvalidError",
    "ApprovalAssertion",
    "ApprovalError",
    "ApprovalExpiredError",
    "ApprovalIntegrationMismatchError",
    "ApprovalInvalidError",
    "ApprovalIssuerInvalidError",
    "ApprovalMalformedError",
    "ApprovalNotFoundError",
    "ApprovalNotApprovedError",
    "ApprovalPolicyInvalidError",
    "ApprovalPrincipalMismatchError",
    "ApprovalRecord",
    "ApprovalSignatureInvalidError",
    "ApprovalState",
    "ApprovalRequestMismatchError",
    "ApprovalRequiredError",
    "APPROVAL_SIGNATURE_ALGORITHM",
    "ApprovalVerifier",
    "ApprovalVersionUnsupportedError",
    "CANONICALIZATION_PROFILE",
    "CanonicalizationError",
    "Condition",
    "ConditionOperator",
    "CorruptApprovalRecordError",
    "Decision",
    "Dmint",
    "DmintError",
    "ExecutionError",
    "IllegalApprovalTransitionError",
    "InvocationSnapshot",
    "MAX_SAFE_INTEGER",
    "MalformedApprovalError",
    "LocalApprovalAuthority",
    "NO_RESOURCE",
    "NoResource",
    "AnyResource",
    "Policy",
    "PolicyProvenance",
    "PolicyError",
    "policy_digest",
    "REQUEST_BINDING_VERSION",
    "RequestValidationError",
    "Rule",
    "ApprovalStore",
    "ApprovalStoreConfigurationError",
    "SQLAlchemyApprovalStore",
    "SQLiteApprovalStore",
    "ThreadSafeApprovalStore",
    "create_approval_store",
    "ApprovalStoreError",
    "ToolRequest",
    "TrustedContext",
    "UnknownApprovalStateError",
    "UnknownApprovalVersionError",
    "VerifiedApproval",
    "canonicalize",
    "canonicalize_request",
    "redact_database_url",
    "canonical_request_binding",
    "request_fingerprint",
    "request_binding_envelope",
    "request_binding_fingerprint",
    "new_approval_id",
    "new_request_id",
    "parse_approval_state",
    "WebhookConfig",
    "WebhookNotifier",
    "build_slack_payload",
    "build_discord_payload",
    "build_teams_payload",
    "build_denial_payload",
    "dispatch_approval_webhook",
    "dispatch_denial_webhook",
    # Key management
    "KeyExistsError",
    "KeyLoadError",
    "KeyPermissionError",
    "load_private_key",
    "load_private_key_from_file",
    "public_key_from_hex",
    "public_key_from_pem",
    "public_key_hex",
    "public_key_pem",
    "write_private_key_atomic",
]


def __getattr__(name: str) -> Any:
    if name == "LocalApprovalAuthority":
        from .authority import LocalApprovalAuthority

        return LocalApprovalAuthority
    if name in ("load_private_key", "load_private_key_from_file", "write_private_key_atomic"):
        from .keys import (
            load_private_key,
            load_private_key_from_file,
            write_private_key_atomic,
        )

        return {
            "load_private_key": load_private_key,
            "load_private_key_from_file": load_private_key_from_file,
            "write_private_key_atomic": write_private_key_atomic,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
