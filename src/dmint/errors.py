"""Stable, machine-readable Dmint errors."""


class DmintError(Exception):
    """Base class for expected Dmint failures."""

    code = "DMT_ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or self.code


class RequestValidationError(DmintError):
    """The request is not a valid Dmint request."""

    code = "DMT_INVALID_REQUEST"


class CanonicalizationError(RequestValidationError):
    """A value cannot be represented unambiguously as canonical JSON."""

    code = "DMT_CANONICALIZATION_ERROR"


class PolicyError(DmintError):
    """The policy is malformed or cannot be evaluated safely."""

    code = "DMT_INVALID_POLICY"


class AuthorizationError(DmintError):
    """Authorization failed; callers must not execute the protected tool."""

    code = "DMT_AUTHORIZATION_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        request_id: str | None = None,
        decision: str | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.request_id = request_id
        self.decision = decision


class ApprovalError(DmintError):
    """Base class for approval-domain failures."""

    code = "DMT_APPROVAL_ERROR"


class MalformedApprovalError(ApprovalError):
    """Approval-domain data is malformed or fails validation."""

    code = "DMT_APPROVAL_MALFORMED"


class UnknownApprovalStateError(MalformedApprovalError):
    """An approval state is not part of the supported state machine."""

    code = "DMT_APPROVAL_UNKNOWN_STATE"


class UnknownApprovalVersionError(MalformedApprovalError):
    """An approval schema, binding, or canonicalization version is unknown."""

    code = "DMT_APPROVAL_UNKNOWN_VERSION"


class IllegalApprovalTransitionError(ApprovalError):
    """An approval state transition is not legal."""

    code = "DMT_APPROVAL_ILLEGAL_TRANSITION"


class ApprovalExpiredError(IllegalApprovalTransitionError):
    """An approval cannot be used because its expiration has passed."""

    code = "DMT_APPROVAL_EXPIRED"


class ApprovalStoreError(ApprovalError):
    """The approval store could not safely complete an operation."""

    code = "DMT_APPROVAL_STORE_ERROR"


class ApprovalNotFoundError(ApprovalStoreError):
    """No approval record exists for the requested identity."""

    code = "DMT_APPROVAL_NOT_FOUND"


class CorruptApprovalRecordError(ApprovalStoreError):
    """Stored approval data failed strict validation."""

    code = "DMT_APPROVAL_CORRUPT"


class ApprovalInvalidError(ApprovalError):
    """The approval assertion is not valid for the requested operation."""

    code = "DMT_APPROVAL_INVALID"


class ApprovalSignatureInvalidError(ApprovalError):
    """The approval assertion signature does not verify."""

    code = "DMT_APPROVAL_SIGNATURE_INVALID"


class ApprovalIssuerInvalidError(ApprovalError):
    """The assertion issuer is not trusted by this verifier."""

    code = "DMT_APPROVAL_ISSUER_INVALID"


class ApprovalAudienceInvalidError(ApprovalError):
    """The assertion is not addressed to this Dmint integration."""

    code = "DMT_APPROVAL_AUDIENCE_INVALID"


class ApprovalPrincipalMismatchError(ApprovalError):
    """The assertion principal does not match the exact request."""

    code = "DMT_APPROVAL_PRINCIPAL_MISMATCH"


class ApprovalIntegrationMismatchError(ApprovalError):
    """The assertion integration does not match the exact request."""

    code = "DMT_APPROVAL_INTEGRATION_MISMATCH"


class ApprovalVersionUnsupportedError(ApprovalError):
    """The assertion credential version is unsupported."""

    code = "DMT_APPROVAL_VERSION_UNSUPPORTED"


class ApprovalNotApprovedError(ApprovalError):
    """The approval is not in the APPROVED state."""

    code = "DMT_APPROVAL_NOT_APPROVED"


class ApprovalConsumedError(ApprovalError):
    """The approval was already consumed."""

    code = "DMT_APPROVAL_CONSUMED"


class ApprovalRequestMismatchError(ApprovalError):
    """The expected retry request does not match the approval."""

    code = "DMT_APPROVAL_REQUEST_MISMATCH"


class ApprovalPolicyInvalidError(ApprovalError):
    """The approval cannot proceed under current policy provenance."""

    code = "DMT_APPROVAL_POLICY_INVALID"


class ApprovalDeploymentInvalidError(ApprovalError):
    """The approval belongs to another deployment epoch."""

    code = "DMT_APPROVAL_DEPLOYMENT_INVALID"


class ApprovalConcurrentConsumeError(ApprovalError):
    """Another consumer won the approval consumption race."""

    code = "DMT_APPROVAL_CONCURRENT_CONSUME"


class ApprovalRequiredError(AuthorizationError):
    """Execution stopped pending trusted approval of one exact request."""

    code = "DMT_APPROVAL_REQUIRED"

    def __init__(
        self,
        message: str,
        *,
        request_id: str,
        approval_id: str,
        request_fingerprint: str,
    ) -> None:
        super().__init__(message, code=self.code, request_id=request_id)
        self.approval_id = approval_id
        self.request_fingerprint = request_fingerprint


class ExecutionError(DmintError):
    """The protected tool failed after authorization and consumption."""

    code = "DMT_EXECUTION_FAILED"


class ApprovalAlgorithmUnsupportedError(ApprovalError):
    """The assertion signing algorithm is not explicitly allowed."""

    code = "DMT_APPROVAL_ALGORITHM_UNSUPPORTED"


class ApprovalMalformedError(ApprovalError):
    """The serialized approval assertion is malformed."""

    code = "DMT_APPROVAL_MALFORMED"


class ApprovalCredentialInvalidError(ApprovalError):
    """The supplied retry credential is malformed or invalid."""

    code = "DMT_APPROVAL_CREDENTIAL_INVALID"
