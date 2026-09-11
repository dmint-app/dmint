"""Synchronous, request-bound pre-execution enforcement."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, TypeVar, cast

from .approvals import ApprovalRecord, new_request_id
from .authority import ApprovalAssertion, ApprovalVerifier
from .canonicalize import freeze_json, thaw_json
from .errors import (
    ApprovalPolicyInvalidError,
    ApprovalCredentialInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    ExecutionError,
    RequestValidationError,
)
from .hashing import request_fingerprint
from .models import Decision, NO_RESOURCE, NoResource, ToolRequest, TrustedContext, validate_text
from .policy import Policy
from .approvals import PolicyProvenance
from .storage import SQLiteApprovalStore

F = TypeVar("F", bound=Callable[..., Any])
ResourceResolver = Callable[[Mapping[str, Any]], str]
ResourceSpec = NoResource | ResourceResolver

_AUTHORIZATION_TOKEN = object()


@dataclass(frozen=True)
class _ProtectedBinding:
    owner: "Dmint"
    function: Callable[..., Any]
    capability: str
    resource: ResourceSpec


def _capability_parts(capability: str) -> tuple[str, str]:
    validate_text(capability, "capability")
    tool, separator, action = capability.partition(".")
    if not separator or not tool or not action:
        raise RequestValidationError("capability must have the form tool.action")
    return tool, action


@dataclass(frozen=True)
class InvocationSnapshot:
    """Immutable JSON-normalized values plus the function's call signature."""

    signature: inspect.Signature
    arguments: Mapping[str, Any]

    @classmethod
    def from_bound(cls, bound: inspect.BoundArguments) -> "InvocationSnapshot":
        frozen_arguments: dict[str, Any] = {}
        for name, value in bound.arguments.items():
            parameter = bound.signature.parameters[name]
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                if type(value) is not tuple:
                    raise RequestValidationError("invalid variadic argument snapshot")
                value = list(value)
            frozen_arguments[name] = freeze_json(value, f"arguments.{name}")
        return cls(bound.signature, MappingProxyType(frozen_arguments))

    def as_arguments(self) -> dict[str, Any]:
        """Return a fresh JSON-native mapping for ToolRequest construction."""

        return thaw_json(self.arguments)

    def as_bound_arguments(self) -> inspect.BoundArguments:
        """Rebuild BoundArguments, then let inspect determine call semantics."""

        arguments = self.as_arguments()
        for name, parameter in self.signature.parameters.items():
            if name not in arguments:
                continue
            if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
                arguments[name] = tuple(arguments[name])
            elif parameter.kind is inspect.Parameter.VAR_KEYWORD:
                arguments[name] = dict(arguments[name])
        return inspect.BoundArguments(self.signature, arguments)


class AuthorizedRequest:
    """Opaque local capability binding one request to one invocation snapshot."""

    __slots__ = ("_token", "_owner", "_function", "_request", "_snapshot")

    def __init__(
        self,
        token: object,
        owner: "Dmint",
        function: Callable[..., Any],
        request: ToolRequest,
        snapshot: InvocationSnapshot,
    ) -> None:
        if token is not _AUTHORIZATION_TOKEN:
            raise TypeError("AuthorizedRequest instances are created by Dmint")
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_function", function)
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_snapshot", snapshot)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("AuthorizedRequest is immutable")

    @property
    def request(self) -> ToolRequest:
        return self._request

    @property
    def fingerprint(self) -> str:
        return request_fingerprint(
            self._request,
            integration_id=self._owner._integration_id,
            capability_id=f"{self._request.tool}.{self._request.action}",
        )


def _validate_function(function: Any) -> Callable[..., Any]:
    if not callable(function):
        raise RequestValidationError("protected target must be callable")
    if inspect.iscoroutinefunction(function):
        raise RequestValidationError("async functions are not supported in Phase 1")
    if hasattr(function, "__wrapped__"):
        raise RequestValidationError(
            "Dmint must wrap the actual function, not a functools-wrapped callable"
        )
    return cast(Callable[..., Any], function)


def _resolve_resource(resource: ResourceSpec, arguments: Mapping[str, Any]) -> str | NoResource:
    if type(resource) is NoResource:
        return resource
    if not callable(resource):
        raise RequestValidationError(
            "resource must be NO_RESOURCE or a resolver over bound arguments"
        )
    value = resource(arguments)
    if type(value) is not str:
        raise RequestValidationError("resource resolver must return a string")
    return validate_text(value, "resolved resource")


class Dmint:
    """Authorize and execute one immutable invocation snapshot at a time."""

    __slots__ = (
        "_policy",
        "_agent_id",
        "_context",
        "_integration_id",
        "_approval_store",
        "_approval_verifier",
        "_policy_provenance",
        "_approval_ttl",
        "_clock",
        "_registered",
        "_sealed",
    )

    def __init__(
        self,
        policy: Policy,
        *,
        agent_id: str,
        context: TrustedContext,
        integration_id: str = "local-runtime",
        approval_store: SQLiteApprovalStore | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        policy_provenance: PolicyProvenance | None = None,
        approval_ttl: timedelta | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        if type(context) is not TrustedContext:
            raise TypeError("context must be TrustedContext")
        if type(integration_id) is not str or not integration_id or integration_id != integration_id.strip():
            raise TypeError("integration_id must be a non-empty string")
        if approval_store is not None and type(approval_store) is not SQLiteApprovalStore:
            raise TypeError("approval_store must be SQLiteApprovalStore")
        if approval_verifier is not None and type(approval_verifier) is not ApprovalVerifier:
            raise TypeError("approval_verifier must be ApprovalVerifier")
        if policy_provenance is not None and type(policy_provenance) is not PolicyProvenance:
            raise TypeError("policy_provenance must be PolicyProvenance")
        if approval_ttl is not None and (
            type(approval_ttl) is not timedelta or approval_ttl <= timedelta(0)
        ):
            raise TypeError("approval_ttl must be a positive timedelta")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_agent_id", validate_text(agent_id, "agent_id"))
        object.__setattr__(self, "_context", context)
        object.__setattr__(self, "_integration_id", integration_id)
        object.__setattr__(self, "_approval_store", approval_store)
        object.__setattr__(self, "_approval_verifier", approval_verifier)
        object.__setattr__(self, "_policy_provenance", policy_provenance)
        object.__setattr__(self, "_approval_ttl", approval_ttl)
        object.__setattr__(self, "_clock", clock or (lambda: datetime.now(timezone.utc)))
        object.__setattr__(self, "_registered", {})
        object.__setattr__(self, "_sealed", True)
        if approval_store is not None and policy_provenance is not None:
            if approval_store.get_authoritative_policy() is None:
                approval_store.set_authoritative_policy(policy, policy_provenance)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("Dmint configuration is immutable")
        object.__setattr__(self, name, value)

    def _evaluate_decision(self, request: ToolRequest) -> Decision:
        if type(request) is not ToolRequest:
            raise AuthorizationError("invalid authorization request", code="DMT_INVALID_REQUEST")
        if request.agent_id != self._agent_id or request.context.values != self._context.values:
            raise AuthorizationError(
                "request identity or trusted context mismatch",
                code="DMT_INVALID_REQUEST",
                request_id=request.request_id,
            )
        try:
            decision = self._policy.evaluate(request)
        except Exception as exc:
            raise AuthorizationError(
                "authorization failed",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            ) from exc
        if decision not in (Decision.ALLOW, Decision.DENY, Decision.APPROVAL_REQUIRED):
            raise AuthorizationError(
                "authorization returned an invalid decision",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            )
        return decision

    def _evaluate(self, request: ToolRequest) -> Decision:
        decision = self._evaluate_decision(request)
        if decision is Decision.DENY:
            raise AuthorizationError(
                "policy denied the request",
                code="DMT_POLICY_DENIED",
                request_id=request.request_id,
                decision=decision.value,
            )
        if decision is Decision.APPROVAL_REQUIRED:
            raise AuthorizationError(
                "approval is required",
                code="DMT_APPROVAL_REQUIRED",
                request_id=request.request_id,
            )
        return decision

    def register(
        self,
        function: Callable[..., Any],
        capability: str,
        *,
        resource: ResourceSpec = NO_RESOURCE,
    ) -> Callable[..., Any]:
        """Register a target callable for a capability on this Dmint instance."""

        _capability_parts(capability)
        if type(resource) is not NoResource and not callable(resource):
            raise RequestValidationError(
                "resource must be NO_RESOURCE or a resolver over bound arguments"
            )
        target = _validate_function(function)
        binding = _ProtectedBinding(self, target, capability, resource)
        self._registered[id(target)] = binding
        target.__dmint_binding__ = binding
        return target

    def _prepare_call(
        self,
        function: Callable[..., Any],
        call_args: tuple[Any, ...],
        call_kwargs: Mapping[str, Any],
        *,
        capability: str,
        resource: ResourceSpec,
        request_id: str | None = None,
    ) -> tuple[Callable[..., Any], InvocationSnapshot, ToolRequest]:
        tool, action = _capability_parts(capability)
        function = _validate_function(function)
        binding = getattr(function, "__dmint_binding__", None) or self._registered.get(id(function))
        if binding is None or binding.owner is not self or binding.capability != capability:
            raise AuthorizationError(
                "callable is not registered for capability on this Dmint instance",
                code="DMT_AUTHORIZATION_FAILED",
            )
        target = binding.function
        signature = inspect.signature(target)
        bound = signature.bind(*call_args, **call_kwargs)
        bound.apply_defaults()
        snapshot = InvocationSnapshot.from_bound(bound)
        request = ToolRequest(
            request_id=request_id or new_request_id(),
            agent_id=self._agent_id,
            tool=tool,
            action=action,
            resource=_resolve_resource(resource, snapshot.arguments),
            arguments=snapshot.as_arguments(),
            context=self._context,
        )
        return target, snapshot, request

    def _persist_pending(self, request: ToolRequest) -> None:
        if self._approval_store is None or self._policy_provenance is None or self._approval_ttl is None:
            raise AuthorizationError(
                "approval storage and policy provenance are required",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            )
        now = self._clock()
        provenance = PolicyProvenance(
            self._policy_provenance.version_id,
            self._policy_provenance.policy_digest,
            now,
        )
        record = ApprovalRecord.create(
            request=request,
            integration_id=self._integration_id,
            capability_id=f"{request.tool}.{request.action}",
            policy_provenance=provenance,
            created_at=now,
            expires_at=now + self._approval_ttl,
        )
        try:
            persisted = self._approval_store.save_pending(record)
        except Exception as exc:
            raise AuthorizationError(
                "approval request could not be persisted",
                code="DMT_AUTHORIZATION_ERROR",
                request_id=request.request_id,
            ) from exc
        raise ApprovalRequiredError(
            "trusted approval is required",
            request_id=persisted.request_id,
            approval_id=persisted.approval_id,
            request_fingerprint=persisted.request_fingerprint,
        )

    def _authorize_call(
        self,
        function: Callable[..., Any],
        call_args: tuple[Any, ...],
        call_kwargs: Mapping[str, Any],
        *,
        capability: str,
        resource: ResourceSpec,
    ) -> AuthorizedRequest:
        function, snapshot, request = self._prepare_call(
            function,
            call_args,
            call_kwargs,
            capability=capability,
            resource=resource,
        )
        decision = self._evaluate_decision(request)
        if decision is Decision.APPROVAL_REQUIRED:
            self._persist_pending(request)
        if decision is Decision.DENY:
            raise AuthorizationError(
                "policy denied the request",
                code="DMT_POLICY_DENIED",
                request_id=request.request_id,
                decision=decision.value,
            )
        return AuthorizedRequest(_AUTHORIZATION_TOKEN, self, function, request, snapshot)

    def authorize(
        self,
        function: F,
        *args: Any,
        capability: str,
        resource: ResourceSpec = NO_RESOURCE,
        **kwargs: Any,
    ) -> AuthorizedRequest:
        """Authorize a callable and its exact arguments as one capability."""

        try:
            return self._authorize_call(
                function,
                args,
                kwargs,
                capability=capability,
                resource=resource,
            )
        except AuthorizationError:
            raise
        except Exception as exc:
            raise AuthorizationError("authorization failed", code="DMT_AUTHORIZATION_ERROR") from exc

    def execute(self, authorized: AuthorizedRequest) -> Any:
        """Execute only the callable and snapshot contained in an authorization artifact."""

        if (
            type(authorized) is not AuthorizedRequest
            or authorized._token is not _AUTHORIZATION_TOKEN
            or authorized._owner is not self
        ):
            raise AuthorizationError(
                "invalid authorization artifact",
                code="DMT_INVALID_AUTHORIZATION",
            )
        self._evaluate(authorized._request)
        return self._execute_snapshot(authorized._function, authorized._snapshot, authorized._request.request_id)

    def _execute_snapshot(
        self,
        function: Callable[..., Any],
        snapshot: InvocationSnapshot,
        request_id: str,
    ) -> Any:
        try:
            bound = snapshot.as_bound_arguments()
        except Exception as exc:
            raise AuthorizationError(
                "invalid authorized invocation",
                code="DMT_INVALID_AUTHORIZATION",
                request_id=request_id,
            ) from exc
        return function(*bound.args, **bound.kwargs)

    def retry(
        self,
        protected_callable: Callable[..., Any],
        *args: Any,
        approval_credential: ApprovalAssertion | bytes,
        **kwargs: Any,
    ) -> Any:
        """Verify, atomically consume, and execute one exact approved retry."""

        binding = getattr(protected_callable, "__dmint_binding__", None)
        if type(binding) is not _ProtectedBinding or binding.owner is not self:
            raise AuthorizationError(
                "retry requires a callable protected by this Dmint instance",
                code="DMT_AUTHORIZATION_FAILED",
            )
        if self._approval_store is None or self._approval_verifier is None:
            raise AuthorizationError("approval retry is not configured", code="DMT_AUTHORIZATION_FAILED")
        if type(approval_credential) is bytes:
            try:
                approval_credential = ApprovalAssertion.from_bytes(approval_credential)
            except Exception as exc:
                raise ApprovalCredentialInvalidError("approval credential is invalid") from exc
        if type(approval_credential) is not ApprovalAssertion:
            raise ApprovalCredentialInvalidError("approval credential is invalid")
        verification_time = self._clock()
        record = self._approval_store.get(approval_credential.approval_id)
        if record is None:
            raise AuthorizationError("approval not found", code="DMT_APPROVAL_NOT_FOUND")
        function, snapshot, request = self._prepare_call(
            binding.function,
            args,
            kwargs,
            capability=binding.capability,
            resource=binding.resource,
            request_id=record.request_id,
        )
        store_policy_info = self._approval_store.get_authoritative_policy()
        if store_policy_info is not None:
            store_policy, store_provenance = store_policy_info
            if (
                record.policy_provenance.version_id != store_provenance.version_id
                or record.policy_provenance.policy_digest != store_provenance.policy_digest
            ):
                if record.state is not None and record.state.value == "APPROVED":
                    self._approval_store.invalidate_approved(
                        record,
                        reason="shared store policy provenance changed",
                    )
                raise ApprovalPolicyInvalidError("approval policy provenance is stale per shared store")
            store_decision = store_policy.evaluate(request)
            if store_decision is Decision.DENY:
                if record.state is not None and record.state.value == "APPROVED":
                    self._approval_store.invalidate_approved(
                        record,
                        reason="shared store policy denied request",
                    )
                raise ApprovalPolicyInvalidError("current shared store policy denies the approved request")

        if self._policy_provenance is None:
            raise ApprovalPolicyInvalidError("current policy provenance is unavailable")
        if (
            record.policy_provenance.version_id != self._policy_provenance.version_id
            or record.policy_provenance.policy_digest != self._policy_provenance.policy_digest
        ):
            if record.state is not None and record.state.value == "APPROVED":
                self._approval_store.invalidate_approved(
                    record,
                    reason="policy provenance changed",
                )
            raise ApprovalPolicyInvalidError("approval policy provenance is stale")
        decision = self._evaluate_decision(request)
        if decision is Decision.DENY:
            if record.state.value == "APPROVED":
                self._approval_store.invalidate_approved(
                    record,
                    reason="current policy denied request",
                )
            raise ApprovalPolicyInvalidError("current policy denies the approved request")
        consumed = self._approval_store.consume_approved(
            approval_id=record.approval_id,
            credential=approval_credential,
            expected_request=request,
            verifier=self._approval_verifier,
        )
        try:
            return self._execute_snapshot(function, snapshot, consumed.request_id)
        except Exception as exc:
            raise ExecutionError("protected tool execution failed") from exc

    def protected(
        self,
        capability: str,
        *,
        resource: ResourceSpec = NO_RESOURCE,
    ) -> Callable[[F], F]:
        """Protect a synchronous function using one immutable invocation snapshot."""

        _capability_parts(capability)
        if type(resource) is not NoResource and not callable(resource):
            raise RequestValidationError(
                "resource must be NO_RESOURCE or a resolver over bound arguments"
            )

        def decorator(function: F) -> F:
            target = self.register(function, capability, resource=resource)
            binding = self._registered[id(target)]
            signature = inspect.signature(target)

            def guarded(*args: Any, **kwargs: Any) -> Any:
                try:
                    authorized = self._authorize_call(
                        target,
                        args,
                        kwargs,
                        capability=capability,
                        resource=resource,
                    )
                except AuthorizationError:
                    raise
                except Exception as exc:
                    raise AuthorizationError("authorization failed", code="DMT_AUTHORIZATION_ERROR") from exc
                return self.execute(authorized)

            guarded.__name__ = target.__name__
            guarded.__qualname__ = target.__qualname__
            guarded.__doc__ = target.__doc__
            guarded.__annotations__ = getattr(target, "__annotations__", {})
            guarded.__signature__ = signature
            guarded.__dmint_binding__ = binding
            self._registered[id(guarded)] = binding
            return cast(F, guarded)

        return decorator
