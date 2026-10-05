"""HTTP route handlers for Dmint Dashboard.

All routes delegate exclusively to CoreClient which in turn calls Core public
APIs.  No SQL, no private Core attributes, no approval logic lives here.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from dmint import ApprovalState
from dmint.approvals import ApprovalRecord
from dmint.errors import (
    ApprovalConcurrentConsumeError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalStoreError,
    CorruptApprovalRecordError,
    IllegalApprovalTransitionError,
    MalformedApprovalError,
)
from dmint.models import NoResource

from .core_client import CoreClient

log = logging.getLogger("dmint_dashboard")

# Maximum reason length accepted at the HTTP layer (Core enforces 1000).
_MAX_REASON_LENGTH = 500
# Limit for dashboard listing pages.
_LIST_LIMIT = 100
_AUDIT_LIMIT = 200


def build_router() -> APIRouter:
    """Return an APIRouter with all dashboard routes registered."""
    router = APIRouter()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _client(request: Request) -> CoreClient:
        return request.app.state.core_client

    def _templates(request: Request):
        return request.app.state.templates

    def _render(request: Request, template: str, ctx: dict[str, Any], *, status_code: int = 200) -> HTMLResponse:
        ctx["request"] = request
        # Propagate flash messages from query params.
        ctx.setdefault("flash_message", request.query_params.get("msg", ""))
        ctx.setdefault("flash_type", request.query_params.get("msg_type", "info"))
        return _templates(request).TemplateResponse(
            request=request, name=template, context=ctx, status_code=status_code
        )

    def _redirect_with_msg(url: str, *, msg: str, msg_type: str = "success") -> RedirectResponse:
        import urllib.parse

        params = urllib.parse.urlencode({"msg": msg, "msg_type": msg_type})
        return RedirectResponse(f"{url}?{params}", status_code=303)

    def _record_display(record: ApprovalRecord) -> dict[str, Any]:
        """Convert an ApprovalRecord to a template-friendly dict."""
        resource = record.request.resource
        resource_display = resource if isinstance(resource, str) else "(no resource)"
        try:
            args_json = json.dumps(dict(record.request.arguments), indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            args_json = "(could not render)"

        decision_auth = record.decision_authority
        return {
            "approval_id": record.approval_id,
            "request_id": record.request_id,
            "agent_id": record.request.agent_id,
            "tool": record.request.tool,
            "action": record.request.action,
            "resource": resource_display,
            "arguments_json": args_json,
            "integration_id": record.integration_id,
            "capability_id": record.capability_id,
            "fingerprint": record.request_fingerprint,
            "policy_version_id": record.policy_provenance.version_id,
            "policy_digest": record.policy_provenance.policy_digest,
            "policy_evaluated_at": record.policy_provenance.evaluated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "expires_at": record.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "state": record.state.value,
            "state_at": record.state_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "state_reason": record.state_reason or "",
            "decision_at": record.decision_at.strftime("%Y-%m-%d %H:%M:%S UTC") if record.decision_at else "",
            "consumed_at": record.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if record.consumed_at else "",
            "authority_id": decision_auth.authority_id if decision_auth else "",
            "authority_subject": decision_auth.subject_id if decision_auth else "",
            "authority_kind": decision_auth.kind.value if decision_auth else "",
        }

    def _state_badge_class(state: str) -> str:
        return {
            "PENDING": "warning",
            "APPROVED": "success",
            "REJECTED": "danger",
            "CONSUMED": "secondary",
            "EXPIRED": "secondary",
            "CANCELLED": "secondary",
            "POLICY_INVALIDATED": "dark",
        }.get(state, "secondary")

    # ------------------------------------------------------------------
    # GET /health
    # ------------------------------------------------------------------

    @router.get("/health", response_class=JSONResponse)
    def health(request: Request) -> JSONResponse:
        alive = _client(request).ping()
        return JSONResponse({"status": "ok", "core": "ok" if alive else "unavailable"})

    # ------------------------------------------------------------------
    # GET /api/dashboard
    # ------------------------------------------------------------------

    @router.get("/api/dashboard", response_class=JSONResponse)
    def api_dashboard(request: Request) -> JSONResponse:
        client = _client(request)
        error_msg: str | None = None
        try:
            pending_records = client.list_pending(limit=_LIST_LIMIT)
            count_pending = len(pending_records)
            count_approved = client.count_by_state(ApprovalState.APPROVED)
            count_rejected = client.count_by_state(ApprovalState.REJECTED)
        except ApprovalStoreError as exc:
            log.error("store error on api_dashboard: %s", exc)
            pending_records = []
            count_pending = count_approved = count_rejected = 0
            error_msg = str(exc)

        pending = []
        for rec in pending_records:
            resource = rec.request.resource
            pending.append(
                {
                    "approval_id": rec.approval_id,
                    "agent_id": rec.request.agent_id,
                    "tool": rec.request.tool,
                    "action": rec.request.action,
                    "resource": resource if isinstance(resource, str) else "(none)",
                    "created_at": rec.created_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "expires_at": rec.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "state": rec.state.value,
                    "badge": _state_badge_class(rec.state.value),
                }
            )

        response_data: dict[str, Any] = {
            "pending_count": count_pending,
            "approved_count": count_approved,
            "rejected_count": count_rejected,
            "pending": pending,
        }
        if error_msg:
            response_data["error"] = error_msg
        return JSONResponse(response_data)

    # ------------------------------------------------------------------
    # GET /
    # ------------------------------------------------------------------

    @router.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        client = _client(request)
        flash_override: dict[str, str] = {}
        try:
            pending_records = client.list_pending(limit=_LIST_LIMIT)
            count_pending = len(pending_records)
            count_approved = client.count_by_state(ApprovalState.APPROVED)
            count_rejected = client.count_by_state(ApprovalState.REJECTED)
        except ApprovalStoreError as exc:
            log.error("store error on index: %s", exc)
            pending_records = []
            count_pending = count_approved = count_rejected = 0
            if "deployment epoch mismatch" in str(exc).lower():
                flash_override = {
                    "flash_message": (
                        "Deployment Epoch Mismatch: The SQLite database contains records with a different deployment epoch. "
                        "Please restart `dmint dashboard` with the matching `--deployment-epoch` parameter (e.g. `--deployment-epoch prod-v1`)."
                    ),
                    "flash_type": "warning",
                }
            else:
                flash_override = {
                    "flash_message": f"Approval Store Error: {exc}",
                    "flash_type": "danger",
                }

        rows = []
        for rec in pending_records:
            resource = rec.request.resource
            rows.append(
                {
                    "approval_id": rec.approval_id,
                    "agent_id": rec.request.agent_id,
                    "tool": rec.request.tool,
                    "action": rec.request.action,
                    "resource": resource if isinstance(resource, str) else "(none)",
                    "created_at": rec.created_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "expires_at": rec.expires_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "state": rec.state.value,
                    "badge": _state_badge_class(rec.state.value),
                }
            )

        ctx = {
            "count_pending": count_pending,
            "count_approved": count_approved,
            "count_rejected": count_rejected,
            "rows": rows,
        }
        ctx.update(flash_override)
        return _render(request, "index.html", ctx)

    # ------------------------------------------------------------------
    # GET /approvals/{approval_id}
    # ------------------------------------------------------------------

    @router.get("/approvals/{approval_id}", response_class=HTMLResponse)
    def approval_detail(request: Request, approval_id: str) -> HTMLResponse:
        client = _client(request)
        try:
            record = client.get_approval(approval_id)
        except (CorruptApprovalRecordError, MalformedApprovalError):
            return _render(
                request,
                "error.html",
                {
                    "status_code": 404,
                    "detail": "Approval not found.",
                },
            )
        except ApprovalStoreError as exc:
            log.error("store error fetching %s: %s", approval_id, exc)
            return _render(
                request,
                "error.html",
                {
                    "status_code": 500,
                    "detail": "Could not load approval record.",
                },
            )

        if record is None:
            return _render(
                request,
                "error.html",
                {
                    "status_code": 404,
                    "detail": "Approval not found.",
                },
            )

        display = _record_display(record)
        display["badge"] = _state_badge_class(display["state"])
        display["is_pending"] = record.state is ApprovalState.PENDING
        return _render(request, "approval.html", {"record": display})

    # ------------------------------------------------------------------
    # POST /approvals/{approval_id}/approve
    # ------------------------------------------------------------------

    @router.post("/approvals/{approval_id}/approve")
    def approve_approval(request: Request, approval_id: str) -> RedirectResponse:
        client = _client(request)
        detail_url = f"/approvals/{approval_id}"
        try:
            client.approve(approval_id)
        except ApprovalNotFoundError:
            return _redirect_with_msg(detail_url, msg="Approval not found.", msg_type="danger")
        except ApprovalExpiredError:
            return _redirect_with_msg(detail_url, msg="Approval has expired and cannot be approved.", msg_type="danger")
        except ApprovalConcurrentConsumeError:
            return _redirect_with_msg(
                detail_url, msg="A concurrent decision was already made on this approval.", msg_type="warning"
            )
        except IllegalApprovalTransitionError:
            return _redirect_with_msg(detail_url, msg="This approval is not in a pending state.", msg_type="warning")
        except (CorruptApprovalRecordError, MalformedApprovalError) as exc:
            log.warning("approval rejected by Core for %s: %s", approval_id, exc)
            return _redirect_with_msg(detail_url, msg="Invalid approval request.", msg_type="danger")
        except ApprovalStoreError as exc:
            log.error("store error approving %s: %s", approval_id, exc)
            return _redirect_with_msg(detail_url, msg="Internal error. Could not approve.", msg_type="danger")
        return _redirect_with_msg(detail_url, msg="Approval granted successfully.", msg_type="success")

    # ------------------------------------------------------------------
    # POST /approvals/{approval_id}/reject
    # ------------------------------------------------------------------

    @router.post("/approvals/{approval_id}/reject")
    def reject_approval(
        request: Request,
        approval_id: str,
        reason: str = Form(default=""),
    ) -> RedirectResponse:
        client = _client(request)
        detail_url = f"/approvals/{approval_id}"

        # Sanitise reason at the HTTP layer; Core enforces its own limit.
        clean_reason: str | None = reason.strip() if reason else None
        if clean_reason and len(clean_reason) > _MAX_REASON_LENGTH:
            clean_reason = clean_reason[:_MAX_REASON_LENGTH]

        try:
            client.reject(approval_id, reason=clean_reason)
        except ApprovalNotFoundError:
            return _redirect_with_msg(detail_url, msg="Approval not found.", msg_type="danger")
        except ApprovalExpiredError:
            return _redirect_with_msg(detail_url, msg="Approval has expired and cannot be rejected.", msg_type="danger")
        except ApprovalConcurrentConsumeError:
            return _redirect_with_msg(
                detail_url, msg="A concurrent decision was already made on this approval.", msg_type="warning"
            )
        except IllegalApprovalTransitionError:
            return _redirect_with_msg(detail_url, msg="This approval is not in a pending state.", msg_type="warning")
        except (CorruptApprovalRecordError, MalformedApprovalError) as exc:
            log.warning("rejection rejected by Core for %s: %s", approval_id, exc)
            return _redirect_with_msg(detail_url, msg="Invalid rejection request.", msg_type="danger")
        except ApprovalStoreError as exc:
            log.error("store error rejecting %s: %s", approval_id, exc)
            return _redirect_with_msg(detail_url, msg="Internal error. Could not reject.", msg_type="danger")
        return _redirect_with_msg(detail_url, msg="Approval rejected.", msg_type="success")

    # ------------------------------------------------------------------
    # GET /audit
    # ------------------------------------------------------------------

    @router.get("/audit", response_class=HTMLResponse)
    def audit(request: Request) -> HTMLResponse:
        client = _client(request)
        state_filter = request.query_params.get("state")

        try:
            if state_filter:
                try:
                    states = {ApprovalState(state_filter)}
                except ValueError:
                    states = None
            else:
                states = None
            records = client.list_records(states=states, limit=_AUDIT_LIMIT)
        except ApprovalStoreError as exc:
            log.error("store error on audit: %s", exc)
            records = []

        rows = []
        for rec in records:
            resource = rec.request.resource
            auth = rec.decision_authority
            rows.append(
                {
                    "timestamp": rec.state_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "approval_id": rec.approval_id,
                    "agent_id": rec.request.agent_id,
                    "integration_id": rec.integration_id,
                    "tool": rec.request.tool,
                    "action": rec.request.action,
                    "resource": resource if isinstance(resource, str) else "(none)",
                    "state": rec.state.value,
                    "badge": _state_badge_class(rec.state.value),
                    "state_reason": rec.state_reason or "",
                    "actor": auth.subject_id if auth else "",
                }
            )

        return _render(
            request,
            "audit.html",
            {
                "rows": rows,
                "state_filter": state_filter or "",
                "all_states": [s.value for s in ApprovalState],
            },
        )

    return router
