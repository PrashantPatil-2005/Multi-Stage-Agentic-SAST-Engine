"""Human-in-the-loop approval service.

Approval is a *permission state*: ``approve(...)`` only flips state and
records an audit event. It never modifies source code, executes commands,
runs a shell, deploys anything, creates commits, calls external services or
calls an LLM.

State machine (transitions only move forward; approved/rejected are
terminal)::

    pending ──┬─→ approved           (terminal)
              ├─→ rejected           (terminal)
              └─→ changes_requested
    changes_requested ──→ pending    (new review cycle; version + 1)

Eligibility (default policy): a request may only be created for a finding
whose VALIDATE verdict is ``true_positive`` AND whose PROVE status is
``verified``. Gate failures raise :class:`ApprovalGateError`.

Idempotency: an existing *active* request (pending / changes_requested) for
the same finding + action is returned instead of creating a duplicate.
After a terminal state, a new request is only allowed when the policy
permits re-requests.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from app.approval.models import (
    ApprovalAction,
    ApprovalEvent,
    ApprovalRequest,
    ApprovalStatus,
)
from app.approval.policies import ApprovalPolicy
from app.approval.store import get_approval_store
from app.prove.store import get_proof_store
from app.validate.store import get_validation_store

logger = logging.getLogger(__name__)

ALLOWED_TRANSITIONS: dict[ApprovalStatus, frozenset[ApprovalStatus]] = {
    "pending": frozenset({"approved", "rejected", "changes_requested"}),
    "changes_requested": frozenset({"pending"}),
    "approved": frozenset(),
    "rejected": frozenset(),
}

ACTIVE_STATUSES = frozenset({"pending", "changes_requested"})
TERMINAL_STATUSES = frozenset({"approved", "rejected"})


class ApprovalGateError(RuntimeError):
    """Raised when a finding is not eligible for an approval request."""


class InvalidTransitionError(RuntimeError):
    """Raised when an approval state transition is not allowed."""


def _ensure_aware_utc(value: datetime, what: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(
            f"{what} must be a timezone-aware datetime (naive datetimes are not allowed)"
        )
    return value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:32] + uuid.uuid4().hex[:32]


class ApprovalService:
    def __init__(self, policy: ApprovalPolicy | None = None) -> None:
        self._policy = policy or ApprovalPolicy()

    @property
    def policy(self) -> ApprovalPolicy:
        return self._policy

    # ---------------------------------------------------------------- create

    def request_approval(
        self,
        finding_id: str,
        action: ApprovalAction = "remediation",
        requested_by: str = "system",
        requested_at: datetime | None = None,
        scan_run_id: str | None = None,
    ) -> ApprovalRequest:
        store = get_approval_store()

        existing = self._find_active(store, finding_id, action)
        if existing is not None:
            logger.info(
                "approval: reusing active request %s for finding %s",
                existing.id[:12], finding_id,
            )
            return existing

        terminal = store.find_for_finding(finding_id)
        if terminal is not None and terminal.status in TERMINAL_STATUSES:
            if not self._policy.allow_re_request_after_terminal:
                raise ApprovalGateError(
                    f"finding {finding_id} already has a terminal approval "
                    f"({terminal.status}); re-request not permitted by policy"
                )

        self._check_eligibility(finding_id)
        now = _ensure_aware_utc(requested_at or _utcnow(), "requested_at")
        request = ApprovalRequest(
            id=_new_id(finding_id, action, now.isoformat()),
            finding_id=finding_id,
            status="pending",
            requested_at=now,
            requested_by=requested_by,
            action=action,
            version=1,
            scan_run_id=scan_run_id,
        )
        store.save(request)
        store.record_event(
            ApprovalEvent(
                id=_new_id(request.id, "pending", now.isoformat()),
                approval_id=request.id,
                finding_id=finding_id,
                previous_status=None,
                new_status="pending",
                actor=requested_by,
                reason=None,
                created_at=now,
            )
        )
        logger.info(
            "approval: created %s for finding %s (%s, v%d)",
            request.id[:12], finding_id, action, request.version,
        )
        return request

    def _find_active(
        self, store, finding_id: str, action: str
    ) -> ApprovalRequest | None:
        return store.find_active(finding_id, action, ACTIVE_STATUSES)

    # ---------------------------------------------------------------- gates

    def _check_eligibility(self, finding_id: str) -> None:
        policy = self._policy
        validation = (
            get_validation_store().get(finding_id)
            if policy.require_validation
            else None
        )
        if policy.require_validation:
            if validation is None:
                raise ApprovalGateError(
                    f"finding {finding_id} has not been validated; "
                    "approval requires VALIDATE verdict true_positive"
                )
            if validation.verdict != "true_positive":
                raise ApprovalGateError(
                    f"finding {finding_id} is not eligible for approval: "
                    f"VALIDATE verdict is {validation.verdict} "
                    "(requires true_positive)"
                )
        if policy.require_proof:
            proof = get_proof_store().get(finding_id)
            if proof is None:
                raise ApprovalGateError(
                    f"finding {finding_id} has not been proven; "
                    "approval requires PROVE status verified"
                )
            if proof.status != "verified":
                raise ApprovalGateError(
                    f"finding {finding_id} is not eligible for approval: "
                    f"PROVE status is {proof.status} (requires verified)"
                )

    # ---------------------------------------------------------- transitions

    def approve(
        self,
        approval_id: str,
        reviewed_by: str,
        reason: str | None = None,
        reviewed_at: datetime | None = None,
    ) -> ApprovalRequest:
        return self._transition(
            approval_id, "approved", reviewed_by, reason, reviewed_at
        )

    def reject(
        self,
        approval_id: str,
        reviewed_by: str,
        reason: str | None = None,
        reviewed_at: datetime | None = None,
    ) -> ApprovalRequest:
        return self._transition(
            approval_id, "rejected", reviewed_by, reason, reviewed_at
        )

    def request_changes(
        self,
        approval_id: str,
        reviewed_by: str,
        reason: str | None = None,
        reviewed_at: datetime | None = None,
    ) -> ApprovalRequest:
        return self._transition(
            approval_id, "changes_requested", reviewed_by, reason, reviewed_at
        )

    def resubmit(
        self,
        approval_id: str,
        reviewed_by: str,
        reason: str | None = None,
        reviewed_at: datetime | None = None,
    ) -> ApprovalRequest:
        """changes_requested -> pending (new review cycle; version + 1)."""
        return self._transition(
            approval_id, "pending", reviewed_by, reason, reviewed_at
        )

    def _transition(
        self,
        approval_id: str,
        new_status: ApprovalStatus,
        actor: str,
        reason: str | None,
        reviewed_at: datetime | None,
    ) -> ApprovalRequest:
        store = get_approval_store()
        request = store.get(approval_id)
        if request is None:
            raise InvalidTransitionError(
                f"unknown approval request: {approval_id}"
            )
        allowed = ALLOWED_TRANSITIONS[request.status]
        if new_status not in allowed:
            raise InvalidTransitionError(
                f"invalid approval transition: {request.status} -> "
                f"{new_status} is not allowed"
            )
        now = _ensure_aware_utc(reviewed_at or _utcnow(), "reviewed_at")

        version = request.version
        if request.status == "changes_requested" and new_status == "pending":
            version += 1  # new review cycle

        updated = request.model_copy(
            update={
                "status": new_status,
                "reviewed_at": now,
                "reviewed_by": actor,
                "reason": reason,
                "version": version,
            }
        )
        store.save(updated)
        store.record_event(
            ApprovalEvent(
                id=_new_id(request.id, new_status, now.isoformat(), actor),
                approval_id=request.id,
                finding_id=request.finding_id,
                previous_status=request.status,
                new_status=new_status,
                actor=actor,
                reason=reason,
                created_at=now,
            )
        )
        logger.info(
            "approval: %s %s -> %s by %s (v%d)",
            request.id[:12], request.status, new_status, actor, version,
        )
        return updated

    # -------------------------------------------------------------- queries

    def get_history(self, approval_id: str) -> list[ApprovalEvent]:
        return get_approval_store().events_for(approval_id)

    def is_action_allowed(self, approval_id: str) -> bool:
        """Authorization for a future action engine.

        True only when the request is approved AND the requested action is
        in the policy's ``allowed_actions``. Never executes anything.
        """
        request = get_approval_store().get(approval_id)
        if request is None:
            return False
        return request.status == "approved" and request.action in self._policy.allowed_actions