"""Read-only notifications endpoint.

GET /api/notifications - derived from existing persisted events (approval
state transitions, SLA escalations, validation completions, proof
completions). Read/unread state is tracked per-user in the
``notification_reads`` table.

Nothing is mutated; this endpoint is intentionally read-only.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from app.auth.dependencies import get_current_user
from app.auth.models import User
from app.api.notifications_models import Notification, NotificationList
from app.approval.store import get_approval_store
from app.db.models import NotificationReadRow
from app.dedup.service import repo_label_for_file
from app.prove.store import get_proof_store
from app.risk.service import all_escalation_events
from app.validate.store import get_validation_store

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _derive_notifications(request: Request) -> list[Notification]:
    """Derive notification list from existing persisted events."""
    now = datetime.now(timezone.utc)
    items: list[Notification] = []

    # SLA breaches
    for event in all_escalation_events():
        items.append(
            Notification(
                id=f"sla_{event.finding_id}_{event.new_level}",
                type="sla_breached",
                title="SLA Breached",
                message=event.reason,
                finding_id=event.finding_id,
                created_at=event.created_at,
                read=False,
            )
        )

    # Approval state transitions
    for event in get_approval_store().all_events():
        status_label = event.new_status.replace("_", " ")
        actor = event.actor or "system"
        items.append(
            Notification(
                id=f"approval_{event.id}",
                type="approval_updated",
                title="Approval Updated",
                message=f"Approval moved to {status_label} by {actor}",
                finding_id=event.finding_id,
                created_at=event.created_at,
                read=False,
            )
        )

    # Validation completions
    for validation in get_validation_store().all():
        verdict_label = validation.verdict.replace("_", " ")
        items.append(
            Notification(
                id=f"validation_{validation.finding_id}",
                type="finding_validated",
                title="Finding Validated",
                message=f"Finding {validation.finding_id[:8]} validated as {verdict_label}",
                finding_id=validation.finding_id,
                created_at=validation.validated_at,
                read=False,
            )
        )

    # Proof completions
    for proof in get_proof_store().all():
        status_label = proof.status.replace("_", " ")
        items.append(
            Notification(
                id=f"proof_{proof.finding_id}",
                type="proof_completed",
                title="Proof Completed",
                message=f"Proof {status_label} for {proof.vulnerability_type}",
                finding_id=proof.finding_id,
                created_at=proof.created_at,
                read=False,
            )
        )

    # Sort by creation time, newest first
    items.sort(key=lambda item: item.created_at, reverse=True)
    return items


def _apply_read_state(
    request: Request, user_id: str, notifications: list[Notification]
) -> list[Notification]:
    """Mark notifications as read if they exist in the notification_reads table."""
    with request.app.state.session_factory() as session:
        read_rows = (
            session.query(NotificationReadRow)
            .filter(NotificationReadRow.user_id == user_id)
            .all()
        )
        read_ids = {row.id for row in read_rows}

    for notification in notifications:
        if notification.id in read_ids:
            notification.read = True
    return notifications


@router.get("", response_model=NotificationList)
def list_notifications(
    request: Request,
    user: User = Depends(get_current_user),
) -> NotificationList:
    """Return notifications derived from persisted events, with read/unread state."""
    notifications = _derive_notifications(request)
    notifications = _apply_read_state(request, user.id, notifications)
    unread_count = sum(1 for n in notifications if not n.read)
    return NotificationList(
        notifications=notifications,
        unread_count=unread_count,
    )


@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Mark a single notification as read for the authenticated user."""
    now = datetime.now(timezone.utc)
    with request.app.state.session_factory() as session:
        existing = (
            session.query(NotificationReadRow)
            .filter(
                NotificationReadRow.id == notification_id,
                NotificationReadRow.user_id == user.id,
            )
            .first()
        )
        if existing is None:
            row = NotificationReadRow(
                id=notification_id,
                user_id=user.id,
                read_at=now,
            )
            session.add(row)
            session.commit()
    return {"status": "ok"}


@router.post("/read-all")
def mark_all_notifications_read(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Mark all current notifications as read for the authenticated user."""
    now = datetime.now(timezone.utc)
    notifications = _derive_notifications(request)
    with request.app.state.session_factory() as session:
        for notification in notifications:
            existing = (
                session.query(NotificationReadRow)
                .filter(
                    NotificationReadRow.id == notification.id,
                    NotificationReadRow.user_id == user.id,
                )
                .first()
            )
            if existing is None:
                row = NotificationReadRow(
                    id=notification.id,
                    user_id=user.id,
                    read_at=now,
                )
                session.add(row)
        session.commit()
    return {"status": "ok"}
