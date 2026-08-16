"""Approval workflow stores (same convention as the validate/prove/dedup/risk
singletons) with optional SQLite backing.

Requests and append-only events are mirrored into SQLite rows when a session
factory is configured (see ``app/db/persistence.py``). Rehydration restores
both, with each request's event trail ordered by creation time.
"""

from app.approval.models import ApprovalEvent, ApprovalRequest
from app.db.models import ApprovalEventRow, ApprovalRequestRow
from app.db.persistence import db_delete_all, db_insert, db_load_all, db_upsert


class ApprovalStore:
    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._events: dict[str, list[ApprovalEvent]] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._requests.clear()
        self._events.clear()
        for key, request in db_load_all(
            factory, ApprovalRequestRow, ApprovalRequest, "approval_id"
        ):
            self._requests[key] = request
        for _, event in db_load_all(factory, ApprovalEventRow, ApprovalEvent, "event_id"):
            self._events.setdefault(event.approval_id, []).append(event)
        for events in self._events.values():
            events.sort(key=lambda e: e.created_at)

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def save(self, request: ApprovalRequest) -> None:
        self._requests[request.id] = request
        db_upsert(
            self._factory,
            ApprovalRequestRow,
            "approval_id",
            request.id,
            request,
            finding_id=request.finding_id,
        )

    def find_for_finding(self, finding_id: str) -> ApprovalRequest | None:
        matches = [
            r for r in self._requests.values() if r.finding_id == finding_id
        ]
        if not matches:
            return None
        return max(matches, key=lambda r: r.requested_at)

    def find_active(
        self, finding_id: str, action: str, statuses: frozenset[str]
    ) -> ApprovalRequest | None:
        for request in self._requests.values():
            if (
                request.finding_id == finding_id
                and request.action == action
                and request.status in statuses
            ):
                return request
        return None

    def record_event(self, event: ApprovalEvent) -> None:
        self._events.setdefault(event.approval_id, []).append(event)
        db_insert(
            self._factory,
            ApprovalEventRow(
                event_id=event.id,
                approval_id=event.approval_id,
                payload=event.model_dump(mode="json"),
            ),
        )

    def events_for(self, approval_id: str) -> list[ApprovalEvent]:
        return list(self._events.get(approval_id, []))

    def remove_finding(self, finding_id: str) -> None:
        """Remove every approval request + audit event for one finding.

        Used by repository deletion. Idempotent: findings without approvals
        are fine.
        """
        request_ids = [
            request.id
            for request in self._requests.values()
            if request.finding_id == finding_id
        ]
        for approval_id in request_ids:
            self._requests.pop(approval_id, None)
            self._events.pop(approval_id, None)
        if self._factory is None:
            return
        with self._factory() as session:
            session.query(ApprovalRequestRow).filter(
                ApprovalRequestRow.finding_id == finding_id
            ).delete()
            if request_ids:
                session.query(ApprovalEventRow).filter(
                    ApprovalEventRow.approval_id.in_(request_ids)
                ).delete(synchronize_session=False)
            session.commit()

    def all(self) -> list[ApprovalRequest]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._requests.values())

    def all_events(self) -> list[ApprovalEvent]:
        """Read-only enumeration of every recorded event (newest last)."""
        return [event for events in self._events.values() for event in events]

    def clear(self) -> None:
        self._requests.clear()
        self._events.clear()
        db_delete_all(self._factory, ApprovalEventRow)
        db_delete_all(self._factory, ApprovalRequestRow)


_approvals = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _approvals


def set_approval_store_factory(factory) -> None:
    _approvals.set_factory(factory)