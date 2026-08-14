"""In-memory stores for the approval workflow (same convention as the
validate/prove/dedup/risk singletons)."""

from app.approval.models import ApprovalEvent, ApprovalRequest


class ApprovalStore:
    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._events: dict[str, list[ApprovalEvent]] = {}

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def save(self, request: ApprovalRequest) -> None:
        self._requests[request.id] = request

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

    def events_for(self, approval_id: str) -> list[ApprovalEvent]:
        return list(self._events.get(approval_id, []))

    def all(self) -> list[ApprovalRequest]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._requests.values())

    def all_events(self) -> list[ApprovalEvent]:
        """Read-only enumeration of every recorded event (newest last)."""
        return [event for events in self._events.values() for event in events]

    def clear(self) -> None:
        self._requests.clear()
        self._events.clear()


_approvals = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _approvals