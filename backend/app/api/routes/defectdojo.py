"""DefectDojo API routes.

Endpoints for creating, syncing, and querying DefectDojo tickets.
All endpoints require authentication (via the existing RBAC system).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import get_current_user
from app.auth.models import User
from app.defectdojo.config import DefectDojoConfig
from app.defectdojo.models import DefectDojoSyncResult, DefectDojoTicket
from app.defectdojo.service import (
    DefectDojoService,
    all_tickets,
    get_ticket,
)
from app.validate.store import get_finding_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/defectdojo", tags=["defectdojo"])


def _get_service(request: Request) -> DefectDojoService:
    """Build the DefectDojo service from app settings."""
    return DefectDojoService()


@router.get("/status")
def defectdojo_status(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Return the current DefectDojo integration status."""
    service = _get_service(request)
    return service.get_status()


@router.post("/test-connection")
def test_connection(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Test connectivity to the configured DefectDojo instance."""
    service = _get_service(request)
    result = service.test_connection()
    return result.model_dump()


@router.post("/create/{finding_id}")
def create_ticket(
    finding_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Create a DefectDojo ticket for a specific finding."""
    finding_store = get_finding_store()
    finding = finding_store.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    service = _get_service(request)
    ticket = service.create_ticket(finding)
    return ticket.model_dump(mode="json")


@router.post("/sync")
def sync_findings(
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Sync all findings to DefectDojo.

    Creates tickets for findings that don't have one yet.
    """
    finding_store = get_finding_store()
    findings = finding_store.all()

    service = _get_service(request)
    result = service.sync_findings(findings)
    return result.model_dump()


@router.get("/tickets")
def list_tickets(
    request: Request,
    user: User = Depends(get_current_user),
) -> list[dict]:
    """List all DefectDojo tickets."""
    tickets = all_tickets()
    return [t.model_dump(mode="json") for t in tickets]


@router.get("/tickets/{finding_id}")
def get_ticket_detail(
    finding_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    """Get the DefectDojo ticket for a specific finding."""
    ticket = get_ticket(finding_id)
    if ticket is None:
        raise HTTPException(
            status_code=404,
            detail=f"No DefectDojo ticket for finding {finding_id}",
        )
    return ticket.model_dump(mode="json")
