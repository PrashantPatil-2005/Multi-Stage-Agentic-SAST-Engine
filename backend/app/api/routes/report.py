"""Security report API endpoints.

POST /api/reports/generate - Generate a security assessment report
GET  /api/reports - List available reports (placeholder for future use)

Reports are generated on-demand from existing platform data.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from app.auth.dependencies import get_current_user
from app.auth.models import User
from app.report.models import ReportRequest, SecurityReport
from app.report.pdf_generator import generate_pdf
from app.report.service import ReportService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate", response_class=Response)
def generate_report(
    body: ReportRequest,
    request: Request,
    user: User = Depends(get_current_user),
) -> Response:
    """Generate a security assessment report.

    Args:
        body: Report generation request with optional project_id and format.
        request: FastAPI request object for session factory access.

    Returns:
        PDF or JSON report based on the requested format.
    """
    service = ReportService(session_factory=request.app.state.session_factory)

    try:
        report = service.generate_report(project_id=body.project_id)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(exc)}"
        ) from exc

    if body.format == "pdf":
        try:
            pdf_content = generate_pdf(report)
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="security-report-{report.report_id[:12]}.pdf"'
                },
            )
        except Exception as exc:
            logger.error("PDF generation failed: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"PDF generation failed: {str(exc)}"
            ) from exc
    else:
        # JSON format
        return Response(
            content=report.model_dump_json(indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="security-report-{report.report_id[:12]}.json"'
            },
        )


@router.get("", response_model=dict)
def list_reports(
    user: User = Depends(get_current_user),
) -> dict:
    """List available reports (placeholder for future persistent reports).

    Currently reports are generated on-demand, so this returns
    information about the report generation capability.
    """
    return {
        "reports": [],
        "message": "Reports are generated on-demand. Use POST /api/reports/generate to create a report.",
    }
